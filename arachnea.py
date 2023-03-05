#!/usr/bin/python3

import bs4
import datetime
import logging
import optparse
import re
import selenium
import socket
import sys
import threading
import time

import html2text
import MySQLdb
import MySQLdb._exceptions
import requests
import selenium.common.exceptions
import selenium.webdriver
import selenium.webdriver.common.by
import selenium.webdriver.firefox.options

socket.setdefaulttimeout(5)


Scroll_Pause_Time = 1.0


class Internal_Exception(Exception):
    """
    Thrown in the case of a coding error or other internal issue.
    """
    pass


class Handle(object):
    """
    Represents a mastodon handle.
    """
    __slots__ = 'handle_id', 'username', 'host'

    @property
    def handle(self):
        """
        Returns the handle in @username@host form.
        """
        return f"@{self.username}@{self.host}"

    @property
    def profile_url(self):
        """
        Returns the handle in https://host/@username form.
        """
        return f"https://{self.host}/@{self.username}"

    def __init__(self, handle_id=None, username='', host=''):
        """
        Instances the Handle object.

        :param handle_id: The primary key of the row in the MySQL
                          arachnea.handles table that furnished the data this
                          Handle object is instanced from, if any.
        :param username:  The part of the handle that represents the indicated
                          user's username.
        :param host:      The part of the handle that represents the indicated
                          user's instance.
        """
        assert isinstance(handle_id, int) or handle_id is None
        self.handle_id = handle_id
        self.username = username
        self.host = host

    def convert_to_deleted_user(self):
        """
        Instances a Deleted_User object from the state of this Handle object.
        """
        return Deleted_User(handle_id=self.handle_id, username=self.username, host=self.host)

    def fetch_or_set_handle_id(self, data_store):
        """
        If the Handle object was instanced from another source than a row in
        the MySQL arachnea.handles table, set the handle_id from the table,
        inserting the data if necessary.

        :param data_store: The Data_Store object to use to access the arachnea.handles table.
        """
        # If the handle_id is already set, do nothing & return failure.
        if self.handle_id:
            return False

        # Fetch the extant handle_id value from the table if it so happens this
        # username/host part is already in the handles table.
        fetch_handle_id_sql = (f"""SELECT handle_id FROM handles WHERE username = '{self.username}'
                                                                 AND instance = '{self.host}';""")
        data_store.db_cursor.execute(fetch_handle_id_sql)
        rows = data_store.db_cursor.fetchall()

        # If it wasn't present, insert the username/host pair into the table,
        # and repeats the fetch query.
        if not len(rows):
            insert_handle_sql = f"INSERT INTO handles (username, instance) VALUES ('{self.username}', '{self.host}');"
            data_store.db_cursor.execute(insert_handle_sql)
            data_store.db_cursor.fetchall()
            data_store.db_cursor.execute(fetch_handle_id_sql)
            rows = data_store.db_cursor.fetchall()
        ((handle_id,),) = rows
        self.handle_id = handle_id
        return True


class Data_Store(object):
    __slots__ = 'db_connection', 'db_cursor', 'logger'

    host = 'localhost'
    user = 'kmfahey'
    password = '3.1415926535'
    db = 'arachnea'

    def __init__(self, logger):
        self.logger = logger
        self.logger.info(f"opening connection to database")
        self.db_connection = MySQLdb.Connect(host=self.host, user=self.user, password=self.password, db=self.db)
        self.db_connection.autocommit(True)
        self.db_cursor = self.db_connection.cursor()

    def users_in_relations_not_in_profiles(self):
        self.logger.info(f"selecting handles from relations left join profiles")
        relations_left_join_profiles_sql = "SELECT DISTINCT relation_handle_id, relation_username, relation_instance FROM "\
                                           "relations LEFT JOIN profiles ON relations.relation_handle_id = "\
                                           "profiles.profile_handle_id WHERE profiles.profile_handle_id IS NULL "\
                                           "ORDER BY RAND();"
        return self._execute_sql_generator(relations_left_join_profiles_sql)

    def users_in_profiles_not_in_relations(self):
        self.logger.info(f"selecting handles from profiles left join relations")
        profiles_left_join_relations_sql = "SELECT profiles.profile_handle_id, username, instance FROM profiles "\
                                           "LEFT JOIN relations ON profiles.profile_handle_id = relations.profile_handle_id "\
                                           "WHERE relations.profile_handle_id IS NULL ORDER BY RAND();"
        return self._execute_sql_generator(profiles_left_join_relations_sql)

    def users_in_handles_not_in_profiles(self):
        self.logger.info(f"selecting handles from handles left join profiles")
        handles_left_join_profiles_sql = "SELECT handles.handle_id, handles.username, handles.instance FROM handles LEFT "\
                                         "JOIN profiles ON handles.handle_id = profiles.profile_handle_id WHERE "\
                                         "profiles.profile_handle_id IS NULL ORDER BY RAND();"
        return self._execute_sql_generator(handles_left_join_profiles_sql)

    def _execute_sql_generator(self, select_sql):
        self.db_cursor.execute(select_sql)
        row = self.db_cursor.fetchone()
        while row is not None:
            yield Handle(*row)
            row = self.db_cursor.fetchone()

    def execute(self, sql):
        self.db_cursor.execute(sql)
        return self.db_cursor.fetchall()

    def close(self):
        self.db_cursor.close()
        self.db_connection.close()

    def __del__(self):
        self.close()


class Instance(object):
    __slots__ = 'host', 'logger', 'rate_limit_expires', 'attempts', 'malfunctioning', 'suspended', 'unparseable'

    rate_limit_expires_isoformat = property(lambda self: datetime.datetime.fromtimestamp(self.rate_limit_expires).time().isoformat())

    status = property(lambda self: 'malfunctioning' if self.malfunctioning
                              else 'suspended' if self.suspended
                              else 'unparseable' if self.unparseable
                              else 'ingoodstanding')

    def __init__(self, host, logger, malfunctioning=False, suspended=False, unparseable=False, rate_limited=False, x_ratelimit_limit=None, attempts=0):
        self.host = host
        self.logger = logger
        self.attempts = attempts
        self.malfunctioning = malfunctioning
        self.suspended = suspended
        self.unparseable = unparseable
        if rate_limited:
            self.set_rate_limit(x_ratelimit_limit)
        else:
            self.rate_limit_expires = 0.0

    def set_rate_limit(self, x_ratelimit_limit=None):
        if x_ratelimit_limit:
            self.rate_limit_expires = time.time() + float(x_ratelimit_limit)
        else:
            self.rate_limit_expires = time.time() + 300.0
        self.logger.info(f"set rate limit on instance '{self.host}': rate limit expires at {self.rate_limit_expires_isoformat}")

    @classmethod
    def fetch_all_instances(self, data_store, logger):
        instances_dict = dict()
        for row in data_store.execute("SELECT instance, issue FROM bad_instances;"):
            host, issue = row
            instances_dict[host] = Instance(host, logger, malfunctioning=(issue == 'malfunctioning'),
                                                          suspended=(issue == 'suspended'),
                                                          unparseable=(issue == 'unparseable'))
        logger.info(f"retrieved {len(instances_dict)} instances from bad_instances table")
        return instances_dict

    @classmethod
    def save_instances(self, instances_dict, data_store, logger):
        existing_instances_dict = self.fetch_all_instances(data_store, logger)
        instances_to_insert = dict()
        for host, instance in instances_dict.items():
            if host in existing_instances_dict:
                continue
            instances_to_insert[host] = instances_dict[host]
        if not instances_to_insert:
            return False
        values_stmts = tuple(f"('{instance.host}','{instance.issue}')" for instance in instances_to_insert.values())
        insert_sql = "INSERT INTO bad_instances (instance, issue) VALUES %s;" % ', '.join(values_stmts)
        logger.info(f"saving {len(instances_to_insert)} bad instances to bad_instances table")
        data_store.execute(insert_sql)

    def still_rate_limited(self):
        return time.time() < self.rate_limit_expires

    def save_instance(self, data_store):
        if not self.malfunctioning and not self.suspended and not self.unparseable:
            return False
        else:
            status = 'malfunctioning' if self.malfunctioning else 'suspended' if self.suspended else 'unparseable'
        result = data_store.execute(f"SELECT instance, issue FROM bad_instances WHERE instance = '{self.host}';")
        if not result:
            self.logger.info(f"saving bad instance {self.host} to bad_instances table")
            data_store.execute(f"INSERT INTO bad_instances (instance, issue) VALUES ('{self.host}', '{status}');")
            return True


class Failed_Request(object):
    __slots__ = ('host', 'status_code', 'ratelimited', 'user_deleted', 'malfunctioning', 'unparseable', 'suspended',
                 'ssl_error', 'too_many_redirects', 'timeout', 'connection_error', 'posts_too_old', 'no_public_posts',
                 'forwarding_address', 'is_dynamic', 'webdriver_error', 'x_ratelimit_limit')

    def __init__(self, host, status_code=0, ratelimited=False, user_deleted=False, malfunctioning=False,
                       unparseable=False, suspended=False, ssl_error=False, too_many_redirects=False, timeout=False,
                       connection_error=False, posts_too_old=False, no_public_posts=False, forwarding_address='',
                       is_dynamic=False, webdriver_error=False, x_ratelimit_limit=0):
        self.host = host
        self.status_code = status_code
        self.ratelimited = ratelimited
        self.user_deleted = user_deleted
        self.malfunctioning = malfunctioning
        self.unparseable = unparseable
        self.suspended = suspended
        self.ssl_error = ssl_error
        self.too_many_redirects = too_many_redirects
        self.timeout = timeout
        self.connection_error = connection_error
        self.posts_too_old = posts_too_old
        self.no_public_posts = no_public_posts
        self.forwarding_address = forwarding_address
        self.is_dynamic = is_dynamic
        self.webdriver_error = webdriver_error
        self.x_ratelimit_limit = x_ratelimit_limit

    def __repr__(self):
        init_argd = dict()
        for attr_key in self.__slots__:
            attr_value = getattr(self, attr_key, False)
            if bool(attr_value):
                init_argd[attr_key] = attr_value
        args_str = ", ".join(f"{key}={repr(value)}" for key, value in init_argd.items())
        return f"{self.__class__.__name__}({args_str})"


class Deleted_User(Handle):
    __slots__ = 'logger',

    @classmethod
    def fetch_all_deleted_users(self, data_store):
        deleted_users_dict = dict()
        for row in data_store.execute("SELECT handle_id, username, instance FROM deleted_users;"):
            handle_id, username, host = row
            deleted_users_dict[username, host] = Deleted_User(handle_id=handle_id, username=username, host=host)
        return deleted_users_dict

    def save_deleted_user(self, data_store):
        insert_sql = f"INSERT INTO deleted_users (handle_id, username, instance) VALUES ({self.handle_id}, '{self.username}', '{self.host}');"
        try:
            data_store.execute(insert_sql)
        except MySQLdb._exceptions.IntegrityError:
            self.logger.info(f"got an SQL IntegrityError when inserting {self.handle} into table deleted_users")
        else:
            self.logger.info(f"inserted {self.handle} into table deleted_users")


class Page_Factory(object):
    __slots__ = ('instances_dict', 'data_store', 'logger', 'deleted_users_dict', 'save_profiles', 'save_relations',
                 'dont_discard_bc_wifi')

    def __init__(self, data_store, logger, instances_dict, save_profiles=False, save_relations=False, dont_discard_bc_wifi=False):
        self.data_store = data_store
        self.logger = logger
        self.instances_dict = instances_dict
        self.deleted_users_dict = Deleted_User.fetch_all_deleted_users(self.data_store)
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.dont_discard_bc_wifi = dont_discard_bc_wifi

    def instantiate_and_fetch_page(self, handle, url):
        host = handle.host
        instance = self.instances_dict.get(host, None)
        if instance is not None:
            if instance.malfunctioning or instance.unparseable or instance.suspended:
                if self.save_profiles:
                    self.logger.info(f"instance {host} on record as {instance.status}; didn't load {url}; saving null bio to database")
                    page = Page(handle, url, self.logger, save_profiles=self.save_profiles, save_relations=self.save_relations)
                    page.save_page(self.data_store)
                    return page, Failed_Request(host,
                                                malfunctioning=instance.malfunctioning,
                                                unparseable=instance.unparseable,
                                                suspended=instance.suspended)
                else:
                    self.logger.info(f"instance {host} on record as {instance.status}; didn't load {url}")
                    return None, Failed_Request(host,
                                                malfunctioning=instance.malfunctioning,
                                                unparseable=instance.unparseable,
                                                suspended=instance.suspended)
            elif instance.still_rate_limited():
                self.logger.info(f"instance {host} still rate limited, expires at {instance.rate_limit_expires_isoformat}, didn't load {url}")
                return None, Failed_Request(host, ratelimited=True)
        if (handle.host, handle.username) in self.deleted_users_dict:
            # FIXME: this step can be skipped if a JOIN against deleted_users is added to the handles loading step
            self.logger.info(f"user {handle.handle} known to be deleted; didn't load {url}")
            return None, Failed_Request(handle.host, user_deleted=True)
        page = Page(handle, url, self.logger, save_profiles=self.save_profiles, save_relations=self.save_relations)
        result = page.requests_fetch()
        if isinstance(result, Failed_Request) and result.is_dynamic:
            self.logger.info(f"loaded {url}: page has <noscript>; loading with webdriver")
            result = page.webdriver_fetch()
        if isinstance(result, Failed_Request):
            if result.ratelimited:
                if host not in self.instances_dict:
                    instance = Instance(host, self.logger, rate_limited=True, x_ratelimit_limit=result.x_ratelimit_limit)
                    self.instances_dict[host] = instance
                else:
                    instance = self.instances_dict[host]
                    instance.set_rate_limit(x_ratelimit_limit=result.x_ratelimit_limit)
                self.logger.info(f"failed to load {url}: rate limited: expires at {instance.rate_limit_expires_isoformat}")
            elif result.malfunctioning:
                if host in self.instances_dict:
                    instance = self.instances_dict[host]
                    instance.attempts += 1
                else:
                    instance = Instance(host, self.logger, attempts=1)
                    self.instances_dict[host] = instance
                if result.ssl_error:
                    self.logger.info(f"failed to load {url}, host malfunctioning: ssl error (error #{instance.attempts} for this host)")
                elif result.too_many_redirects:
                    self.logger.info(f"failed to load {url}, host malfunctioning: too many redirects (error #{instance.attempts} for this host)")
                elif result.timeout:
                    self.logger.info(f"failed to load {url}, host malfunctioning: connection timeout (error #{instance.attempts} for this host)")
                elif result.connection_error:
                    self.logger.info(f"failed to load {url}, host malfunctioning: connection error (error #{instance.attempts} for this host)")
                else:
                    self.logger.info(f"failed to load {url}, host malfunctioning: got status code {result.status_code} (error #{instance.attempts} for this host)")
            elif result.user_deleted:
                deleted_user = handle.convert_to_deleted_user()
                deleted_user.logger = self.logger
                self.deleted_users_dict[handle.username, handle.host] = deleted_user 
                deleted_user.save_deleted_user(self.data_store)
                self.logger.info(f"failed to load {url}: user deleted")
            elif result.webdriver_error:
                self.logger.info(f"loaded {url}: webdriver loading failed with internal error")
            elif result.no_public_posts:
                self.logger.info(f"loaded {url}: no public posts")
            elif result.posts_too_old:
                self.logger.info(f"loaded {url}: posts too old")
            elif result.forwarding_address:
                if result.forwarding_address is True:
                    self.logger.info(f"loaded {url}: forwarding page (could not recover handle)")
                else:
                    self.logger.info(f"loaded {url}: forwarding page")
            elif result.unparseable:
                self.logger.info(f"loaded {url}: parsing failed")
            else:
                self.logger.info(f"loaded {url}: unanticipated error {repr(result)}")
            if self.save_profiles and page.is_profile:
                if self.dont_discard_bc_wifi and result.connection_error:
                    self.logger.info(f"handle {handle.handle}: fetching returned connection error but the wifi might've gone out, saving for later")
                    return page, True
                elif result.connection_error:
                    self.logger.info(f"handle {handle.handle}: fetching returned error, saving null bio to database")
            page.save_page(self.data_store)
            return None, result
        elif self.save_profiles and page.is_profile:
            self.logger.info(f"loaded {url}: detected profile bio, length {len(page.profile_bio_text)}; saving bio to database")
            page.save_page(self.data_store)
        elif self.save_relations and page.is_following:
            self.logger.info(f"loaded {url}: found {result} following handles")
        elif self.save_relations and page.is_followers:
            self.logger.info(f"loaded {url}: found {result} followers handles")
        return page, True


class Page(object):
    __slots__ = ('handle', 'username', 'host', 'logger', 'url', 'logger', 'document', 'is_dynamic', 'loaded',
                 'is_profile', 'is_following', 'is_followers', 'page_number', 'profile_no_public_posts',
                 'profile_posts_too_old', 'profile_bio_text', 'relations_list', 'unparseable', 'save_profiles',
                 'save_relations')

    forwarding_handle_re = re.compile(r'^.*(@) ([A-Za-z0-9._]+@[A-Za-z0-9._]+\.[a-z]+).*$', flags=re.M)
    handle_url_href_re = re.compile(r'https://([\w.]+\.\w+)/@(\w+)')
    moved_handle_re = re.compile(r'moved-account-widget__message')
    profile_url_re = re.compile(r'(?:https://[A-Za-z0-9_.-]+\.[a-z]+)?/@[A-Za-z0-9_.-]+$')
    relation_url_re = re.compile(r'(?:https://[A-Za-z0-9_.-]+\.[a-z]+)?/(?:users/|@)[A-Za-z0-9_.-]+/(follow(?:ing|ers))(?:\?page=[0-9]+)?$')
    static_pagination_page_split_re = re.compile("(?<=page=)")
    static_pagination_re = re.compile(r'/users/[A-Za-z0-9_.-]+/follow(?:ing|ers)(?:\?page=\d+)?')

    @property
    def is_static(self):
        return not self.is_dynamic

    @is_static.setter
    def is_static(self, boolval):
        self.is_dynamic = not boolval

    @property
    def relation_type(self):
        return 'following' if self.is_following else 'followers' if self.is_followers else None

    def __init__(self, handle, url, logger, save_profiles=False, save_relations=False):
        self.handle = handle
        self.url = url
        self.logger = logger
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.username = handle.username
        self.host = handle.host
        self.document = None
        self.is_dynamic = False
        self.loaded = None
        self.is_profile = self.is_following = self.is_followers = False
        self.profile_no_public_posts = self.profile_posts_too_old = False
        self.relations_list = list()
        self.unparseable = False
        self.profile_bio_text = ''
        if self.profile_url_re.match(self.url):
            self.is_profile = True
            self.page_number = 0
        elif match := self.relation_url_re.match(self.url):
            follow_fragment = match.group(1)
            if follow_fragment == 'following':
                self.is_following = True
            else:
                self.is_followers = True
            url_components = self.static_pagination_page_split_re.split(self.url)
            if len(url_components) == 2:
                _, page_number = url_components
                self.page_number = int(page_number)
            elif '/users/' in self.url:
                self.page_number = 1
            else:
                self.page_number = 0
        else:
            raise Internal_Exception(f"unable to discern profile, following or follower page from parsing url {self.url} ")

    def requests_fetch(self):
        try:
            http_response = requests.get(self.url, timeout=5.0)
        except requests.exceptions.SSLError:
            self.loaded = False
            return Failed_Request(self.host, malfunctioning=True, ssl_error=True)
        except requests.exceptions.TooManyRedirects:
            self.loaded = False
            return Failed_Request(self.host, malfunctioning=True, too_many_redirects=True)
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
            self.loaded = False
            return Failed_Request(self.host, malfunctioning=True, timeout=True)
        except (requests.exceptions.ConnectionError, IOError):
            self.loaded = False
            return Failed_Request(self.host, malfunctioning=True, connection_error=True)
        if http_response.status_code == 429:
            if http_response.headers['x-ratelimit-limit']:
                self.loaded = False
                return Failed_Request(self.host, status_code=http_response.status_code, ratelimited=True, x_ratelimit_limit=float(http_response.headers['x-ratelimit-limit']))
            else:
                self.loaded = False
                return Failed_Request(self.host, status_code=http_response.status_code, ratelimited=True)
        elif http_response.status_code in (401, 400, 403, 406) or http_response.status_code >= 500:
            self.loaded = False
            return Failed_Request(self.host, status_code=http_response.status_code, malfunctioning=True)
        elif http_response.status_code == 404 or http_response.status_code == 410:
            self.loaded = False
            return Failed_Request(self.host, status_code=http_response.status_code, user_deleted=True)
        elif http_response.status_code != 200:
            self.loaded = False
            return Failed_Request(self.host, status_code=http_response.status_code)
        else:
            self.document = bs4.BeautifulSoup(markup=http_response.text, features='lxml')
            if self.document.find_all('noscript'):
                self.loaded = False
                self.is_dynamic = True
                return Failed_Request(self.host, is_dynamic=True)
            else:
                self.loaded = True
                if self.is_profile and self.save_profiles:
                    return self.parse_profile_page()
                elif (self.is_following or self.is_followers) and self.save_relations:
                    return self.parse_relations_page()
                else:
                    return True

    def webdriver_fetch(self):
        try:
            options = selenium.webdriver.firefox.options.Options()
            options.add_argument('-headless')
            self.logger.info(f"webdriver instantiating headless Firefox program")
            browser = selenium.webdriver.Firefox(options=options)
            self.logger.info(f"webdriver loading url {self.url}")
            browser.get(self.url)
            if self.is_profile and self.save_profiles:
                html = browser.page_source
                self.document = bs4.BeautifulSoup(markup=html, features='lxml')
                page_height = browser.execute_script("return document.body.scrollHeight")
                self.logger.info(f"webdriver loaded page of height {page_height}")
                return self.parse_profile_page()
            elif (self.is_following or self.is_followers) and self.save_relations:
                last_height = browser.execute_script("return document.body.scrollHeight")
                self.logger.info(f"webdriver loaded initial page height {last_height}")
                while True:
                    browser.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    time.sleep(Scroll_Pause_Time)
                    new_height = browser.execute_script("return document.body.scrollHeight")
                    if new_height == last_height:
                        self.logger.info(f"webdriver scrolled down to page height {last_height} and finished scrolling")
                        break
                    last_height = new_height
                    self.logger.info(f"webdriver scrolled down to page height {last_height}")
                return self.parse_relations_page(browser)
            else:
                return False
        except (selenium.common.exceptions.NoSuchElementException, selenium.common.exceptions.WebDriverException):
            return Failed_Request(self.host, webdriver_error=True)
        finally:
            self.logger.info(f"closing out webdriver Firefox instance")
            browser.quit()
            del browser

    def parse_profile_page(self):
        self.logger.info(f"parsing profile at {self.url}")
        time_tags = self.document.find_all('time', {'class': 'time-ago'})
        if len(time_tags) == 0:
            self.profile_no_public_posts = True
            return Failed_Request(self.host, no_public_posts=True)
        else:
            time_tags = [time_tag['datetime'] for time_tag in time_tags]
            if '+' in time_tags[0]:
                time_tags = [time_split[0]+'Z' for time_split in (time_tag.split('+') for time_tag in time_tags)]
            toot_datetimes = sorted(map(lambda time_tag: datetime.datetime.strptime(time_tag, '%Y-%m-%dT%H:%M:%SZ'), time_tags))
            seven_days_ago_datetime = datetime.datetime.today() - datetime.timedelta(days=7)
            most_recent_toot_datetime = toot_datetimes[0]
            self.profile_posts_too_old = most_recent_toot_datetime < seven_days_ago_datetime
            if self.profile_posts_too_old:
                return Failed_Request(self.host, posts_too_old=True)
        forwarding_tag = self.document.find('div', {'class': self.moved_handle_re})
        if forwarding_tag:
            forwarding_match = self.forwarding_handle_re.match(html2text.html2text(forwarding_tag.prettify()))
            if forwarding_match is not None:
                handle_at, handle_rest = forwarding_match.groups()
                forwarding_handle = handle_at + handle_rest
                return Failed_Request(self.host, forwarding_address=forwarding_handle)
            else:
                return Failed_Request(self.host, forwarding_address=True)
        profile_div_tag = self.document.find('div', {'class': 'public-account-bio'})
        if profile_div_tag is None:
            profile_div_tag = self.document.find('div', {'class': 'account__header__content'})
        if profile_div_tag is None:
            self.unparseable = True
            return Failed_Request(self.host, unparseable=True)
        if self.is_dynamic:
            unwanted_masto_link_divs = profile_div_tag.find_all('div', {'class': 'account__header__extra__links'})
            if len(unwanted_masto_link_div):
                unwanted_masto_link_divs[0].replaceWith('')
        self.profile_bio_text = html2text.html2text(str(profile_div_tag))
        return len(self.profile_bio_text)

    def parse_relations_page(self, browser=None):
        self.logger.info(f"parsing {self.relation_type} at {self.url}")
        if self.is_dynamic:
            try: 
                html_tag = browser.find_element(selenium.webdriver.common.by.By.XPATH, '/html')
                html_tag.send_keys(selenium.webdriver.common.keys.Keys.HOME)
                time.sleep(Scroll_Pause_Time)
                html_tag.send_keys(selenium.webdriver.common.keys.Keys.END)
                time.sleep(Scroll_Pause_Time)
                html_tag.send_keys(selenium.webdriver.common.keys.Keys.ARROW_UP)
                article_tag_text_by_data_id = dict.fromkeys((tag.get_attribute('data-id')
                    for tag in browser.find_elements(selenium.webdriver.common.by.By.XPATH, "//article")), "")
                total_article_tags_count = loaded_article_tag_count = len(article_tag_text_by_data_id)
                self.logger.info(f"using selenium.webdriver to page over dynamic {self.relation_type} page forcing "\
                            f"<article> tags to load; found {len(article_tag_text_by_data_id)} <article> tags")
                pass_counter = 1
                while any(not bool(text) for text in article_tag_text_by_data_id.values()):
                    article_tags = browser.find_elements(selenium.webdriver.common.by.By.XPATH, "//article")
                    for article_tag in article_tags:
                        article_tag_text = article_tag.text
                        data_id = article_tag.get_attribute('data-id')
                        if data_id not in article_tag_text_by_data_id:
                            article_tag_text_by_data_id[data_id] = article_tag.text if article_tag_text else ''
                        elif article_tag_text_by_data_id[data_id]:
                            continue
                        elif article_tag_text:
                            article_tag_text_by_data_id[data_id] = article_tag.text
                    for article_tag in article_tags:
                        data_id = article_tag.get_attribute('data-id')
                        if article_tag_text_by_data_id.get(data_id, False):
                            continue
                        browser.execute_script("arguments[0].scrollIntoView();", article_tag)
                        break
                    loaded_article_tag_count = len(tuple(filter(lambda tag_text: not tag_text, article_tag_text_by_data_id.values())))
                    empty_article_tags_count_diff = total_article_tags_count - loaded_article_tag_count
                    self.logger.info(f"pass #{pass_counter}: {empty_article_tags_count_diff} <article> tags text found")
                    pass_counter += 1
            except (selenium.common.exceptions.NoSuchElementException, selenium.common.exceptions.WebDriverException):
                return Failed_Request(self.host, webdriver_error=True)
            for handle_str in article_tag_text_by_data_id.values():
                if "\n" in handle_str:
                    handle_str = handle_str.split("\n")[1]
                if handle_str.count('@') == 1:
                    username = handle_str.strip('@')
                    host = self.host
                elif handle_str.count('@') == 2:
                    _, username, host = handle_str.split('@')
                else:
                    continue
                handle = Handle(username=username, host=host)
                self.relations_list.append(handle)
        else:
            found_relations_a_tags = self.document.find_all('a', {'href': self.profile_url_re})
            relations_hrefs = [tag.attrs['href'] for tag in found_relations_a_tags]
            for relation_href in relations_hrefs:
                handle_match = self.handle_url_href_re.match(relation_href)
                if not handle_match:
                    continue
                relation_instance, relation_username = handle_match.groups()
                if relation_username == self.username and relation_instance == self.host:
                    continue
                self.relations_list.append(Handle(username=relation_username, host=relation_instance))
        return len(self.relations_list)

    def generate_initial_relation_page_urls(self):
        if not self.is_profile:
            return []
        elif self.is_dynamic:
            return [f"https://{self.host}/@{self.username}/following",
                    f"https://{self.host}/@{self.username}/followers"]
        else:
            return [f"https://{self.host}/users/{self.username}/following",
                    f"https://{self.host}/users/{self.username}/followers"]

    def generate_all_relation_page_urls(self):
        if not (self.is_following or self.is_followers):
            return []
        a_tags = self.document.find_all('a', {'href': self.static_pagination_re})
        if not len(a_tags):
            return []
        hrefs = [a_tag['href'] for a_tag in a_tags]
        relation_url_dict = {(int(href.split('page=')[1]) if 'page=' in href else 1): href for href in hrefs}
        highest_page_no = max(relation_url_dict.keys())
        highest_page_url = relation_url_dict[highest_page_no]
        if 'page=' in highest_page_url:
            base_url, _ = self.static_pagination_page_split_re.split(highest_page_url)
            if not base_url.startswith('https://'):
                base_url = 'https://' + self.host + base_url
            return [f"{base_url}{page_no}" for page_no in range(2,highest_page_no+1)]
        else:
            return []

    def save_page(self, data_store):
        if self.is_profile:
            profile_bio_text = self.profile_bio_text.replace("'", "\\'")
            handle = self.handle
            if not handle.handle_id:
                handle.fetch_or_set_handle_id(data_store)
            select_sql = f"SELECT profile_handle_id FROM profiles WHERE profile_handle_id = {handle.handle_id};"
            rows = data_store.execute(select_sql)
            if rows:
                return 0
            insert_sql = f"INSERT INTO profiles (profile_handle_id, username, instance, considered, profile_snippet) "\
                         f"VALUES ({handle.handle_id}, '{handle.username}', '{handle.host}', 0, "\
                         f"'{profile_bio_text}');"
            data_store.execute(insert_sql)
            return 1
        else:
            if not len(self.relations_list):
                return 0
            relation = 'following' if self.is_following else 'followers'
            profile_handle = self.handle
            profile_handle.fetch_or_set_handle_id(data_store)
            select_sql = f"SELECT DISTINCT profile_handle_id FROM relations WHERE profile_handle_id = "\
                         f"{profile_handle.handle_id} AND relation_type = '{relation}' AND "\
                         f"relation_page_number = {self.page_number};"
            rows = data_store.execute(select_sql)
            if rows:
                self.logger.info(f"page {self.page_number} of {relation} for @{self.username}@{self.host} already in database")
                return 0
            value_sql_list = list()
            insertion_count = 0
            for relation_handle in self.relations_list:
                relation_handle.fetch_or_set_handle_id(data_store)
                value_sql_list.append(f"({profile_handle.handle_id}, '{self.username}', '{self.host}', "\
                                      f"{relation_handle.handle_id}, '{relation}', {self.page_number}, "\
                                      f"'{relation_handle.username}', '{relation_handle.host}')")
            insert_sql = "INSERT INTO relations (profile_handle_id, profile_username, profile_instance, "\
                         "relation_handle_id, relation_type, relation_page_number, relation_username, "\
                         f"relation_instance) VALUES %s;" % ', '.join(value_sql_list)
            try:
                data_store.execute(insert_sql)
            except MySQLdb._exceptions.IntegrityError:
                insertion_count = 0
                for relation_handle in self.relations_list:
                    relation_handle.fetch_or_set_handle_id(data_store)
                    insert_sql = "INSERT INTO relations (profile_handle_id, profile_username, profile_instance, "\
                                 "relation_handle_id, relation_type, relation_page_number, relation_username, "\
                                 f"relation_instance) VALUES ({profile_handle.handle_id}, '{self.username}', "\
                                 f"'{self.host}', {relation_handle.handle_id}, '{relation}', {self.page_number}, "\
                                 f"'{relation_handle.username}', '{relation_handle.host}')"
                    try: 
                        data_store.execute(insert_sql)
                    except MySQLdb._exceptions.IntegrityError:
                        self.logger.info(f"got an SQL IntegrityError when inserting {relation_handle.handle} %s "\
                                    f"{profile_handle.handle} into table relations" % (
                                        'follower of' if relation == 'followers' else relation))
                    else:
                        insertion_count += 1
            else:
                insertion_count = len(value_sql_list)
            self.logger.info(f"saved {insertion_count} %s to the database" % ('followings' if relation == 'following' else relation))
            return insertion_count


class Handle_Processor(object):
    __slots__ = ('data_store', 'logger', 'instances_dict', 'save_from_wifi', 'last_time_point', 'current_time_point',
                 'prev_time_point', 'save_profiles', 'save_relations', 'page_factory', 'logger', 'dont_discard_bc_wifi')

    def __init__(self, data_store, logger, instances_dict, save_profiles=False, save_relations=False, dont_discard_bc_wifi=False):
        self.data_store = data_store
        self.logger = logger
        self.instances_dict = instances_dict
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.prev_time_point = current_time_point = time.time()
        self.dont_discard_bc_wifi = dont_discard_bc_wifi
        self.page_factory = Page_Factory(data_store, self.logger, instances_dict, save_profiles=save_profiles,
                                         save_relations=save_relations, dont_discard_bc_wifi=self.dont_discard_bc_wifi)

    def process_handle_iterable(self, iterable_length, handle_iterable):
        handles_remaining_count = iterable_length
        count_history = list()
        rate_history = list()
        skipped_handles = list()
        for handle in handle_iterable:
            if not handle.handle_id:
                handle.fetch_or_set_handle_id(write_data_store)
            profile_url = handle.profile_url
            try:
                if self.save_profiles and not self.save_relations:
                    result = self.retrieve_profile(handle, profile_url)
                else:
                    result = self.retrieve_relations_from_profile(handle, profile_url)
            except Internal_Exception:
                continue
            if isinstance(result, Failed_Request):
                if result.ratelimited == True or result.connection_error:
                    skipped_handles.append(handle)
                if result.forwarding_address and result.forwarding_address is not True:
                    handles_remaining_count += 1
            else:
                handles_remaining_count -= 1
            #self.check_time_report_progress(iterable_length, handles_remaining_count, count_history, rate_history)
        while len(skipped_handles):
            successful_requests = 0
            for index in range(0, len(skipped_handles)):
                handle = skipped_handles[index]
                result = self.retrieve_relations_from_profile(handle, profile_url)
                if isinstance(result, Failed_Request) and result.ratelimited == True:
                    continue
                skipped_handles[index] = None
                successful_requests += 1
                handles_remaining_count -= 1
            if successful_requests == 0:
                self.logger.info("All Handle objects remaining in queue are from instances where we're still ratelimited; "
                                 "no more retrievals are possible right now. Exitting.")
                exit(1)
            skipped_handles = list(filter(lambda handle: handle is not None, skipped_handles))
            #self.check_time_report_progress(iterable_length, handles_remaining_count, count_history, rate_history)

    def check_time_report_progress(self, total_handles_count, handles_processed_count, count_history, rate_history):
        self.current_time_point = time.time()
        prev_datetime = datetime.datetime.fromtimestamp(self.prev_time_point)
        current_datetime = datetime.datetime.fromtimestamp(self.current_time_point)
        if prev_datetime.minute != current_datetime.minute:
            elapsed_timedelta = current_datetime - prev_datetime
            elapsed_seconds = elapsed_timedelta.seconds + elapsed_timedelta.microseconds/1000000
            prev_count = count_history[-1] if len(count_history) else 0
            count_diff = handles_processed_count - prev_count
            count_history.append(handles_processed_count)
            handles_per_most_recent_minute = count_diff / (elapsed_seconds / 60)
            rate_history.append(handles_per_most_recent_minute)
            handles_remaining = total_handles_count - handles_processed_count
            average_handles_rate = sum(rate_history) / len(rate_history)
            minutes_until_completion = handles_remaining / average_handles_rate
            completion_time = (datetime.datetime.today() + datetime.timedelta(minutes=minutes_until_completion)).today()
            self.logger.info(f"processed {count_diff} in most recent period, for a rate of {handles_per_most_recent_minute} per minute")
            self.logger.info(f"average handles per minute rate {average_handles_rate}; total handles processed {handles_processed_count}")
            self.logger.info(f"handles remaining {handles_remaining}, projected completion time {completion_time.isoformat()}")

    def retrieve_profile(self, handle, profile_page_url):
        profile_page, result = self.page_factory.instantiate_and_fetch_page(handle, profile_page_url)
        return result

    def retrieve_relations_from_profile(self, handle, profile_page_url):
        profile_page, result = self.page_factory.instantiate_and_fetch_page(handle, profile_page_url)
        if isinstance(result, Failed_Request):
            return result
        first_following_page_url, first_followers_page_url = profile_page.generate_initial_relation_page_urls()
        result = self.retrieve_relations(handle, first_following_page_url)
        if isinstance(result, Failed_Request):
            return result
        result = self.retrieve_relations(handle, first_followers_page_url)
        return result

    def retrieve_relations(self, handle, first_relation_page_url):
        first_relation_page, result = self.page_factory.instantiate_and_fetch_page(handle, first_relation_page_url)
        if isinstance(result, Failed_Request):
            return result
        first_relation_page.save_page(self.data_store)
        if first_relation_page.is_dynamic:
            return result
        total_result = 0
        for relation_page_url in first_relation_page.generate_all_relation_page_urls():
            relation_page, result = self.page_factory.instantiate_and_fetch_page(handle, relation_page_url)
            if isinstance(result, Failed_Request):
                return result
            relation_page.save_page(self.data_store)
            total_result + result
        return total_result


parser = optparse.OptionParser()
parser.add_option("-C", "--handles-from-args", action="store_true", default=False, dest="handles_from_args",
                  help="skip querying the database for handles, instead process only the handles specified on the "
                       "commandline")
parser.add_option("-H", "--handles-join-profiles", action="store_true", default=False, dest="handles_join_profiles",
                  help="when fetching profiles, load unfetched handles from the `handles` table left join the "
                       "`profiles` table")
parser.add_option("-p", "--fetch-profiles-only", action="store_true", default=False, dest="fetch_profiles_only", 
                  help="fetch profiles only, disregard following & followers pages")
parser.add_option("-q", "--fetch-relations-only", action="store_true", default=False, dest="fetch_relations_only",
                  help="fetch following & followers pages only, disregard profiles")
parser.add_option("-r", "--fetch-profiles-and-relations", action="store_true", default=False,
                  dest="fetch_profiles_and_relations", help="fetch both profiles and relations")
parser.add_option("-R", "--relations-join-profiles", action="store_true", default=False, dest="relations_join_profiles",
                  help="when fetching profiles, load unfetched handles from the `relations` table left join the "
                       "`profiles` table")
parser.add_option("-t", "--use-threads", action="store", default=0, type="int", dest="use_threads", help="use the "
                  "specified number of threads")
parser.add_option("-w", "--dont-discard-bc-wifi", action="store_true", default=False, dest="dont_discard_bc_wifi",
                  help="when loading a page leads to a connection error, assume it's the wifi and don't store a null "
                       "bio")
parser.add_option("-x", "--dry-run", action="store_true", default=False, dest="dry_run", help="don't fetch anything, "
                  "just load data structures from the database and then exit")

(options, args) = parser.parse_args()

if not options.fetch_profiles_only and not options.fetch_relations_only and not options.fetch_profiles_and_relations:
    print("please specify one of either -p, -q or -r on the commandline to choose the scraping mode")
    exit(1)
elif options.fetch_profiles_only and options.fetch_relations_only or \
    options.fetch_profiles_only and options.fetch_profiles_and_relations or \
    options.fetch_relations_only and options.fetch_profiles_and_relations:
    print("more than just one of -p, -q and -r specified on the commandline; please supply only one")
    exit(1)

if (options.fetch_profiles_only or options.fetch_profiles_and_relations) and not (options.handles_join_profiles or options.relations_join_profiles or options.handles_from_args):
    print("if -p or -r is specified, please specify one of -H, -R or -C on the commandline to indicate where to source handles to process")
    exit(1)
elif (options.fetch_profiles_only or options.fetch_profiles_and_relations) and \
        ((options.handles_join_profiles and options.relations_join_profiles) or
         (options.handles_join_profiles and options.handles_from_args) or
         (options.relations_join_profiles and options.handles_from_args)):
    print("with -p or -r specified, please specify _only one_ of -H, -R or -C on the commandline to indicate where to source handles to process")
    exit(1)
elif options.fetch_relations_only and (options.handles_join_profiles or options.relations_join_profiles):
    print("with -q specified, please don't specify -H or -R; profiles-only fetching uses a profiles left join relations query for its handles")
    exit(1)
elif options.handles_from_args and not args:
    print("with -C specified, please supply one or more handles on the commandline")
    exit(1)
elif not options.handles_from_args and args:
    print("-C was not specified, but args supplied on the commandline")
    exit(1)
elif options.use_threads and options.dry_run:
    print("-t and -x were both specified, these modes conflict")
    exit(1)
    

main_logger = logging.getLogger(name="main")
main_logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
if options.use_threads:
    formatter = logging.Formatter('[%(asctime)s] <%(name)s> %(levelname)s: %(message)s')
else:
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
handler.setFormatter(formatter)
main_logger.addHandler(handler)


if options.fetch_profiles_only:
    main_logger.info("got -p flag, entering profiles-only mode")
elif options.fetch_relations_only:
    main_logger.info("got -q flag, entering relations-only mode")
else:
    main_logger.info("got -r flag, entering profiles & relations mode")
if options.relations_join_profiles:
    main_logger.info("got -R flag, sourcing handles from relations join profiles")
elif options.handles_join_profiles:
    main_logger.info("got -H flag, sourcing handles from handles join profiles")
elif options.fetch_relations_only:
    main_logger.info("got -q flag, sourcing handles from profiles join relations")
if options.dry_run:
    main_logger.info("got -x flag, doing a dry run")
if options.dry_run:
    main_logger.info("got -w flag, saving handles for later if a generic connection error occurs")

handle_re = re.compile("^@([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)$")


def determine_rowcount(read_data_store, main_logger):
    rowcount = 0
    main_logger.info(f"loading handles from the profiles table who are not in the relations table")
    if options.fetch_relations_only:
        handles_generator = read_data_store.users_in_profiles_not_in_relations()
    elif options.handles_join_profiles:
        handles_generator = read_data_store.users_in_handles_not_in_profiles()
    elif options.relations_join_profiles:
        handles_generator = read_data_store.users_in_relations_not_in_profiles()
    while True:
        user = next(handles_generator, None)
        if user is None:
            break
        rowcount += 1
    main_logger.info(f"detected {rowcount} handles in response to query")
    return rowcount

save_profiles=(options.fetch_profiles_only or options.fetch_profiles_and_relations)
save_relations=(options.fetch_relations_only or options.fetch_profiles_and_relations)

if options.handles_from_args:
    write_data_store = Data_Store()
    read_data_store = Data_Store()
    instances_dict = Instance.fetch_all_instances(read_data_store, main_logger)
    handle_processor = Handle_Processor(Data_Store(main_logger), main_logger, instances_dict,
                                        save_profiles=save_profiles, save_relations=save_relations,
                                        dont_discard_bc_wifi=options.dont_discard_bc_wifi)
    handle_objs_from_args = list()
    for handle_str in args:
        match = handle_re.match(handle_str)
        if match is None:
            logging.error(f"got argument {handle_str} that doesn't parse as a mastodon handle; fatal error")
            exit(1)
        username, host = match.group(1,2)
        handle = Handle(username=username, host=host)
        handle.fetch_or_set_handle_id(write_data_store)
        handle_objs_from_args.append(handle)
    if options.dry_run:
        exit(0)
    handle_processor.process_handle_iterable(len(handle_objs_from_args), handle_objs_from_args)
elif options.use_threads:
    threads = list()
    loggers = list()
    read_data_stores = list()
    handle_processors = list()
    handles_lists = [list() for _ in range(0, options.use_threads)]
    for index in range(0, options.use_threads):
        loggers.append(logging.getLogger(name=f"thread#{index}"))
        loggers[-1].setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        handler.setFormatter(formatter)
        loggers[-1].addHandler(handler)
        read_data_stores.append(Data_Store(loggers[-1]))
    instances_dict = Instance.fetch_all_instances(read_data_stores[0], main_logger)
    for index in range(0, options.use_threads):
        handle_processors.append(Handle_Processor(read_data_stores[index], loggers[index], instances_dict,
                                                  save_profiles=save_profiles, save_relations=save_relations,
                                                  dont_discard_bc_wifi=options.dont_discard_bc_wifi))
    rowcount = determine_rowcount(read_data_stores[0], main_logger)
    if options.dry_run:
        exit(0)
    if options.fetch_relations_only:
        handles_generator = read_data_stores[0].users_in_profiles_not_in_relations()
    elif options.handles_join_profiles:
        handles_generator = read_data_stores[0].users_in_handles_not_in_profiles()
    elif options.relations_join_profiles:
        handles_generator = read_data_stores[0].users_in_relations_not_in_profiles()
    try:
        while True:
            for index in range(0, options.use_threads):
                handles_lists[((index + 1) % options.use_threads) - 1].append(next(handles_generator))
    except StopIteration:
        pass
    main_logger.info("populated handles lists, lengths " + ", ".join(str(len(handle_list))
                                                                     for handle_list in handles_lists))
    for index in range(0, options.use_threads):
        threads.append(threading.Thread(target=handle_processors[index].process_handle_iterable,
                                        args=(len(handles_lists[index]), iter(handles_lists[index])), daemon=True))
        main_logger.info(f"instantiated thread #{index}")
    for index in range(0, options.use_threads):
        threads[index].start()
        main_logger.info(f"started thread #{index}")
    for index in range(0, options.use_threads):
        threads[index].join()
        main_logger.info(f"closed thread #{index}")
else:
    read_data_store = Data_Store(main_logger)
    instances_dict = Instance.fetch_all_instances(read_data_store, main_logger)
    handle_processor = Handle_Processor(Data_Store(main_logger), main_logger, instances_dict,
                                        save_profiles=save_profiles, save_relations=save_relations,
                                        dont_discard_bc_wifi=options.dont_discard_bc_wifi)
    rowcount = determine_rowcount(read_data_store, main_logger)
    if options.dry_run:
        exit(0)
    if options.fetch_relations_only:
        handles_generator = read_data_store.users_in_profiles_not_in_relations()
    elif options.handles_join_profiles:
        handles_generator = read_data_store.users_in_handles_not_in_profiles()
    elif options.relations_join_profiles:
        handles_generator = read_data_store.users_in_relations_not_in_profiles()
    handle_processor.process_handle_iterable(rowcount, handles_generator)
