#!/usr/bin/python3

import bs4
import datetime
import html2text
import MySQLdb
import re
import requests
import selenium
import selenium.common.exceptions
import selenium.webdriver
import selenium.webdriver.common.by
import selenium.webdriver.firefox.options
import socket
import time
import urllib

from arachnea.handles import Handle, Deleted_User
from arachnea.succeedfail import Failed_Request, Internal_Exception


# One of two places that a timeout of 5 seconds is set. The other place is at
# the top of the Page.requests_fetch() method where the actual requests.get()
# call is made.
socket.setdefaulttimeout(5)

# Used to set how long selenium.webdriver waits between directing the puppet
# firefox instance to scroll the page.
SCROLL_PAUSE_TIME = 1.0


class Page_Fetcher:
    """
    An originator of Page objects that executes this workflow:

    * Prepares the request
    * Fails fast if it is unsatisfiable
    * Instances the Page object
    * Has the Page object execute the request
    * If it fails, handles a variety of failed requests in different ways
    * If it succeeds, yields the Page object.
    """
    __slots__ = ('instances_dict', 'data_store', 'logger_obj', 'deleted_users_dict', 'save_profiles', 'save_relations',
                 'dont_discard_bc_wifi', 'conn_err_wait_time')

    def __init__(self, data_store, logger_obj, instances_dict, save_profiles=False, save_relations=False,
                       dont_discard_bc_wifi=False, conn_err_wait_time=0.0):
        """
        Instances the Page_Fetcher object.

        :param data_store:                 The Data_Store object to use when saving a
                                           Page or Deleted_User object.
        :type data_store:                  Data_Store
        :param logger_obj:                     The Logger object to use to log events.
        :type logger_obj:                      logging.Logger
        :param instances_dict:             A dict mapping hostnames to Instance objects
                                           that is the store of known instance and their
                                           statuses.
        :type instances_dict:              dict
        :param save_profiles:              True to run in profiles-saving mode, False
                                           otherwise.
        :type save_profiles:               bool
        :param save_relations:             True to run in followers/following-saving mode, False
                                           otherwise.
        :type save_relations:              bool
        :param dont_discard_bc_wifi:       True if connection errors are to be treated
                                           as nonfatal, False if a connection error
                                           should result in recording a null page to the
                                           Data Store. (Only applies to profiles at present.)
        :type dont_discard_bc_wifi:        bool
        :param conn_err_wait_time:         When a connection error is treated as
                                           nonfatal, sleep this number of seconds
                                           before resuming the algorithm.
        :type conn_err_wait_time:          bool
        """
        self.data_store = data_store
        self.logger_obj = logger_obj
        self.instances_dict = instances_dict
        self.deleted_users_dict = Deleted_User.fetch_all_deleted_users(self.data_store)
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.dont_discard_bc_wifi = dont_discard_bc_wifi
        self.conn_err_wait_time = conn_err_wait_time

    def instantiate_and_fetch_page(self, handle, url):
        host = handle.host
        if host in self.instances_dict:
            instance = self.instances_dict[host]
        else:
            self.instances_dict[host] = instance = Instance(host, self.logger_obj,
                                                            dont_discard_bc_wifi=self.dont_discard_bc_wifi)

        # There exists a record of this instance in the instances_dict. It is
        # almost certainly not contactable. Figuring out *how* and handle it.
        if instance is not None:
            if instance.malfunctioning or instance.unparseable or instance.suspended:
                if self.save_profiles:
                    # If in a profile-saving mode, a handle that turns out to
                    # have a bad instance gets a null profile bio saved to the
                    # data store. The empty Page for that profile is returned.
                    self.logger_obj.info(f"instance {host} on record as {instance.status}; "
                                     f"didn't load {url}; saving null bio to database")
                    page = Page(handle, url, self.logger_obj, instance, save_profiles=self.save_profiles,
                                save_relations=self.save_relations, dont_discard_bc_wifi=self.dont_discard_bc_wifi)
                    page.save_page(self.data_store)
                    return page, Failed_Request(host,
                                                malfunctioning=instance.malfunctioning,
                                                unparseable=instance.unparseable,
                                                suspended=instance.suspended)
                else:
                    # If in a relations-saving mode, no Page is generated or
                    # saved.
                    self.logger_obj.info(f"instance {host} on record as {instance.status}; didn't load {url}")
                    return None, Failed_Request(host,
                                                malfunctioning=instance.malfunctioning,
                                                unparseable=instance.unparseable,
                                                suspended=instance.suspended)
            elif instance.still_rate_limited():

                # The other case for an unreachable instance is if the program
                # is rate-limited from it.
                self.logger_obj.info(f"instance {host} still rate limited, expires at "
                                 f"{instance.rate_limit_expires_isoformat}, didn't load {url}")
                return None, Failed_Request(host, ratelimited=True)

        # There exists a record of this user-instance combination in the
        # deleted_users_dict. Handling it.
        elif (handle.username, handle.host) in self.deleted_users_dict:
            # FIXME: this step can be skipped if a JOIN against deleted_users is
            # added to the handles loading step
            # FIXME should save a null bio
            self.logger_obj.info(f"user {handle.handle} known to be deleted; didn't load {url}")
            return None, Failed_Request(handle.host, user_deleted=True)

        # Possibilities for aborting transfer don't apply; proceeding with a
        # normal attempt to load the page.
        host = urllib.parse.urlparse(url).netloc
        if host in self.instances_dict:
            instance = self.instances_dict[host]
        else:
            self.instances_dict[host] = instance = Instance(host, self.logger_obj,
                                                            dont_discard_bc_wifi=self.dont_discard_bc_wifi)
        page = Page(handle, url, self.logger_obj, instance, save_profiles=self.save_profiles,
                    save_relations=self.save_relations, dont_discard_bc_wifi=self.dont_discard_bc_wifi)
        result = page.requests_fetch()

        # If the request failed because the page is dynamic (ie. has a
        # <noscript> tag), trying again using webdriver.
        if isinstance(result, Failed_Request) and result.is_dynamic:
            self.logger_obj.info(f"loaded {url}: page has <noscript>; loading with webdriver")
            result = page.webdriver_fetch()

        # BEGIN *outer* big conditional
        if isinstance(result, Failed_Request):

            # Beginning the elaborate process of testing for and handling every
            # possible error case. There's quite a few.

            # BEGIN *inner* big conditional
            if result.ratelimited:

                # The program is rate-limited. Saving that fact to
                # self.instances_dict.
                if host not in self.instances_dict:
                    instance = Instance(host, self.logger_obj, rate_limited=True,
                                        x_ratelimit_limit=result.x_ratelimit_limit,
                                        dont_discard_bc_wifi=self.dont_discard_bc_wifi)
                    self.instances_dict[host] = instance
                else:
                    instance = self.instances_dict[host]
                    instance.set_rate_limit(x_ratelimit_limit=result.x_ratelimit_limit)
                self.logger_obj.info(f"failed to load {url}: rate limited: expires at " +
                                 instance.rate_limit_expires_isoformat)

            # The instance malfunctioned.
            elif result.malfunctioning:

                # Saving that fact to the instances_dict.
                if host in self.instances_dict:
                    instance = self.instances_dict[host]
                    instance.attempts += 1
                else:
                    instance = Instance(host, self.logger_obj, attempts=1,
                                        dont_discard_bc_wifi=self.dont_discard_bc_wifi)
                    self.instances_dict[host] = instance

                # Logging the precise type malfunction it was.
                if result.ssl_error:
                    self.logger_obj.info(f"failed to load {url}, host malfunctioning: ssl error "
                                     f"(error #{instance.attempts} for this host)")
                elif result.too_many_redirects:
                    self.logger_obj.info(f"failed to load {url}, host malfunctioning: too many redirects "
                                     f"(error #{instance.attempts} for this host)")
                elif result.timeout:
                    self.logger_obj.info(f"failed to load {url}, host malfunctioning: connection timeout "
                                     f"(error #{instance.attempts} for this host)")
                elif result.connection_error:
                    self.logger_obj.info(f"failed to load {url}, host malfunctioning: connection error "
                                     f"(error #{instance.attempts} for this host)")
                else:
                    self.logger_obj.info(f"failed to load {url}, host malfunctioning: "
                                         f"got status code {result.status_code} "
                                     f"(error #{instance.attempts} for this host)")

            elif result.user_deleted:

                # The user has been deleted from the instance. Saving that fact
                # to the data store.
                deleted_user = handle.convert_to_deleted_user()
                deleted_user.logger_obj = self.logger_obj
                self.deleted_users_dict[handle.username, handle.host] = deleted_user
                deleted_user.save_deleted_user(self.data_store)
                self.logger_obj.info(f"failed to load {url}: user deleted")

            # Several other kinds of error that only need to be logged.
            elif result.webdriver_error:
                self.logger_obj.info(f"loading {url}: webdriver loading failed with internal error")
            elif result.no_public_posts:
                self.logger_obj.info(f"loaded {url}: no public posts")
            elif result.posts_too_old:
                self.logger_obj.info(f"loaded {url}: posts too old")
            elif result.unparseable:
                self.logger_obj.info(f"loaded {url}: parsing failed")
            elif result.robots_txt_disallowed:
                self.logger_obj.info(f"loading {url}: site's robots.txt does not allow it")

            # The profile gave the program a forwarding address.
            # FIXME should save these to the handles table.
            elif result.forwarding_address:
                if result.forwarding_address is True:
                    self.logger_obj.info(f"loaded {url}: forwarding page (could not recover handle)")
                else:
                    self.logger_obj.info(f"loaded {url}: forwarding page")
            else:
                self.logger_obj.info(f"loading {url}: unanticipated error {repr(result)}")
            # END *first* big conditional

            # A connection failure when retrieving a profile normally leads to
            # saving a null profile bio to the data store. The only exception is
            # if --dont-discard-bc-wifi was specified on the commandline.
            if result.connection_error and self.dont_discard_bc_wifi:
                # Handling the case of when the --dont-discard-bc-wifi flag
                # is in effect and a connection error has happened.

                what_fetched = ('profile' if page.is_profile
                                else 'following' if page.is_following
                                else 'followers' if page.is_followers else '???')

                self.logger_obj.info(f"handle {handle.handle}: fetching {what_fetched} returned connection error; "
                                 "but the wifi might've gone out, saving for later")

                # If the wifi goes out, it's possible for this program to chew
                # through hundreds of passes of the main loop before it's
                # restored. That expends lot of queued handles that can't be
                # recovered until the program is restarted.
                #
                # The --conn-err-wifi-sleep-period flag is used to specify a
                # wait time to sleep for when the (self.dont_discard_bc_wifi and
                # result.connection_error) condition is True.
                if self.conn_err_wait_time:
                    time.sleep(self.conn_err_wait_time)

            else:
                page.save_page(self.data_store)

            return None, result

        # END *outer* big conditional
        # type(result) is not Failed_Request

        # Logging what kind of page was loaded
        if self.save_profiles and page.is_profile:
            self.logger_obj.info(f"loaded {url}: detected profile bio, length {len(page.profile_bio_text)}")
        elif self.save_relations and page.is_following:
            self.logger_obj.info(f"loaded {url}: found {result} following handles")
        elif self.save_relations and page.is_followers:
            self.logger_obj.info(f"loaded {url}: found {result} followers handles")

        return page, result


class Page:
    """
    Represents a single page; handles retrieving the page and the ensuing errors
    itself.
    """
    __slots__ = ('handle', 'username', 'host', 'logger_obj', 'instance', 'url', 'document', 'is_dynamic', 'loaded',
                 'is_profile', 'is_following', 'is_followers', 'page_number', 'profile_no_public_posts',
                 'profile_posts_too_old', 'profile_bio_text', 'relations_list', 'unparseable', 'save_profiles',
                 'save_relations', 'dont_discard_bc_wifi')

    # Regular expressions used in the retrieval and parsing of the page.

    # Matches the handle in a forwarding notice when parsing a page that has one.
    forwarding_handle_re = re.compile(r'^.*(@) ([A-Za-z0-9._]+@[A-Za-z0-9._]+\.[a-z]+).*$', flags=re.M)

    # Matches a URL of the form https://instance/@username
    handle_url_href_re = re.compile(r'https://([\w.]+\.\w+)/@(\w+)')

    # Matches the class used to denote the forwarding handle notice.
    moved_handle_class_re = re.compile(r'moved-account-widget__message')

    # Matches a URL used to link to profiles.
    profile_url_re = re.compile(r'(?:https://[A-Za-z0-9_.-]+\.[a-z]+)?/@[A-Za-z0-9_.-]+$')

    # Matches a URL used to link to a following or followers page.
    relation_url_re = re.compile(r'(?:https://[A-Za-z0-9_.-]+\.[a-z]+)?'
                                 r'/(?:users/|@)[A-Za-z0-9_.-]+/(follow(?:ing|ers))(?:\?page=[0-9]+)?$')

    # Matches the breakpoint in a static page pagination URL between base URL
    # and the pagination argument.
    static_pagination_page_split_re = re.compile("(?<=page=)")

    # Matches the URL of a static page.
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

    def __init__(self, handle, url, logger_obj, instance, save_profiles=False, save_relations=False,
                 dont_discard_bc_wifi=False):
        """
        Instances the Page object.

        :param handle:         The handle of the profile the page belongs to.
        :type handle:          Handle
        :param url:            The URL of the page.
        :type url:             str
        :param logger_obj:         The Logger object to log events to.
        :type logger_obj:          logging.Logger
        :param instance:       The Instance object associated with the host this Page's
                               url is located at.
        :type instance:        Instance
        :param save_profiles:  If the program is in a profiles-saving mode.
        :type save_profiles:   bool
        :param save_relations: If the program is in a relations-saving mode.
        :type save_relations:  bool
        """
        # Setting instance vars from the args and their attributes.
        self.handle = handle
        self.url = url
        self.logger_obj = logger_obj
        self.instance = instance
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.username = handle.username
        self.host = handle.host
        self.dont_discard_bc_wifi = dont_discard_bc_wifi

        # Setting some defaults.
        self.document = None
        self.is_dynamic = False
        self.loaded = None
        self.is_profile = self.is_following = self.is_followers = False
        self.profile_no_public_posts = self.profile_posts_too_old = False
        self.relations_list = list()
        self.unparseable = False
        self.profile_bio_text = ''

        # Parsing the URL to discover what kind of page this is and what page
        # number it is.
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
            raise Internal_Exception("unable to discern profile, following or follower page "
                                     f"from parsing URL {self.url} ")

    def requests_fetch(self):
        """
        Tries to fetch self.url using requests.get()

        :return:

        """
        try:
            can_fetch = self.instance.can_fetch(self.url)
        except requests.exceptions.ConnectionError:
            # If the robots.txt couldn't be fetched due to a transient
            # connection error, the program just assumes the retrieval is
            # allowed. Odds are this retrieval will suffer a connection error
            # too, in any event.
            can_fetch = True
        if not can_fetch:
            # The file can't be fetched because the site has a robots.txt and
            # the robots.txt disallows it.
            self.loaded = False
            return Failed_Request(self.host, robots_txt_disallowed=True)
        # A big try/except statement to handle a variety of different Exceptions
        # differently.
        try:
            http_response = requests.get(self.url, timeout=5.0)
        except requests.exceptions.SSLError:
            # An error in the SSL handshake, or an expired cert.
            self.loaded = False
            return Failed_Request(self.host, malfunctioning=True, ssl_error=True)
        except requests.exceptions.TooManyRedirects:
            # The instance put the program's client through too many redirects.
            self.loaded = False
            return Failed_Request(self.host, malfunctioning=True, too_many_redirects=True)
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
            # The connection timed out.
            self.loaded = False
            return Failed_Request(self.host, malfunctioning=True, timeout=True)
        except (requests.exceptions.ConnectionError, IOError):
            # There was a generic connection error.
            self.loaded = False
            return Failed_Request(self.host, malfunctioning=True, connection_error=True)

        # There's a requests.models.Response object, but now the program needs
        # to handle all the non-200 status codes.
        if http_response.status_code == 429:
            # The program has been rate-limited.
            if http_response.headers['x-ratelimit-limit']:
                # If there's an X-Ratelimit-Limit header, the program captures
                # its int value and saves that in the Failed_Request object
                # bc that's how many seconds the program needs to wait before
                # trying again.
                self.loaded = False
                return Failed_Request(self.host, status_code=http_response.status_code, ratelimited=True,
                                                 x_ratelimit_limit=float(http_response.headers['x-ratelimit-limit']))
            else:
                self.loaded = False
                return Failed_Request(self.host, status_code=http_response.status_code, ratelimited=True)
        elif http_response.status_code in (401, 400, 403, 406) or http_response.status_code >= 500:
            # The instance emitted a status code that indicates it's not
            # handling requests correctly. The program classes it as malfunctioning.
            self.loaded = False
            return Failed_Request(self.host, status_code=http_response.status_code, malfunctioning=True)
        elif http_response.status_code == 404 or http_response.status_code == 410:
            # The status code is 404 Not Found or 410 Gone. The user has been deleted.
            self.loaded = False
            return Failed_Request(self.host, status_code=http_response.status_code, user_deleted=True)
        elif http_response.status_code != 200:
            # Any other status code than 200; one the program wasn't expecting.
            # Saving it to the Failed_Request object for the caller to handle.
            self.loaded = False
            return Failed_Request(self.host, status_code=http_response.status_code)
        else:
            # An ostensibly valid page was returned. Parse it with BS and see if
            # it contains the data the program's looking for.
            self.document = bs4.BeautifulSoup(markup=http_response.text, features='lxml')
            if self.document.find_all('noscript'):
                # The page has a noscript tag, which means it's dynamic. The
                # caller will need to try again with webdriver.
                self.loaded = False
                self.is_dynamic = True
                return Failed_Request(self.host, is_dynamic=True)
            else:
                # The page is static and parseable with static tools.
                self.loaded = True
                if self.is_profile and self.save_profiles:
                    # In a profile-saving mode, parse it as a profile page.
                    return self.parse_profile_page()
                elif (self.is_following or self.is_followers) and self.save_relations:
                    # In a relations-saving mode, parse it as a relations page.
                    return self.parse_relations_page()
                else:
                    # The page is a profile when the program is not saving
                    # profiles, or a relation when the program is not saving
                    # relations. This call was made in error. Return False.
                    return False

        # This is only reachable if the preceding if/then/else chain ended in
        # its else clause and the page was parsed. So the document was returned
        # and is in line with the mode. Return True.
        return True

    def webdriver_fetch(self):
        """
        Tries to fetch self.url using selenium.webdriver.firefox.

        :return: If the fetch was successful and it's a profile, the lenth of the
                 bio; if it's a relations page, the number of relations. If it failed,
                 then a Failed_Request object detailing the problem. If the fetch can't
                 be done bc it's a profile when not in a profile-fetching mode, or a
                 relations page when not in relations-fetching mode, False.
        :rtype:  bool, int, or Failed_Request
        """
        # FIXME implement a Successful_Request object to normalize the return
        # values of this and subordinate methods.
        if not self.instance.can_fetch(self.url):
            # The file can't be fetched because the site has a robots.txt and
            # the robots.txt disallows it.
            self.loaded = False
            return Failed_Request(self.host, robots_txt_disallowed=True)
        try:
            # Instancing the headless puppet firefox instance.
            options = selenium.webdriver.firefox.options.Options()
            options.add_argument('-headless')
            self.logger_obj.info("webdriver instantiating headless Firefox program")
            browser = selenium.webdriver.Firefox(options=options)
            self.logger_obj.info(f"webdriver loading URL {self.url}")

            browser.get(self.url)

            if self.is_profile and self.save_profiles:
                # If this is a profile page, then it doesn't need to be
                # scrolled, and no further interaction with the page is
                # necessary after capturing the initial JS rendering.
                html = browser.page_source
                self.document = bs4.BeautifulSoup(markup=html, features='lxml')
                page_height = browser.execute_script("return document.body.scrollHeight")
                self.logger_obj.info(f"webdriver loaded page of height {page_height}")

                # Contrast with parse_relations_page(), which *does* need to
                # interact with the page further.
                return self.parse_profile_page()
            elif (self.is_following or self.is_followers) and self.save_relations:
                # The page needs to be scrolled to the bottom, moving the pane
                # down by its height step by step, to ensure the entire page
                # is loaded (may be other lazy-loaded elements) and so that
                # parse_relations_page() starts from the bottom.
                last_height = browser.execute_script("return document.body.scrollHeight")
                self.logger_obj.info(f"webdriver loaded initial page height {last_height}")
                while True:

                    # The most effective way to scroll the amount needed is to
                    # use JS to scroll the page by the body's scrollheight.
                    #
                    # Thanks to lazy loading, the body elements's scrollheight
                    # is either as tall as how much of the page has already been
                    # displayed, or somewhat longer but not guaranteed to be the
                    # full height the body element can be.
                    #
                    # The while loop scrolls to scrollHeight until it stops
                    # changing, which is how the program knows it's reached the
                    # true bottom of the page.
                    browser.execute_script("window.scrollTo(0, document.body.scrollHeight);")

                    # The program pauses to give the lazy-loading javascript
                    # on the page time to execute and complete loading their
                    # elements and updating the page.
                    time.sleep(SCROLL_PAUSE_TIME)

                    # Checking if the scrollHeight has bottomed out; if so,
                    # scrolling is done and the loop exits.
                    new_height = browser.execute_script("return document.body.scrollHeight")
                    if new_height == last_height:
                        self.logger_obj.info(f"webdriver scrolled down to page height {last_height} "
                                             "and finished scrolling")
                        break
                    last_height = new_height
                    self.logger_obj.info(f"webdriver scrolled down to page height {last_height}")

                # Time to parse the page. More scrolling and detection of
                # elements will be involved so parse_relations_page() takes the
                # browser object.
                return self.parse_relations_page(browser)
            else:
                return False
        except (selenium.common.exceptions.NoSuchElementException, selenium.common.exceptions.WebDriverException):
            # selenium.webdriver failed fsr. There's no diagnosing this sort of
            # thing, so a Failed_Request is returned.
            self.logger_obj.info("webdriver experienced an internal error, failing")
            return Failed_Request(self.host, webdriver_error=True)
        finally:
            self.logger_obj.info("closing out webdriver Firefox instance")
            browser.quit()
            del browser

    def parse_profile_page(self):
        """
        Parses the loaded page in the self.document attribute, treating it as a
        profile page. Rules it out if it's not a usable page, otherwise extracts
        the profile bio and save it.

        :return: If the page is ruled out for some reason or the parsing failed, returns
                 a Failed_Request object. Otherwise returns the length of the bio in
                 acharacters fter the HTML has been converted to markdown.
        :rtype:  Failed_Request or int
        """
        # FIXME should draw its post age threshold from a global constant
        self.logger_obj.info(f"parsing profile at {self.url}")
        # FIXME correct time tag parsing to reflect the latest format in use
#       time_tags = self.document.find_all('time', {'class': 'time-ago'})
#        if len(time_tags) == 0:
#            self.profile_no_public_posts = True
#            return Failed_Request(self.host, no_public_posts=True)
#        else:
#            time_tags = [time_tag['datetime'] for time_tag in time_tags]
#            if '+' in time_tags[0]:
#                time_tags = [time_split[0]+'Z' for time_split in (time_tag.split('+') for time_tag in time_tags)]
#            toot_datetimes = sorted(map(lambda time_tag: datetime.datetime.strptime(time_tag,
#                                                                                    '%Y-%m-%dT%H:%M:%SZ'),
#                                        time_tags))
#            seven_days_ago_datetime = datetime.datetime.today() - datetime.timedelta(days=7)
#            most_recent_toot_datetime = toot_datetimes[0]
#            self.profile_posts_too_old = most_recent_toot_datetime < seven_days_ago_datetime
#            if self.profile_posts_too_old:
#                return Failed_Request(self.host, posts_too_old=True)

        # Detects if this is a forwarding page.
        forwarding_tag = self.document.find('div', {'class': self.moved_handle_class_re})
        if forwarding_tag:
            forwarding_match = self.forwarding_handle_re.match(html2text.html2text(forwarding_tag.prettify()))
            # Tries to detect and save the forwarding handle but it doesn't
            # always parse.
            if forwarding_match is not None:
                handle_at, handle_rest = forwarding_match.groups()
                forwarding_handle = handle_at + handle_rest
                # FIXME forwarding handles should be loaded into the data store.
                return Failed_Request(self.host, forwarding_address=forwarding_handle)
            else:
                return Failed_Request(self.host, forwarding_address=True)

        # Trying 2 known classes used to demarcate the bio by different versions
        # of Mastodon.
        profile_div_tag = self.document.find('div', {'class': 'public-account-bio'})
        if profile_div_tag is None:
            profile_div_tag = self.document.find('div', {'class': 'account__header__content'})

        # If the profile div couldn't be found, return a Failed_Request.
        if profile_div_tag is None:
            self.unparseable = True
            return Failed_Request(self.host, unparseable=True)

        # If this is a dynamic page, clear out some known clutter from the
        # profile bio div.
        if self.is_dynamic:
            unwanted_masto_link_divs = profile_div_tag.find_all('div', {'class': 'account__header__extra__links'})
            if len(unwanted_masto_link_divs):
                unwanted_masto_link_divs[0].replaceWith('')

        # Convert the bio to markdown and save it. The program doesn't need its
        # HTML. Return the length of the bio.
        self.profile_bio_text = html2text.html2text(str(profile_div_tag))
        return len(self.profile_bio_text)

    def parse_relations_page(self, browser=None):
        """
        Parses the loaded page in the self.document attribute, treating it as a
        relations (ie. following or followers) page. Rules it out if it's not a usable
        page, otherwise extracts the following or followers profile links and saves
        them. Expects a webdriver browser instance as an argument if self.is_dynamic is
        True.

        :param browser: The webdriver browser object of the headless puppet
                        Firefox instance that has loaded the relations page fully and is
                        ready to be scrolled across scaping data.
        :type browser:  selenium.webdriver.firefox.webdriver.WebDriver, optional
        :return:        If the parsing process failed for any reason, a Failed_Request
                        object; otherwise the number of following or followers profile
                        links collected.
        :rtype:         Failed_Request or int
        """
        self.logger_obj.info(f"parsing {self.relation_type} at {self.url}")

        # This is a dynamic page, so the program parses the dynamic form of the
        # following/followers page, which takes quite a lot of work.
        if self.is_dynamic:
            try:
                html_tag = browser.find_element(selenium.webdriver.common.by.By.XPATH, '/html')

                # Scrolls to HOME and then END, just to sort out any remaining
                # javascript that can be prompted to execute by doing this.
                html_tag.send_keys(selenium.webdriver.common.keys.Keys.HOME)
                time.sleep(SCROLL_PAUSE_TIME)
                html_tag.send_keys(selenium.webdriver.common.keys.Keys.END)
                time.sleep(SCROLL_PAUSE_TIME)

                html_tag.send_keys(selenium.webdriver.common.keys.Keys.ARROW_UP)
                # Initially priming the article_tag_text_by_data_id dict with
                # all the article tag data-id attributes that can currently be
                # seen.
                data_ids = [tag.get_attribute('data-id') for tag in browser.find_elements(
                                                                                selenium.webdriver.common.by.By.XPATH,
                                                                                "//article")]
                article_tag_text_by_data_id = dict.fromkeys(data_ids)
                total_article_tags_count = loaded_article_tag_count = len(article_tag_text_by_data_id)

                # Beginning the process of scrolling around the document.
                self.logger_obj.info(f"using selenium.webdriver to page over dynamic {self.relation_type} page forcing "
                            f"<article> tags to load; found {len(article_tag_text_by_data_id)} <article> tags")
                pass_counter = 1
                # FIXME why doesn't this loop just scroll by sending <pgup>?
                #
                # So long as there's any article data-ids in the
                # article_tag_text_by_data_id dict, keep scrolling around the
                # document trying to find them all.
                while any(not bool(text) for text in article_tag_text_by_data_id.values()):
                    # Pull all the article tags the browser can currently see.
                    article_tags = browser.find_elements(selenium.webdriver.common.by.By.XPATH, "//article")

                    for article_tag in article_tags:
                        article_tag_text = article_tag.text
                        data_id = article_tag.get_attribute('data-id')
                        # If the article tag is novel, add its data_id and text
                        # to article_tag_text_by_data_id.
                        if data_id not in article_tag_text_by_data_id:
                            article_tag_text_by_data_id[data_id] = article_tag.text if article_tag_text else ''
                        # If the program knows that data-id and has text for it already, continue.
                        elif article_tag_text_by_data_id[data_id]:
                            continue
                        # If the program has that data-id but didn't have the
                        # text for it, save the text.
                        elif article_tag_text:
                            article_tag_text_by_data_id[data_id] = article_tag.text

                    # This loop scrolls the page into a region where there's
                    # article tags the program knows about but doesn't have text
                    # for yet.
                    for article_tag in article_tags:
                        data_id = article_tag.get_attribute('data-id')
                        if article_tag_text_by_data_id.get(data_id, False):
                            continue
                        browser.execute_script("arguments[0].scrollIntoView();", article_tag)
                        break

                    # Discerning how many tags the program found text for in
                    # this pass, for logging purposes.
                    # FIXME this shouldn't ever report a negative value
                    loaded_article_tag_count = len(tuple(filter(lambda tag_text: not tag_text,
                                                                article_tag_text_by_data_id.values())))
                    empty_article_tags_count_diff = total_article_tags_count - loaded_article_tag_count
                    self.logger_obj.info(f"pass #{pass_counter}: {empty_article_tags_count_diff} "
                                         "<article> tags text found")
                    pass_counter += 1

            except (selenium.common.exceptions.NoSuchElementException, selenium.common.exceptions.WebDriverException):
                # selenium.webdriver failed fsr. There's no diagnosing this sort of
                # thing, so a Failed_Request is returned.
                return Failed_Request(self.host, webdriver_error=True)

            # Converting the dict of article tags' texts to a list of
            # following/followers handles.
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

        # This is a static page, so the program does the static parsing, which
        # is straightforward.
        else:
            # Sweeps the document for <a> tags whose href attribute matches the
            # profile URL regex.
            found_relations_a_tags = self.document.find_all('a', {'href': self.profile_url_re})
            relations_hrefs = [tag.attrs['href'] for tag in found_relations_a_tags]
            for relation_href in relations_hrefs:
                # Uses a separate, capturing regex to grab instance and username
                # from each URL if possible. Any nonmatching href values are
                # discarded.
                handle_match = self.handle_url_href_re.match(relation_href)
                if not handle_match:
                    continue
                relation_instance, relation_username = handle_match.groups()
                # Don't add the instance and username of the owner of this page.
                if relation_username == self.username and relation_instance == self.host:
                    continue
                self.relations_list.append(Handle(username=relation_username, host=relation_instance))

        return len(self.relations_list)

    def generate_initial_relation_page_urls(self):
        """
        If this is a profile page, generates what its following/followers pages links
        should be based on whether it's dynamic or static.

        :return: A 2-element list of urls if this is a profile page, or an empty list
                 otherwise.
        :rtype:  list
        """
        if not self.is_profile:
            return []
        elif self.is_dynamic:
            return [f"https://{self.host}/@{self.username}/following",
                    f"https://{self.host}/@{self.username}/followers"]
        else:
            return [f"https://{self.host}/users/{self.username}/following",
                    f"https://{self.host}/users/{self.username}/followers"]

    def generate_all_relation_page_urls(self):
        """
        If this is a static relations page, generate the full list of relations urls
        that should be valid to the server.

        :return: If this is a static relations page and the page displays a link to the
                 last relations page, returns a list of all urls between page=1 and that
                 page, otherwise returns an empty list.
        :rtype:  list
        """
        if not (self.is_following or self.is_followers) or not self.is_dynamic:
            return []

        # Collects all links that have pagination parameters.
        a_tags = self.document.find_all('a', {'href': self.static_pagination_re})
        if not len(a_tags):
            return []

        # Collects all the href attribute values.
        hrefs = [a_tag['href'] for a_tag in a_tags]

        # Derives a dict associating pages with the urls that link to them.
        relation_url_dict = {(int(href.split('page=')[1])
                              if 'page=' in href
                              else 1): href
                             for href in hrefs}

        # Finds the highest page number and its URL.
        highest_page_no = max(relation_url_dict.keys())
        highest_page_url = relation_url_dict[highest_page_no]

        # Builds all following/followers pages that should exist.
        if 'page=' in highest_page_url:
            base_url, _ = self.static_pagination_page_split_re.split(highest_page_url)
            if not base_url.startswith('https://'):
                base_url = 'https://' + self.host + base_url
            return [f"{base_url}{page_no}" for page_no in range(2, highest_page_no + 1)]
        else:
            return []

    def save_page(self, data_store):
        """
        Saves the page's content to the data store. If this is a profile page, saves the
        profile. If this is a relations page, save the collected following/followers
        handles.

        :param data_store: The Data_Store object to use to contact the database.
        :type data_store:  Data_Store
        :return:           The number of rows affected by the query.
        :rtype:            int
        """
        if self.is_profile:

            # Saving a profile to the profiles table.
            #
            # If there isn't a handle_id on the object, use
            # Handle.fetch_or_set_handle_id() to get one. The auto-incrementing
            # primary key of the handles table is used to identify rows with the
            # same username and instance in other tables.
            #
            # FIXME should use an existing MySQLdb escape method for this
            profile_bio_text = self.profile_bio_text.replace("'", "\\'")
            handle = self.handle
            if not handle.handle_id:
                handle.fetch_or_set_handle_id(data_store)

            # Checking if this profile already exists in the profiles table and
            # already has its profile saved.
            select_sql = f"""SELECT profile_handle_id, profile_bio_markdown FROM profiles
                             WHERE profile_handle_id = {handle.handle_id};"""
            rows = data_store.execute(select_sql)
            if rows:
                ((handle_id, profile_bio_markdown),) = rows
                if profile_bio_markdown:
                    return 0
                elif profile_bio_text:
                    # If by some chance this handle_id already has a row in the
                    # profiles table, but its profile_bio_markdown is null, and the
                    # bio text the program is going to save here is *not* null,
                    # then use an UPDATE statement to set the profile bio.
                    update_sql = f"""UPDATE profiles SET profile_bio_markdown = {profile_bio_text}
                                     WHERE profile_handle_id = {handle.handle_id};"""
                    data_store.execute(update_sql)
                    return 1
            else:
                # Otherwise use an INSERT statement like usual.
                insert_sql = f"""INSERT INTO profiles (profile_handle_id, username, instance,
                                                       considered, profile_bio_markdown)
                                                  VALUES
                                                      ({handle.handle_id}, '{handle.username}',
                                                      '{handle.host}', 0, '{profile_bio_text}');"""
                data_store.execute(insert_sql)
                return 1
        else:

            # Saving following/followers to the relations table.
            if not len(self.relations_list):
                return 0
            relation = 'following' if self.is_following else 'followers'
            profile_handle = self.handle
            # Setting the handle_id attribute if it's missing.
            profile_handle.fetch_or_set_handle_id(data_store)

            # Checking if this page has already been saved to the relations table.
            select_sql = f"""SELECT DISTINCT profile_handle_id FROM relations
                             WHERE profile_handle_id = {profile_handle.handle_id} AND relation_type = '{relation}'
                                   AND relation_page_number = {self.page_number};"""
            rows = data_store.execute(select_sql)
            if rows:
                # If so, return 0.
                self.logger_obj.info(f"page {self.page_number} of {relation} for "
                                 f"@{self.username}@{self.host} already in database")
                return 0

            # Building the INSERT INTO ... VALUES statement's sequence of
            # parenthesized rows to insert.
            value_sql_list = list()
            insertion_count = 0
            for relation_handle in self.relations_list:
                relation_handle.fetch_or_set_handle_id(data_store)
                value_sql_list.append(f"""({profile_handle.handle_id}, '{self.username}', '{self.host}',
                                           {relation_handle.handle_id}, '{relation}', {self.page_number},
                                           '{relation_handle.username}', '{relation_handle.host}')""")

            # Building the complete INSERT INTO ... VALUES statement.
            insert_sql = """INSERT INTO relations (profile_handle_id, profile_username, profile_instance,
                                                   relation_handle_id, relation_type, relation_page_number,
                                                   relation_username, relation_instance)
                                              VALUES
                                                  %s;""" % ', '.join(value_sql_list)
            try:
                data_store.execute(insert_sql)
            except MySQLdb._exceptions.IntegrityError:
                # If inserting the whole page at once raises an IntegrityError,
                # then fall back on inserting each row individually and failing
                # on the specific row that creates the IntegrityError while
                # still saving all other rows.
                insertion_count = 0
                for relation_handle in self.relations_list:
                    relation_handle.fetch_or_set_handle_id(data_store)
                    insert_sql = f"""INSERT INTO relations (profile_handle_id, profile_username, profile_instance,
                                                            relation_handle_id, relation_type, relation_page_number,
                                                            relation_username, relation_instance)
                                                        VALUES
                                                            ({profile_handle.handle_id}, '{self.username}',
                                                            '{self.host}', {relation_handle.handle_id}, '{relation}',
                                                            {self.page_number}, '{relation_handle.username}',
                                                            '{relation_handle.host}')"""
                    try:
                        data_store.execute(insert_sql)
                    except MySQLdb._exceptions.IntegrityError:
                        # Whatever is causing this error, at least the other
                        # rows got saved.
                        self.logger_obj.info(f"got an SQL IntegrityError when inserting {relation_handle.handle} %s "
                                         f"{profile_handle.handle} into table relations" % (
                                             'follower of' if relation == 'followers' else relation))
                    else:
                        insertion_count += 1
            else:
                insertion_count = len(value_sql_list)
            relation_expr = 'followings' if relation == 'following' else relation
            self.logger_obj.info(f"saved {insertion_count} {relation_expr} to the database")
            return insertion_count


class Instance:
    """
    Represents a mastodon instance.
    """
    __slots__ = ('host', 'logger_obj', 'rate_limit_expires', 'attempts', 'malfunctioning', 'suspended', 'unparseable',
                 'robots_txt_file_obj', 'dont_discard_bc_wifi')

    @property
    def rate_limit_expires_isoformat(self):
        return datetime.datetime.fromtimestamp(self.rate_limit_expires).time().isoformat()

    @property
    def status(self):
        return 'malfunctioning' if self.malfunctioning \
                else 'suspended' if self.suspended \
                else 'unparseable' if self.unparseable \
                else 'ingoodstanding'

    # FIXME implement a 4th failure mode, 'blocked'
    def __init__(self, host, logger_obj, malfunctioning=False, suspended=False, unparseable=False, rate_limited=False,
                       x_ratelimit_limit=None, dont_discard_bc_wifi=False, attempts=0):
        """
        Instances a Instance object.

        :param attempts:          The number of unsuccessful attempts the program has
                                  made to contact this instance.
        :type attempts:           int, optional
        :param host:              The hostname of the instance (str).
        :type host:               str
        :param logger_obj:        The Logger object to log events to.
        :type logger_obj:         logging.Logger
        :param malfunctioning:    Whether the instance is malfunctioning; ie.  returning
                                  a 500-class error when contacted.
        :type malfunctioning:     bool, optional
        :param rate_limited:      Whether the program has been rate-limited from
                                  requests with the instance.
        :type rate_limited:       bool, optional
        :param suspended:         Whether the instance is malfunctioning; ie. has been
                                  excluded from contact due to bad behavior of its
                                  admins, mods or users.
        :type suspended:          bool, optional
        :param unparseable:       Whether the instance is unparseable; ie. if the HTML
                                  documents returned by the instance can't be parsed by
                                  any means at the program's disposal.
        :type unparseable:        bool, optional
        :param x_ratelimit_limit: The number of seconds remaining on the rate limit with
                                  the instance.
        :type x_ratelimit_limit:  int or float, optional
        """
        # FIXME should do input checking on args
        self.host = host
        self.logger_obj = logger_obj
        self.attempts = attempts
        self.malfunctioning = malfunctioning
        self.suspended = suspended
        self.unparseable = unparseable
        # The rate_limit_expires instance var is the time in epoch seconds when
        # the ratelimit will expire.
        if rate_limited:
            self.set_rate_limit(x_ratelimit_limit)
        else:
            self.rate_limit_expires = 0.0
        self.dont_discard_bc_wifi = dont_discard_bc_wifi
        if not (malfunctioning or suspended or unparseable):
            self.robots_txt_file_obj = Robots_Txt_File("python-requests", f"https://{self.host}/",
                                                       self.logger_obj, self.dont_discard_bc_wifi)
        else:
            self.robots_txt_file_obj = None

    def set_rate_limit(self, x_ratelimit_limit=None):
        """
        Sets the rate_limit_expires instance variable to the x_ratelimit_limit argument,
        if supplied, otherwise to 300.0.

        :param x_ratelimit_limit: int or float, optional
        :return:                  None
        :rtype:                   types.NoneType
        """
        # If the x_ratelimit_limit argument (which is taken from the
        # X-Ratelimit-Lime header on the HTTP response that had status 429)
        # is supplied, it's used to set the time in epoch seconds when the
        # ratelimit expires.
        if x_ratelimit_limit:
            self.rate_limit_expires = time.time() + float(x_ratelimit_limit)
        # Otherwise the default ratelimit period of 300 seconds is used.
        else:
            self.rate_limit_expires = time.time() + 300.0
        self.logger_obj.info(f"set rate limit on instance '{self.host}': rate limit expires "
                         f"at {self.rate_limit_expires_isoformat}")

    @classmethod
    def fetch_all_instances(self, data_store, logger_obj):
        """
        Loads all lines from the bad_instances table, converts them to Instance objects,
        and returns a dict mapping hostnames to Instance objects.

        :param data_store: The Data_Store object to use to connect to the database.
        :type data_store:  Data_Store
        :param logger_obj: The Logger object to use to log events to.
        :type logger_obj:  logging.Logger
        :return:           A dict mapping hostnames (strs) to Instance objects.
        :rtype:            dict
        """
        instances_dict = dict()
        for row in data_store.execute("SELECT instance, issue FROM bad_instances;"):
            host, issue = row
            instances_dict[host] = Instance(host, logger_obj, malfunctioning=(issue == 'malfunctioning'),
                                                              suspended=(issue == 'suspended'),
                                                              unparseable=(issue == 'unparseable'),
                                            dont_discard_bc_wifi=self.dont_discard_bc_wifi)
        logger_obj.info(f"retrieved {len(instances_dict)} instances from bad_instances table")
        return instances_dict

    @classmethod
    def save_instances(self, instances_dict, data_store, logger_obj):
        """
        Accepts a dict mapping hostnames to Instance objects, and commits every novel
        one to the database. (Class method.)

        :param instances_dict: A dict mapping hostnames (strs) to Instance objects.
        :type instances_dict:  dict
        :param data_store:     The Data_Store object to use to connect to the database.
        :type data_store:      Data_Store
        :param logger_obj:     The Logger object to use to log events to.
        :type logger_obj:      logging.Logger
        :return:               None
        :rtype:                types.NoneType
        """
        # FIXME should detect changed instance state between database and memory
        existing_instances_dict = self.fetch_all_instances(data_store, logger_obj)
        instances_to_insert = dict()
        # instances_to_insert dict is built by (effectively) subtracting
        # existing_instances_dict from instances_dict.
        for host, instance in instances_dict.items():
            if host in existing_instances_dict:
                continue
            instances_to_insert[host] = instances_dict[host]
        if not instances_to_insert:
            return False
        # Building the VALUES (row), (row), (row), etc. portion of the statement.
        values_stmts = tuple(f"('{instance.host}','{instance.issue}')" for instance in instances_to_insert.values())
        insert_sql = "INSERT INTO bad_instances (instance, issue) VALUES %s;" % ', '.join(values_stmts)
        logger_obj.info(f"saving {len(instances_to_insert)} bad instances to bad_instances table")
        data_store.execute(insert_sql)

    def still_rate_limited(self):
        """
        Returns true if the rate limit on this host hasn't expired yet, false if it has.

        :return: True or False
        :rtype:  bool
        """
        return time.time() < self.rate_limit_expires

    def save_instance(self, data_store):
        """
        Saves this instance to the database.

        :param data_store:     The Data_Store object to use to connect to the database.
        :type data_store:      Data_Store
        :return:               False if the instance's malfunctioning, suspended, and
                               unparseable instance vars are all False, or if there was
                               already a row in the bad_instances table with a value for
                               the instance column matching the host instance var, True
                               otherwise.
        :rtype:                bool
        """
        # FIXME should detect changed instance state between database and memory
        # The bad_instances table only holds data on instances with one of these
        # states. An instance that is in good standing can't be saved to it.
        if not self.malfunctioning and not self.suspended and not self.unparseable:
            return False
        else:
            status = 'malfunctioning' if self.malfunctioning else 'suspended' if self.suspended else 'unparseable'
        # Checking if the instance is already present in the bad_instances table.
        result = data_store.execute(f"SELECT instance, issue FROM bad_instances WHERE instance = '{self.host}';")
        if result:
            return False
        self.logger_obj.info(f"saving bad instance {self.host} to bad_instances table")
        data_store.execute(f"INSERT INTO bad_instances (instance, issue) VALUES ('{self.host}', '{status}');")
        return True

#    def fetch_robots_txt(self):
#        try:
#            robots_txt_file_obj = Robots_Txt_File("python-requests", f"https://{self.host}/",
#                                                  self.logger_obj, self.dont_discard_bc_wifi)
#            robots_txt_file_obj.load_and_parse()
#        except Internal_Exception:
#            robots_txt_file_obj = None
#        self.robots_txt_file_obj = robots_txt_file_obj

    def can_fetch(self, query_url):
        if self.malfunctioning or self.suspended or self.unparseable:
            raise Internal_Exception(f"instance {self.host} has status {self.status}; nothing there can be fetched")
        if self.robots_txt_file_obj is None:
            self.robots_txt_file_obj = Robots_Txt_File("python-requests", f"https://{self.host}/",
                                                       self.logger_obj, self.dont_discard_bc_wifi)
        if not self.robots_txt_file_obj.has_been_loaded():
            self.robots_txt_file_obj.load_and_parse()
        return self.robots_txt_file_obj.can_fetch(query_url)


# This class adapted from robotstxt_to_df.py at
# https://github.com/jcchouinard/SEO-Projects/ . Repository has no LICENSE file
# so presuming open availability to reuse and adapt without limitations.
class Robots_Txt_File:
    """
    Represents a robots.txt file, implementing functionality to test whether a
    User-Agent + path combination is allowed or not.
    """
    __slots__ = 'user_agent', 'url', 'robots_dict', 'logger_obj', 'dont_discard_bc_wifi'

    user_agent_re = re.compile("^User-agent: (.*)$", re.I)
    allow_re = re.compile("^Allow: (.*)$", re.I)
    disallow_re = re.compile("^Disallow: (.*)$", re.I)

    @property
    def host(self):
        return urllib.parse.urlparse(self.url).netloc

    #FIXME add crawl-delay support, somehow
    def __init__(self, user_agent, url, logger_obj, dont_discard_bc_wifi=False):
        """
        Instances a Robots_Txt_File object.

        :param user_agent: The User-Agent string to test against the robots.txt
                           constraints. Should be cut off at the first space or slash.
        :type user_agent:  str
        :param url:        The URL of the site to retrieve the robots.txt file from.
        :type url:         str
        """
        self.user_agent = user_agent
        self.url = url
        self.logger_obj = logger_obj
        self.robots_dict = None
        self.dont_discard_bc_wifi = dont_discard_bc_wifi

    def load_and_parse(self):
        """
        Loads the indicated robots.txt file and parses it, such that after this call the
        can_fetch() method will be operational.

        :return: None
        :rtype:  types.NoneType
        """
        robots_txt_url = self._get_robots_txt_url()
        robots_txt_content = self._read_robots_txt(robots_txt_url)
        if robots_txt_content:
            self.robots_dict = self._parse_robots_txt(robots_txt_content)
        else:
            self.robots_dict = dict()

    def has_been_loaded(self):
        """
        Predicate that returns True if the robots.txt file has been fetched and parsed,
        False otherwise.

        :return: True or False
        :rtype:  bool
        """
        return isinstance(self.robots_dict, dict)

    def can_fetch(self, query_url):
        """
        Check the supplied url against the parsed robots.txt data for the stored
        User-Agent to see if it is allowed or disallowed. Returns True if it's allowed,
        False otherwise.

        :return: True or False
        :rtype:  bool
        """
        if self.robots_dict is None:
            raise Internal_Exception(f"{self._get_robots_txt_url()} hasn't been loaded; can't judge whether "
                                     f"{query_url} can be fetched")
        # There wasn't a robots.txt or an error occurred while attempting to
        # read it.
        elif len(self.robots_dict) == 0:
            return True

        # If the robots.txt file doesn't specify behavior for User-Agent: *, and
        # doesn't specify behavior for this exact User-Agent, then the program
        # can fetch anything it likes.

        if self.user_agent not in self.robots_dict and '*' not in self.robots_dict:
            return True
        # Pick the robots.txt parsed block that matches the program's User-Agent.
        elif self.user_agent in self.robots_dict:
            robots_block = self.robots_dict[self.user_agent]
        else:  # '*' in self.robots_dict:
            robots_block = self.robots_dict['*']

        # Extract the path from the query URL.
        query_path = urllib.parse.urlparse(query_url).path

        matching_allow_pats = set()
        matching_disallow_pats = set()
        for pattern in robots_block["Disallow"]:
            if self._glob_match(pattern, query_path):
                matching_disallow_pats.add(pattern)

        for pattern in robots_block["Allow"]:
            if self._glob_match(pattern, query_path):
                matching_allow_pats.add(pattern)

        # If the pattern matches both Allow and Disallow terms, the longest
        # pattern wins. A pattern ending in a wildcard is considered longest.
        if matching_allow_pats and matching_disallow_pats:
            matching_allow_pats_end_w_wc = {pattern for pattern in matching_allow_pats if pattern.endswith('*')}
            matching_disallow_pats_end_w_wc = {pattern for pattern in matching_disallow_pats if pattern.endswith('*')}

            # If there's an Allow pattern that ends with a wildcard but no
            # Disallow pattern that does, it's allowed.
            if matching_allow_pats_end_w_wc and not matching_disallow_pats_end_w_wc:
                return True
            # Otoh if there's a Disllow pattern that ends with a wildcard but no
            # Allow pattern that does, it's disallowed.
            elif not matching_allow_pats_end_w_wc and matching_disallow_pats_end_w_wc:
                return False
            # If there's both Allow and Disallow patterns ending in wildcards
            # that match, the longest one of *those* wins. (This is ad hoc, also
            # this is a tiny corner case but it needs to be handled.
            elif matching_allow_pats_end_w_wc and matching_disallow_pats_end_w_wc:
                return max(map(len, matching_allow_pats_end_w_wc)) >= max(map(len, matching_disallow_pats_end_w_wc))
            # No matching patterns end in wildcards so it's allowed if the
            # longest matching pattern is an Allow one.
            else:
                return max(map(len, matching_allow_pats)) >= max(map(len, matching_disallow_pats))
        # If any Disallow pattern matched, then fetching the URL is not permitted.
        elif len(matching_disallow_pats):
            return False
        # Otherwise, the path is not explicitly disallowed, so fetching it is
        # permitted.
        else:
            return True

    @classmethod
    def _glob_match(self, pattern, path):
        if '*' not in pattern and '$' not in pattern:
            return path.startswith(pattern)
        else:
            pattern = pattern.replace('*', '[^/]*')
            return bool(re.match(pattern, path))

    def _get_robots_txt_url(self):
        # Derive the URL for the robots.txt file from the website URL instance var.
        domain_url = '{uri.scheme}://{uri.netloc}'.format(uri=urllib.parse.urlparse(self.url))
        robots_txt_url = domain_url + '/robots.txt'
        return robots_txt_url

    def _read_robots_txt(self, robots_txt_url):
        # Retrieve the robots.txt file, extract the content and return it.
        try:
            self.logger_obj.info(f"retrieving robots.txt for {self.host}")
            response = requests.get(robots_txt_url)
        except requests.exceptions.SSLError:
            self.logger_obj.info(f"retrieving https://{self.host}/robots.txt failed: SSL error ")
            return ''
        except requests.exceptions.TooManyRedirects:
            self.logger_obj.info(f"retrieving https://{self.host}/robots.txt failed: too many redirects")
            return ''
        except requests.exceptions.ConnectTimeout:
            self.logger_obj.info(f"retrieving https://{self.host}/robots.txt failed: connection timeout")
            return ''
        except requests.exceptions.ReadTimeout:
            self.logger_obj.info(f"retrieving https://{self.host}/robots.txt failed: read timeout")
            return ''
        except requests.exceptions.ConnectionError as exception:
            if self.dont_discard_bc_wifi:
                self.logger_obj.info(f"retrieving https://{self.host}/robots.txt failed: connection error; "
                                     "but the wifi might've gone out; not treating this as a valid robots.txt "
                                     "retrieval")
                raise exception
            else:
                self.logger_obj.info(f"retrieving https://{self.host}/robots.txt failed: connection error")
                return ''
        except IOError:
            self.logger_obj.info(f"retrieving https://{self.host}/robots.txt failed: python IOError")
            return ''
        if response.status_code != 200:
            self.logger_obj.info(f"retrieving https://{self.host}/robots.txt failed: "
                                 f"status code {response.status_code}")
            return ''
        robots_txt_content = response.content.decode('utf-8')
        return robots_txt_content

    def _parse_robots_txt(self, robots_txt_content):
        self.logger_obj.info(f"parsing robots.txt for {self.host}")
        index = 0
        robots_dict = dict()
        robots_lines = robots_txt_content.split("\n")

        if not len(robots_lines):
            self.logger_obj.warn(f"robots.txt for {self.host} is zero-length")
            return robots_dict

        # Page past the top of the robots.txt file until the first User-agent
        # line.
        while index < len(robots_lines) and not self.user_agent_re.match(robots_lines[index]):
            index += 1

        while index < len(robots_lines):
            block_dict = {"Allow": [], "Disallow": []}
            user_agents = set()
            # A block in a robots.txt file may begin with more than one
            # User-agent line; in that case all the Allow & Disallow patterns
            # that follow apply to every user-agent listed in the series of
            # User-agent lines.
            while ua_match := (index < len(robots_lines) and self.user_agent_re.match(robots_lines[index])):
                user_agents.add(ua_match.group(1))
                index += 1
            # index var now points to the 1st non-UA line, or in the case of a
            # badly-formed robots.txt file it may be equal to the length of the
            # line list.
            while index < len(robots_lines) and not self.user_agent_re.match(robots_lines[index]):
                if allow_match := self.allow_re.match(robots_lines[index]):
                    block_dict["Allow"].append(allow_match.group(1))
                elif disallow_match := self.disallow_re.match(robots_lines[index]):
                    block_dict["Disallow"].append(disallow_match.group(1))
                index += 1
            # index var now points to the 1st UA line (ie. it points to the
            # beginning of the next UA statement), or its equal to the length of
            # the lines list.

            # For every user agent that was found, save the same dict of Allow
            # and Disallow patterns to the robots_dict with the UA as a key.
            for user_agent in user_agents:
                robots_dict[user_agent] = block_dict

        self.logger_obj.info(f"robots.txt for {self.host} parsed")
        return robots_dict
