#!/usr/bin/python3

import bs4
import datetime
import html2text
import logging
import MySQLdb
import re
import requests
import selenium
import selenium.common.exceptions
import selenium.webdriver
import selenium.webdriver.common.by
import selenium.webdriver.firefox.options
import time
import urllib
import validators

from arachnea.outcomes import InternalException, SuccessfulRequest, FailedRequest, NoOpRequest, PROFILE, RELATIONS


# Used to set how long selenium.webdriver waits between directing the puppet
# firefox instance to scroll the page.
SCROLL_PAUSE_TIME = 1.0

# The connection timeout used by requests.get() when retrieving pages from a
# mastodon instance.
REQ_TIMEOUT = 5.0


class Page:
    """
    Represents a single page; handles retrieving the page and the ensuing errors
    itself.
    """
    __slots__ = ('handle_obj', 'username', 'instance', 'logger_obj', 'instance_obj', 'url', 'document', 'is_dynamic',
                 'loaded', 'is_profile', 'is_following', 'is_followers', 'page_number', 'profile_no_public_posts',
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

    def __init__(self, handle_obj, url, logger_obj, instance_obj, save_profiles=False, save_relations=False,
                 dont_discard_bc_wifi=False):
        """
        Instances the Page object.

        :param handle_obj:     The handle object of the profile the page belongs to.
        :type handle_obj:      Handle
        :param url:            The URL of the page.
        :type url:             str
        :param logger_obj:     The Logger object to log events to.
        :type logger_obj:      logging.Logger
        :param instance_obj:   The Instance object associated with the instance this Page's
                               url is located at.
        :type instance_obj:    Instance
        :param save_profiles:  If the program is in a profiles-saving mode.
        :type save_profiles:   bool
        :param save_relations: If the program is in a relations-saving mode.
        :type save_relations:  bool
        """
        # Setting instance vars from the args and their attributes.
        self.handle_obj = handle_obj
        self.url = url
        self.logger_obj = logger_obj
        self.instance_obj = instance_obj
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.username = handle_obj.username
        self.instance = handle_obj.instance
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
            raise InternalException("unable to discern profile, following or follower page "
                                     f"from parsing URL {self.url} ")

    def requests_fetch(self):
        """
        Tries to fetch self.url using requests.get().

        :return: Returns an object of a RequestOutcome subclass; if request was
                 successful, returns a SuccessfulRequest object; otherwise, returns a
                 FailedRequest object.
        :rtype:  RequestOutcome
        """
        try:
            can_fetch = self.instance_obj.can_fetch(self.url)
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
            return FailedRequest(self.instance, robots_txt_disallowed=True, page_obj=self)
        # A big try/except statement to handle a variety of different Exceptions
        # differently.
        try:
            http_response = requests.get(self.url, timeout=REQ_TIMEOUT)
        except requests.exceptions.SSLError:
            # An error in the SSL handshake, or an expired cert.
            self.loaded = False
            return FailedRequest(self.instance, malfunctioning=True, ssl_error=True, page_obj=self)
        except requests.exceptions.TooManyRedirects:
            # The instance put the program's client through too many redirects.
            self.loaded = False
            return FailedRequest(self.instance, malfunctioning=True, too_many_redirects=True, page_obj=self)
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
            # The connection timed out.
            self.loaded = False
            return FailedRequest(self.instance, malfunctioning=True, timeout=True, page_obj=self)
        except (requests.exceptions.ConnectionError, IOError):
            # There was a generic connection error.
            self.loaded = False
            return FailedRequest(self.instance, malfunctioning=True, connection_error=True, page_obj=self)

        return self._handle_status_code(http_response)

    def _handle_status_code(self, http_response):
        # There's a requests.models.Response object, but now the program needs
        # to handle all the non-200 status codes.
        match http_response.status_code:
            case 429:
                # The program has been rate-limited.
                if http_response.headers['x-ratelimit-limit']:
                    # If there's an X-Ratelimit-Limit header, the program captures
                    # its int value and saves that in the Failed_Request object
                    # bc that's how many seconds the program needs to wait before
                    # trying again.
                    self.loaded = False
                    return FailedRequest(self.instance, status_code=http_response.status_code, ratelimited=True,
                                         x_ratelimit_limit=float(http_response.headers['x-ratelimit-limit']),
                                         page_obj=self)
                else:
                    self.loaded = False
                    return FailedRequest(self.instance, status_code=http_response.status_code, ratelimited=True,
                                         page_obj=self)
            case 401 | 400 | 403 | 406 | 418 | 500 | 501 | 502 | 503 | 504 | 529:
                # The instance emitted a status code that indicates it's not
                # handling requests correctly. The program classes it as malfunctioning.
                self.loaded = False
                return FailedRequest(self.instance, status_code=http_response.status_code, malfunctioning=True,
                                     page_obj=self)
            case 404 | 410:
                # The status code is 404 Not Found or 410 Gone. The user has been deleted.
                self.loaded = False
                return FailedRequest(self.instance, status_code=http_response.status_code, user_deleted=True,
                                     page_obj=self)
            case 200:
                # An ostensibly valid page was returned. Parse it with BS and see if
                # it contains the data the program's looking for.
                self.document = bs4.BeautifulSoup(markup=http_response.text, features='lxml')
                if self.document.find_all('noscript'):
                    # The page has a noscript tag, which means it's dynamic. The
                    # caller will need to try again with webdriver.
                    self.loaded = False
                    self.is_dynamic = True
                    return FailedRequest(self.instance, is_dynamic=True, page_obj=self)
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
                        return NoOpRequest(self.instance, page_obj=self, is_dynamic=False)
            case status_code:
                # Any other status code, one the program wasn't expecting.
                # Saving it to the Failed_Request object for the caller to
                # handle.
                self.loaded = False
                return FailedRequest(self.instance, status_code=status_code, page_obj=self)

    def webdriver_fetch(self):
        """
        Tries to fetch self.url using selenium.webdriver.firefox.

        :return: Returns an object of a RequestOutcome subclass; if request was
                 successful, returns a SuccessfulRequest object; otherwise, returns a
                 FailedRequest object.
        :rtype:  RequestOutcome
        """
        # FIXME implement a Successful_Request object to normalize the return
        # values of this and subordinate methods.
        if not self.instance_obj.can_fetch(self.url):
            # The file can't be fetched because the site has a robots.txt and
            # the robots.txt disallows it.
            self.loaded = False
            return FailedRequest(self.instance, robots_txt_disallowed=True, page_obj=self)

        browser = None

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
                return NoOpRequest(self.instance, page_obj=self, is_dynamic=True)
        except (selenium.common.exceptions.NoSuchElementException, selenium.common.exceptions.WebDriverException):
            # selenium.webdriver failed fsr. There's no diagnosing this sort of
            # thing, so a Failed_Request is returned.
            self.logger_obj.info("webdriver experienced an internal error, failing")
            return FailedRequest(self.instance, webdriver_error=True, page_obj=self)
        finally:
            self.logger_obj.info("closing out webdriver Firefox instance")
            if browser is not None:
                browser.quit()
            del browser

    def parse_profile_page(self):
        """
        Parses the loaded page in the self.document attribute, treating it as a
        profile page. Rules it out if it's not a usable page, otherwise extracts
        the profile bio and save it.

        :return: Returns an object of a RequestOutcome subclass; if the page is ruled
                 out for some reason or the parsing failed, a FailedRequest object is
                 oreturned; therwise a SuccessfulRequest object is returned.
        :rtype:  RequestOutcome
        """
        # FIXME should draw its post age threshold from a global constant
        self.logger_obj.info(f"parsing profile at {self.url}")
        # FIXME correct time tag parsing to reflect the latest format in use
#       time_tags = self.document.find_all('time', {'class': 'time-ago'})
#        if len(time_tags) == 0:
#            self.profile_no_public_posts = True
#            return Failed_Request(self.instance, no_public_posts=True)
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
#                return Failed_Request(self.instance, posts_too_old=True)

        # Detects if this is a forwarding page.
        forwarding_tag = self.document.find('div', {'class': self.moved_handle_class_re})
        if forwarding_tag:
            forwarding_match = self.forwarding_handle_re.match(html2text.html2text(forwarding_tag.prettify()))
            # Tries to detect and save the forwarding handle but it doesn't
            # always parse.
            if forwarding_match is not None:
                handle_at, handle_rest = forwarding_match.groups()
                forwarding_handle = handle_at + handle_rest
                return FailedRequest(self.instance, forwarding_address=forwarding_handle, page_obj=self)
            else:
                return FailedRequest(self.instance, forwarding_address=True, page_obj=self)

        # Trying 2 known classes used to demarcate the bio by different versions
        # of Mastodon.
        profile_div_tag = self.document.find('div', {'class': 'public-account-bio'})
        if profile_div_tag is None:
            profile_div_tag = self.document.find('div', {'class': 'account__header__content'})

        # If the profile div couldn't be found, return a Failed_Request.
        if profile_div_tag is None:
            self.unparseable = True
            return FailedRequest(self.instance, unparseable=True, page_obj=self)

        # If this is a dynamic page, clear out some known clutter from the
        # profile bio div.
        if self.is_dynamic:
            unwanted_masto_link_divs = profile_div_tag.find_all('div', {'class': 'account__header__extra__links'})
            if len(unwanted_masto_link_divs):
                unwanted_masto_link_divs[0].replaceWith('')

        # Convert the bio to markdown and save it. The program doesn't need its
        # HTML. Return the length of the bio.
        self.profile_bio_text = html2text.html2text(str(profile_div_tag))
        return SuccessfulRequest(self.instance, retrieved_len=len(self.profile_bio_text), retrieved_type=PROFILE,
                                 page_obj=self)

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
        :return:        Returns an object of a RequestOutcome subclass; if the parsing
                        process failed for any reason, a FailedRequest object is
                        returned; otherwise a SuccessfulRequest object is returned.
        :rtype:         RequestOutcome
        """
        self.logger_obj.info(f"parsing {self.relation_type} at {self.url}")

        # This is a dynamic page, so the program parses the dynamic form of the
        # following/followers page, which takes quite a lot of work.
        if self.is_dynamic:
            self.relations_list.extend(self._parse_relations_from_dynamic_page(browser))
        # This is a static page, so the program does the static parsing, which
        # is straightforward.
        else:
            self.relations_list.extend(self._parse_relations_from_static_page())

        return SuccessfulRequest(self.instance, retrieved_len=len(self.relations_list), retrieved_type=RELATIONS,
                                 page_obj=self)


    def _parse_relations_from_static_page(self, browser):
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
            if relation_username == self.username and relation_instance == self.instance:
                continue
            self.relations_list.append(Handle(username=relation_username, instance=relation_instance))

    def _parse_relations_from_dynamic_page(self, browser):
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
            total_article_tags_count = len(article_tag_text_by_data_id)

            # Beginning the process of scrolling around the document.
            self.logger_obj.info(f"using selenium.webdriver to page over dynamic {self.relation_type} page forcing "
                        f"<article> tags to load; found {len(article_tag_text_by_data_id)} <article> tags")
            pass_counter = 1

            # So long as there's any article data-ids in the
            # article_tag_text_by_data_id dict that don't have text set, keep
            # scrolling around the document trying to find them all.
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
            return FailedRequest(self.instance, webdriver_error=True, page_obj=self)

        # Converting the dict of article tags' texts to a list of
        # following/followers handles.
        relations_list = list()
        for handle_str in article_tag_text_by_data_id.values():
            if "\n" in handle_str:
                handle_str = handle_str.split("\n")[1]
            if handle_str.count('@') == 1:
                username = handle_str.strip('@')
                instance = self.instance
            elif handle_str.count('@') == 2:
                _, username, instance = handle_str.split('@')
            else:
                continue
            handle_obj = Handle(username=username, instance=instance)
            relations_list.append(handle_obj)

        return relations_list

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
            return [f"https://{self.instance}/@{self.username}/following",
                    f"https://{self.instance}/@{self.username}/followers"]
        else:
            return [f"https://{self.instance}/users/{self.username}/following",
                    f"https://{self.instance}/users/{self.username}/followers"]

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
                base_url = 'https://' + self.instance + base_url
            return [f"{base_url}{page_no}" for page_no in range(2, highest_page_no + 1)]
        else:
            return []

    def save_page(self, data_store_obj):
        """
        Saves the page's content to the data store. If this is a profile page, saves the
        profile. If this is a relations page, save the collected following/followers
        handles.

        :param data_store_obj: The Data_Store object to use to contact the database.
        :type data_store_obj:  Data_Store
        :return:               The number of rows affected by the query.
        :rtype:                int
        """
        if self.is_profile:
            return self._save_profile_page(data_store_obj)
        else:
            return self._save_relations_page(data_store_obj)

    def _save_profile_page(self, data_store_obj):
        # Saving a profile to the profiles table.
        #
        # If there isn't a handle_id on the object, use
        # Handle.fetch_or_set_handle_id() to get one. The auto-incrementing
        # primary key of the handles table is used to identify rows with the
        # same username and instance in other tables.
        profile_bio_text = self.profile_bio_text.replace("'", "\\'")
        handle_obj = self.handle_obj
        if not handle_obj.handle_id:
            handle_obj.fetch_or_set_handle_id(data_store_obj)

        # Checking if this profile already exists in the profiles table and
        # already has its profile saved.
        select_sql = f"""SELECT profile_handle_id, profile_bio_markdown FROM profiles
                         WHERE profile_handle_id = {handle_obj.handle_id};"""
        rows = data_store_obj.execute(select_sql)
        if rows:
            ((handle_id, profile_bio_markdown),) = rows
            if profile_bio_markdown:
                return 0
            elif profile_bio_text:
                # If by some chance this handle_id already has a row in the
                # profiles table, but its profile_bio_markdown is null, and the
                # bio text the program is going to save here is *not* null,
                # then use an UPDATE statement to set the profile bio.
                update_sql = f"""UPDATE profiles SET profile_bio_markdown = '{profile_bio_text}'
                                 WHERE profile_handle_id = {handle_obj.handle_id};"""
                data_store_obj.execute(update_sql)
                return 1
        else:
            # Otherwise use an INSERT statement like usual.
            insert_sql = f"""INSERT INTO profiles (profile_handle_id, username, instance,
                                                   considered, profile_bio_markdown)
                                              VALUES
                                                  ({handle_obj.handle_id}, '{handle_obj.username}',
                                                  '{handle_obj.instance}', 0, '{profile_bio_text}');"""
            data_store_obj.execute(insert_sql)
            return 1

    def _save_relations_page(self, data_store_obj):
        # Saving following/followers to the relations table.
        if not len(self.relations_list):
            return 0
        relation = 'following' if self.is_following else 'followers'
        profile_handle_obj = self.handle_obj
        # Setting the handle_id attribute if it's missing.
        profile_handle_obj.fetch_or_set_handle_id(data_store_obj)

        # Checking if this page has already been saved to the relations table.
        select_sql = f"""SELECT DISTINCT profile_handle_id FROM relations
                         WHERE profile_handle_id = {profile_handle_obj.handle_id} AND relation_type = '{relation}'
                               AND relation_page_number = {self.page_number};"""
        rows = data_store_obj.execute(select_sql)
        if rows:
            # If so, return 0.
            self.logger_obj.info(f"page {self.page_number} of {relation} for "
                             f"@{self.username}@{self.instance} already in database")
            return 0

        # Building the INSERT INTO ... VALUES statement's sequence of
        # parenthesized rows to insert.
        value_sql_list = list()
        for relation_handle_obj in self.relations_list:
            relation_handle_obj.fetch_or_set_handle_id(data_store_obj)
            value_sql_list.append(f"""({profile_handle_obj.handle_id}, '{self.username}', '{self.instance}',
                                       {relation_handle_obj.handle_id}, '{relation}', {self.page_number},
                                       '{relation_handle_obj.username}', '{relation_handle_obj.instance}')""")

        # Building the complete INSERT INTO ... VALUES statement.
        insert_sql = """INSERT INTO relations (profile_handle_id, profile_username, profile_instance,
                                               relation_handle_id, relation_type, relation_page_number,
                                               relation_username, relation_instance)
                                          VALUES
                                              %s;""" % ', '.join(value_sql_list)
        try:
            data_store_obj.execute(insert_sql)
        except MySQLdb.IntegrityError:
            # If inserting the whole page at once raises an IntegrityError,
            # then fall back on inserting each row individually and failing
            # on the specific row that creates the IntegrityError while
            # still saving all other rows.
            insertion_count = 0
            for relation_handle_obj in self.relations_list:
                relation_handle_obj.fetch_or_set_handle_id(data_store_obj)
                insert_sql = f"""INSERT INTO relations (profile_handle_id, profile_username, profile_instance,
                                                        relation_handle_id, relation_type, relation_page_number,
                                                        relation_username, relation_instance)
                                                    VALUES
                                                        ({profile_handle_obj.handle_id}, '{self.username}',
                                                        '{self.instance}', {relation_handle_obj.handle_id},
                                                        '{relation}', {self.page_number},
                                                        '{relation_handle_obj.username}',
                                                        '{relation_handle_obj.instance}')"""
                try:
                    data_store_obj.execute(insert_sql)
                except MySQLdb.IntegrityError:
                    # Whatever is causing this error, at least the other
                    # rows got saved.
                    self.logger_obj.info(("got an SQL IntegrityError when inserting "
                                          "{relation_handle_in_at_form} {relation_type} "
                                          "{profile_handle_in_at_form} into table relations").format(
                                            relation_handle_in_at_form=relation_handle_obj.handle_in_at_form,
                                            relation_type=('follower of' if relation == 'followers' else relation),
                                            profile_handle_in_at_form=profile_handle_obj.handle_in_at_form))
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
    __slots__ = ('instance_host', 'logger_obj', 'rate_limit_expires', 'attempts', 'malfunctioning', 'suspended',
                 'unparseable', 'robots_txt_file_obj', 'dont_discard_bc_wifi')

    @property
    def rate_limit_expires_isoformat(self):
        return datetime.datetime.fromtimestamp(self.rate_limit_expires).time().isoformat()

    @property
    def status(self):
        return 'malfunctioning' if self.malfunctioning \
                else 'suspended' if self.suspended \
                else 'unparseable' if self.unparseable \
                else 'ingoodstanding'

    def __init__(self, instance_host, logger_obj, malfunctioning=False, suspended=False, unparseable=False,
                 rate_limited=False, x_ratelimit_limit=None, dont_discard_bc_wifi=False, attempts=0):
        """
        Instances a Instance object.

        :param attempts:          The number of unsuccessful attempts the program has
                                  made to contact this instance.
        :type attempts:           int, optional
        :param instance_host:     The hostname of the instance (str).
        :type instance_host:      str
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
        if not isinstance(logger_obj, logging.Logger):
            raise InternalException(f"logger_obj argument is not an instance of logger.Logger")
        elif not validators.domain(instance_host):
            raise InternalException(f"instance_host argument '{instance_host}' not a valid instance_host: must be a "
                                    "str consisting of letters, numbers, periods, underscores, and dashes ending in a "
                                    "period followed by letters")
        self.instance_host = instance_host
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
            self.robots_txt_file_obj = RobotsTxt("python-requests", f"https://{self.instance_host}/",
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
        self.logger_obj.info(f"set rate limit on instance '{self.instance_host}': rate limit expires "
                         f"at {self.rate_limit_expires_isoformat}")

    @classmethod
    def fetch_all_instances(cls, data_store_obj, logger_obj):
        """
        Loads all lines from the bad_instances table, converts them to Instance objects,
        and returns a dict mapping hostnames to Instance objects.

        :param data_store_obj: The Data_Store object to use to connect to the database.
        :type data_store_obj:  Data_Store
        :param logger_obj:     The Logger object to use to log events to.
        :type logger_obj:      logging.Logger
        :return:               A dict mapping hostnames (strs) to Instance objects.
        :rtype:                dict
        """
        instances_dict = dict()
        for row in data_store_obj.execute("SELECT instance, issue FROM bad_instances;"):
            instance_host, issue = row
            instances_dict[instance_host] = Instance(instance_host, logger_obj,
                                                     malfunctioning=(issue == 'malfunctioning'),
                                                     suspended=(issue == 'suspended'),
                                                     unparseable=(issue == 'unparseable'),
                                                     dont_discard_bc_wifi=cls.dont_discard_bc_wifi)
        logger_obj.info(f"retrieved {len(instances_dict)} instances from bad_instances table")
        return instances_dict

    @classmethod
    def save_instances(cls, instances_dict, data_store_obj, logger_obj):
        """
        Accepts a dict mapping hostnames to Instance objects, and commits every novel
        one to the database. (Class method.)

        :param instances_dict: A dict mapping hostnames (strs) to Instance objects.
        :type instances_dict:  dict
        :param data_store_obj: The Data_Store object to use to connect to the database.
        :type data_store_obj:  Data_Store
        :param logger_obj:     The Logger object to use to log events to.
        :type logger_obj:      logging.Logger
        :return:               None
        :rtype:                types.NoneType
        """
        existing_instances_dict = cls.fetch_all_instances(data_store_obj, logger_obj)
        instances_to_insert = dict()
        # instances_to_insert dict is built by (effectively) subtracting
        # existing_instances_dict from instances_dict.
        for instance_host, instance_obj in instances_dict.items():
            if instance_host in existing_instances_dict:
                continue
            instances_to_insert[instance_host] = instances_dict[instance_host]
        if not instances_to_insert:
            return False
        # Building the VALUES (row), (row), (row), etc. portion of the statement.
        values_stmts = tuple(f"('{instance.instance_obj}','{instance.issue}')"
                             for instance in instances_to_insert.values())
        insert_sql = "INSERT INTO bad_instances (instance_obj, issue) VALUES %s;" % ', '.join(values_stmts)
        logger_obj.info(f"saving {len(instances_to_insert)} bad instances to bad_instances table")
        data_store_obj.execute(insert_sql)

    def still_rate_limited(self):
        """
        Returns True if the rate limit on this instance hasn't expired yet, False if it has.

        :return: True or False
        :rtype:  bool
        """
        return time.time() < self.rate_limit_expires

    def save_instance(self, data_store_obj):
        """
        Saves this instance to the database.

        :param data_store_obj: The Data_Store object to use to connect to the database.
        :type data_store_obj:  Data_Store
        :return:               False if the instance's malfunctioning, suspended, and
                               unparseable instance vars are all False, or if there was
                               already a row in the bad_instances table with a value for
                               the instance column matching the instance attribute, True
                               otherwise.
        :rtype:                bool
        """
        # The bad_instances table only holds data on instances with one of these
        # states. An instance that is in good standing can't be saved to it.
        if not self.malfunctioning and not self.suspended and not self.unparseable:
            return False
        else:
            status = 'malfunctioning' if self.malfunctioning else 'suspended' if self.suspended else 'unparseable'
        # Checking if the instance is already present in the bad_instances table.
        rows = data_store_obj.execute(f"""SELECT instance, issue FROM bad_instances
                                            WHERE instance = '{self.instance_host}';""")
        if len(rows):
            return False
        self.logger_obj.info(f"saving bad instance {self.instance_host} to bad_instances table")
        data_store_obj.execute(f"""INSERT INTO bad_instances (instance, issue)
                                   VALUES ('{self.instance_host}', '{status}');""")
        return True

#    def fetch_robots_txt(self):
#        try:
#            robots_txt_file_obj = Robots_Txt_File("python-requests", f"https://{self.instance}/",
#                                                  self.logger_obj, self.dont_discard_bc_wifi)
#            robots_txt_file_obj.load_and_parse()
#        except Internal_Exception:
#            robots_txt_file_obj = None
#        self.robots_txt_file_obj = robots_txt_file_obj

    def can_fetch(self, query_url):
        """
        Returns True if the given URL is fetchable from the instance according to its
        robots.txt, False if it's not.

        :param query_url: An absolute URL including the instance, or a relative URL
                          based at its document root.
        :type query_url:  str
        :return:          True if the URL may be fetched, False if not.
        :rtype:           bool
        """
        if self.malfunctioning or self.suspended or self.unparseable:
            raise InternalException(f"instance {self.instance_host} has status {self.status};"
                                     f" nothing there can be fetched")
        if self.robots_txt_file_obj is None:
            self.robots_txt_file_obj = RobotsTxt("python-requests", f"https://{self.instance_host}/",
                                                 self.logger_obj, self.dont_discard_bc_wifi)
        if not self.robots_txt_file_obj.has_been_loaded():
            self.robots_txt_file_obj.load_and_parse()
        return self.robots_txt_file_obj.can_fetch(query_url)


class Handle:
    """
    Represents a mastodon handle.
    """
    __slots__ = 'handle_id', 'username', 'instance'

    handle_re = re.compile(r"^@[A-Za-zÀ-ÿ0-9_.-]+@[A-Za-z0-9.-]+\.[A-Za-z]+$")
    username_re = re.compile(r"^[A-Za-zÀ-ÿ0-9_.-]+$")
    instance_re = re.compile(r"^[A-Za-zÀ-ÿ0-9_.-]+\.[A-Za-z]+$")

    @property
    def handle_in_at_form(self):
        """
        Returns the handle in @username@instance form.
        """
        return f"@{self.username}@{self.instance}"

    @property
    def profile_url(self):
        """
        Returns the handle in https://instance/@username form.
        """
        return f"https://{self.instance}/@{self.username}"

    def __init__(self, handle_in_at_form='', handle_id=None, username='', instance=''):
        """
        Instances the Handle object.

        :param handle_id: The primary key of the row in the MySQL handles table that
                          furnished the data this Handle object is instanced from, if
                          any.
        :type handle_id:  int, optional
        :param username:  The part of the handle that represents the indicated user's
                          username.
        :type username:   str
        :param instance:  The part of the handle that represents the indicated user's
                          instance.
        :type instance:   str
        """
        if handle_in_at_form:
            if username or instance:
                match (bool(username), bool(instance)):
                    case (True, True):
                        raise InternalException("Handle object cannot be initialized from both a handle in @ form and "
                                                "also values for username and instance kwargs.")
                    case (True, False):
                        raise InternalException("Handle object cannot be initialized from both a handle in @ form and "
                                                "also a value for the username kwarg.")
                    case (False, True):
                        raise InternalException("Handle object cannot be initialized from both a handle in @ form and "
                                                "also a value for the instance kwarg.")
            self.username, self.instance = handle_in_at_form.strip('@').rsplit('@')
            self.handle_id = handle_id
        else:
            if handle_id is not None and not isinstance(handle_id, int):
                raise InternalException(f"handle_id argument must be an int (got '{handle_id}'")
            elif not isinstance(username, str) or not self.username_re.match(username):
                raise InternalException(f"username argument '{username}' not a valid username: must be a str "
                                         "consisting of letters, numbers, periods, underscores, and dashes")
            elif not instance or not validators.domain(instance):
                raise InternalException(f"instance argument '{instance}' not a valid instance: must be a str "
                                         "consisting of letters, numbers, periods, underscores, and dashes ending in a "
                                         "period followed by letters")
            self.handle_id = handle_id
            self.username = username
            self.instance = instance

    @classmethod
    def validate_handle(cls, handle):
        """
        Validates whether the handle argument matches the pattern for a valid mastodon
        handle. Returns True if so, False otherwise.

        :param handle: The string to validate whether it matches the pattern for a
                       mastodon handle or not.
        :type handle:  str
        :return:       True if the handle is a valid mastodon handle, False otherwise.
        :rtype:        bool
        """
        return bool(cls.handle_re.match(handle))

    def fetch_or_set_handle_id(self, data_store_obj):
        """
        If the Handle object was instanced from another source than a row in the
        MySQL handles table, set the handle_id from the table, inserting the data if
        necessary.

        :param data_store_obj: The Data_Store object to use to access the handles table.
        :type data_store_obj:  Data_Store
        :return:               True if the handle_id value was newly set; False if the
                               handle_id instance variable was already set.
        :rtype:                bool
        """
        # If the handle_id is already set, do nothing & return failure.
        if self.handle_id:
            return False

        # Fetch the extant handle_id value from the table if it so happens this
        # username/instance part is already in the handles table.
        fetch_handle_id_sql = f"""SELECT handle_id FROM handles WHERE username = '{self.username}'
                                                                AND instance = '{self.instance}';"""
        rows = data_store_obj.execute(fetch_handle_id_sql)

        if not len(rows):
            self.save_handle(data_store_obj)

            rows = data_store_obj.execute(fetch_handle_id_sql)

        ((handle_id,),) = rows
        self.handle_id = handle_id
        return True

    def save_handle(self, data_store_obj):
        """
        Saves the handle to the handles table of the database. Returns False if this
        username and instance combination was already present in the handles table, True
        otherwise.

        :param data_store_obj: The Data_Store object to use to access the handles table.
        :type data_store_obj:  Data_Store
        :return:           False if the handle was already in the database, True
                           otherwise.
        :rtype:            bool
        """
        fetch_handle_id_sql = f"""SELECT handle_id FROM handles WHERE username = '{self.username}'
                                                                AND instance = '{self.instance}';"""
        rows = data_store_obj.execute(fetch_handle_id_sql)
        if len(rows):
            return False

        data_store_obj.execute(f"""INSERT INTO handles (username, instance)
                                   VALUES ('{self.username}', '{self.instance}');""")
        return True


class DeletedUser(Handle):
    """
    Represents a user who has been deleted from their instance. Inherits from Handle.
    """
    __slots__ = 'logger_obj',

    @classmethod
    def fetch_all_deleted_users(cls, data_store_obj):
        """
        Retrieves all records from the deleted_users table and returns them in a dict.

        :param data_store_obj: The Data_Store object to use to contact the database.
        :type data_store_obj:  Data_Store
        :return:               A dict mapping 2-tuples of (username, instance) to
                               Deleted_User objects.
        :rtype:                dict
        """
        deleted_users_dict = dict()
        for row in data_store_obj.execute("SELECT handle_id, username, instance FROM deleted_users;"):
            handle_id, username, instance = row
            deleted_users_dict[username, instance] = DeletedUser(handle_id=handle_id, username=username,
                                                                 instance=instance)
        return deleted_users_dict

    @classmethod
    def from_handle_obj(cls, handle_obj):
        """
        Instances a Deleted_User object from the state of the Handle object argument.

        :return: A Deleted_User object.
        :rtype:  DeletedUser
        """
        return DeletedUser(handle_id=handle_obj.handle_id, username=handle_obj.username,
                           instance=handle_obj.instance)

    def save_deleted_user(self, data_store_obj):
        """
        Saves this deleted user to the deleted_users table.

        :param data_store_obj: The Data_Store object to use to contact the database.
        :type data_store_obj:  Data_Store
        :return:               False if the deleted user data is already present in the
                               deleted_users table, True otherwise.
        :rtype:                bool
        """
        if self.handle_id is None:
            self.fetch_or_set_handle_id(data_store_obj)
        select_sql = f"SELECT * FROM deleted_users WHERE handle_id = {self.handle_id};"
        if bool(len(data_store_obj.execute(select_sql))):
            return False
        insert_sql = f"""INSERT INTO deleted_users (handle_id, username, instance) VALUES
                         ({self.handle_id}, '{self.username}', '{self.instance}');"""
        data_store_obj.execute(insert_sql)
        self.logger_obj.info(f"inserted {self.handle_in_at_form} into table deleted_users")
        return True


class RobotsTxt:
    """
    Represents a robots.txt file, implementing functionality to test whether a
    User-Agent + path combination is allowed or not.
    """
    __slots__ = 'user_agent', 'url', 'robots_dict', 'logger_obj', 'dont_discard_bc_wifi'

    user_agent_re = re.compile("^User-agent: (.*)$", re.I)
    allow_re = re.compile("^Allow: (.*)$", re.I)
    disallow_re = re.compile("^Disallow: (.*)$", re.I)

    @property
    def instance(self):
        return urllib.parse.urlparse(self.url).netloc

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
            raise InternalException(f"{self._get_robots_txt_url()} hasn't been loaded; can't judge whether "
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
    def _glob_match(cls, pattern, path):
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
            self.logger_obj.info(f"retrieving robots.txt for {self.instance}")
            response = requests.get(robots_txt_url, timeout=REQ_TIMEOUT)
        except requests.exceptions.SSLError:
            self.logger_obj.info(f"retrieving https://{self.instance}/robots.txt failed: SSL error ")
            return ''
        except requests.exceptions.TooManyRedirects:
            self.logger_obj.info(f"retrieving https://{self.instance}/robots.txt failed: too many redirects")
            return ''
        except requests.exceptions.ConnectTimeout:
            self.logger_obj.info(f"retrieving https://{self.instance}/robots.txt failed: connection timeout")
            return ''
        except requests.exceptions.ReadTimeout:
            self.logger_obj.info(f"retrieving https://{self.instance}/robots.txt failed: read timeout")
            return ''
        except requests.exceptions.ConnectionError as exception:
            if self.dont_discard_bc_wifi:
                self.logger_obj.info(f"retrieving https://{self.instance}/robots.txt failed: connection error; "
                                     "but the wifi might've gone out; not treating this as a valid robots.txt "
                                     "retrieval")
                raise exception
            else:
                self.logger_obj.info(f"retrieving https://{self.instance}/robots.txt failed: connection error")
                return ''
        except IOError:
            self.logger_obj.info(f"retrieving https://{self.instance}/robots.txt failed: python IOError")
            return ''
        if response.status_code != 200:
            self.logger_obj.info(f"retrieving https://{self.instance}/robots.txt failed: "
                                 f"status code {response.status_code}")
            return ''
        robots_txt_content = response.content.decode('utf-8')
        return robots_txt_content

    def _parse_robots_txt(self, robots_txt_content):
        self.logger_obj.info(f"parsing robots.txt for {self.instance}")
        index = 0
        robots_dict = dict()
        robots_lines = robots_txt_content.split("\n")

        if not len(robots_lines):
            self.logger_obj.warn(f"robots.txt for {self.instance} is zero-length")
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

        self.logger_obj.info(f"robots.txt for {self.instance} parsed")
        return robots_dict
