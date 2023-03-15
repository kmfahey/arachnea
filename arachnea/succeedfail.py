#!/usr/bin/python3

# FIXME add a Successful_Request class, re-architect
# Page_Fetcher.instantiate_and_fetch_page, Page.parse_profile_page,
# Page.parse_relations_page, Page.requests_fetch, and Page.webdriver_fetch to
# use Successful_Request complementarily to Failed_Request


class Internal_Exception(Exception):
    """
    Thrown in the case of a coding error or other internal issue.
    """
    pass


class Failed_Request:
    """
    Represents the outcome of a failed HTTP request. Encapsulates details on
    exactly how the request failed and for what reason. Used by Page_Fetcher's
    various methods as a failure signal value.
    """
    __slots__ = ('host', 'status_code', 'ratelimited', 'user_deleted', 'malfunctioning', 'unparseable', 'suspended',
                 'ssl_error', 'too_many_redirects', 'timeout', 'connection_error', 'posts_too_old', 'no_public_posts',
                 'forwarding_address', 'is_dynamic', 'webdriver_error', 'x_ratelimit_limit', 'robots_txt_disallowed')

    def __init__(self, host, connection_error=False, forwarding_address='', is_dynamic=False, malfunctioning=False,
                       no_public_posts=False, posts_too_old=False, ratelimited=False, ssl_error=False, status_code=0,
                       suspended=False, timeout=False, too_many_redirects=False, unparseable=False, user_deleted=False,
                       webdriver_error=False, x_ratelimit_limit=0, robots_txt_disallowed=False):
        """
        Instances a Failed_Request object.

        :param connection_error:      If there was a connection error when contacting the
                                      instance.
        :type connection_error:       bool, optional
        :param forwarding_address:    If the profile had a forwarding address, indicating
                                      it was defunct.
        :type forwarding_address:     bool, optional
        :param host:                  The hostname of the instance that the failed request
                                      occurred with.
        :type host:                   str
        :param is_dynamic:            If the page had a <noscript> tag, indicating that
                                      JavaScript evaluation is required to view the page's
                                      content.
        :type is_dynamic:             bool, optional
        :param malfunctioning:        If the instance returned a request that indicates the
                                      Mastodon software on the instance is malfunctioning
                                      (or misconfigured).
        :type malfunctioning:         bool, optional
        :param no_public_posts:       If the profile retrieved had no publicly accessible
                                      posts.
        :type no_public_posts:        bool, optional
        :param posts_too_old:         If the newest post that was retrieved from the
                                      instance for the particular user was older than the
                                      minimum period for consideration.
        :type posts_too_old:          bool, optional
        :param ratelimited:           If the program has been ratelimited.
        :type ratelimited:            bool, optional
        :param ssl_error:             If the SSL negotiation with the instance failed.
        :type ssl_error:              bool, optional
        :param status_code:           The status code the instance used in the HTTP request
                                      that indicated failure.
        :type status_code:            int, optional
        :param suspended:             If the instance that the program was meant to contact
                                      is a suspended instance.
        :type suspended:              bool, optional
        :param timeout:               If the instance did not response before the timeout
                                      period had elapsed.
        :type timeout:                bool, optional
        :param too_many_redirects:    If the instance sent the program through too many
                                      redirects.
        :type too_many_redirects:     bool, optional
        :param unparseable:           If the HTML returned in the HTTP connection could not
                                      be parsed by the program.
        :type unparseable:            bool, optional
        :param user_deleted:          If the user has been deleted from the instance that
                                      was contacted.
        :type user_deleted:           bool, optional
        :param webdriver_error:       If selenium.webdriver had an internal error.
        :type webdriver_error:        bool, optional
        :param x_ratelimit_limit:     If the request failed with a Status 429 error, and
                                      the response had an X-Ratelimit-Limit header, the
                                      integer value of that header.
        :type x_ratelimit_limit:      int, optional
        :param robots_txt_disallowed: If the request couldn't be made because the site's
                                      robots.txt didn't allow it.
        :type robots_txt_disallowed:  bool, optional
        """
        # raises an error if *none* of the optional args are specified
        if True not in (connection_error, bool(forwarding_address), is_dynamic, malfunctioning, no_public_posts,
                        posts_too_old, ratelimited, robots_txt_disallowed, ssl_error, status_code in (0, 200),
                        suspended, timeout, too_many_redirects, unparseable, user_deleted, webdriver_error,
                        bool(x_ratelimit_limit)):
            raise Internal_Error("Failed_Request instanced with no parameters set")
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
        self.robots_txt_disallowed = robots_txt_disallowed

    def __repr__(self):
        """
        Returns a string representation of the Failed_Request object.

        :return: A string representation of the object.
        :rtype:  str
        """
        init_argd = dict()
        # Builds a dict of all the instance vars that have values which don't cast to False.
        for attr_key in self.__slots__:
            attr_value = getattr(self, attr_key, False)
            if bool(attr_value):
                init_argd[attr_key] = attr_value
        args_str = ", ".join(f"{key}={repr(value)}" for key, value in init_argd.items())
        return f"{self.__class__.__name__}({args_str})"
