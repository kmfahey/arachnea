#!/usr/bin/python3

import bs4
import collections
import datetime
import decouple
import fs.glob
import functools
import html2text
import logging
import MySQLdb
import MySQLdb._exceptions
import optparse
import re
import requests
import selenium
import selenium.common.exceptions
import selenium.webdriver
import selenium.webdriver.common.by
import selenium.webdriver.firefox.options
import socket
import sys
import threading
import time
import urllib.parse


# One of two places that a timeout of 5 seconds is set. The other place is at
# the top of the Page.requests_fetch() method where the actual requests.get()
# call is made.
socket.setdefaulttimeout(5)

# Used to set how long selenium.webdriver waits between directing the puppet
# firefox instance to scroll the page.
SCROLL_PAUSE_TIME = 1.0

# Setting up the options accepted by the program on the commandline
parser = optparse.OptionParser()
parser.add_option("-C", "--handles-from-args", action="store_true", default=False, dest="handles_from_args",
                  help="skip querying the database for handles, instead process only the handles specified on the "
                       "commandline")
parser.add_option("-H", "--handles-join-profiles", action="store_true", default=False, dest="handles_join_profiles",
                  help="when fetching profiles, load unfetched handles from the `handles` table left join the "
                       "`profiles` table")
parser.add_option("-R", "--relations-join-profiles", action="store_true", default=False, dest="relations_join_profiles",
                  help="when fetching profiles, load unfetched handles from the `relations` table left join the "
                       "`profiles` table")

parser.add_option("-p", "--fetch-profiles-only", action="store_true", default=False, dest="fetch_profiles_only",
                  help="fetch profiles only, disregard following & followers pages")
parser.add_option("-q", "--fetch-relations-only", action="store_true", default=False, dest="fetch_relations_only",
                  help="fetch following & followers pages only, disregard profiles")
parser.add_option("-r", "--fetch-profiles-and-relations", action="store_true", default=False,
                  dest="fetch_profiles_and_relations", help="fetch both profiles and relations")

parser.add_option("-t", "--use-threads", action="store", default=0, type="int", dest="use_threads", help="use the "
                  "specified number of threads")
parser.add_option("-w", "--dont-discard-bc-wifi", action="store_true", default=False, dest="dont_discard_bc_wifi",
                  help="when loading a page leads to a connection error, assume it's the wifi and don't store a null "
                       "bio")
parser.add_option("-W", "--conn-err-wait-time", action="store", default=0.0, type="float",
                  dest="conn_err_wait_time", help="when loading a page leads to a connection error, and the "
                  "-w flag was specified, sleep the specified number of seconds before resuming the web spidering")
parser.add_option("-x", "--dry-run", action="store_true", default=False, dest="dry_run", help="don't fetch anything, "
                  "just load data structures from the database and then exit")


def main():
    (options, args) = parser.parse_args()

    # Argument integrity check; catching illegal combinations of commandline
    # arguments and emitting the appropriate error messages.
    if not options.fetch_profiles_only and not options.fetch_relations_only and not options.fetch_profiles_and_relations:
        print("please specify one of either -p, -q or -r on the commandline to choose the scraping mode")
        exit(1)
    elif options.fetch_profiles_only and options.fetch_relations_only or \
            options.fetch_profiles_only and options.fetch_profiles_and_relations or \
            options.fetch_relations_only and options.fetch_profiles_and_relations:
        print("more than just one of -p, -q and -r specified on the commandline; please supply only one")
        exit(1)

    if ((options.fetch_profiles_only or options.fetch_profiles_and_relations)
            and not (options.handles_join_profiles or options.relations_join_profiles or options.handles_from_args)):
        print("if -p or -r is specified, please specify one of -H, -R or -C on the commandline to indicate where to "
              "source handles to process")
        exit(1)
    elif (options.fetch_profiles_only or options.fetch_profiles_and_relations) and \
            ((options.handles_join_profiles and options.relations_join_profiles) or
             (options.handles_join_profiles and options.handles_from_args) or
             (options.relations_join_profiles and options.handles_from_args)):
        print("with -p or -r specified, please specify _only one_ of -H, -R or -C on the commandline to indicate where "
              "to source handles to process")
        exit(1)
    elif options.fetch_relations_only and (options.handles_join_profiles or options.relations_join_profiles):
        print("with -q specified, please don't specify -H or -R; relations-only fetching uses a profiles left join "
              "relations query for its handles")
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

    # Instance the main logger. This is the only logger needed unless threaded mode is used.
    main_logger_obj = instance_logger_obj("main", options.use_threads)

    # Logging the commandline flags received.
    if options.fetch_profiles_only:
        main_logger_obj.info("got -p flag, entering profiles-only mode")
    elif options.fetch_relations_only:
        main_logger_obj.info("got -q flag, entering relations-only mode")
    else:
        main_logger_obj.info("got -r flag, entering profiles & relations mode")

    if options.relations_join_profiles:
        main_logger_obj.info("got -R flag, loading handles present in the relations table but absent from the profiles tables")
    elif options.handles_join_profiles:
        main_logger_obj.info("got -H flag, loading handles present in the handles table but absent from the profiles table")
    elif options.fetch_relations_only:
        main_logger_obj.info("got -q flag, loading handles present in the profiles table but absent from the relations table")

    if options.dry_run:
        main_logger_obj.info("got -x flag, doing a dry run")

    if options.dry_run:
        main_logger_obj.info("got -w flag, saving handles for later if a generic connection error occurs")

    handle_re = re.compile("^@([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)$")

    save_profiles = (options.fetch_profiles_only or options.fetch_profiles_and_relations)
    save_relations = (options.fetch_relations_only or options.fetch_profiles_and_relations)

    # FIXME add database-searching mode and database-matching-rows-clearing mode
    # FIXME add robots.txt handling

    # The three main cases are processing handles from the commandline,
    # processing handles from the database in a threaded fashion,
    # and processing handles from the database in a single-tasking fashion.

    if options.handles_from_args:

        # Intializing the needed objects.
        handle_objs_from_args = list()
        write_data_store = Data_Store()
        read_data_store = Data_Store()
        instances_dict = Instance.fetch_all_instances(read_data_store, main_logger_obj)

        # The save_profiles, save_relations, dont_discard_bc_wifi, and
        # conn_err_wait_time args are passed to the Handle_Processor init, which
        # uses them to instance its captive Page_Fetcher object, which actually uses
        # them.
        handle_processor = Handle_Processor(Data_Store(main_logger_obj), main_logger_obj, instances_dict,
                                            save_profiles=save_profiles, save_relations=save_relations,
                                            dont_discard_bc_wifi=options.dont_discard_bc_wifi,
                                            conn_err_wait_time=options.conn_err_wait_time)

        # Iterating across the non-flag arguments, treating each one
        # as a handle (in @user@instance form) and prepping the
        # Handle_Processor.process_handle_iterable iterable argument.
        for handle_str in args:
            match = handle_re.match(handle_str)
            if match is None:
                logging.error(f"got argument {handle_str} that doesn't parse as a mastodon handle; fatal error")
                exit(1)
            username, host = match.group(1, 2)
            handle = Handle(username=username, host=host)
            handle.fetch_or_set_handle_id(write_data_store)
            handle_objs_from_args.append(handle)

        # If this is a dry run, stop here.
        if options.dry_run:
            exit(0)

        handle_processor.process_handle_iterable(handle_objs_from_args)

    elif options.use_threads:

        # SETTING UP PARALLELISM
        #
        # Each thread needs its own Logger object, its own Data_Store object, its
        # own Handle_Processor object, and its own equal-sized list of handles to
        # process.

        thread_objs = list()
        logger_objs = list()
        data_store_objs = list()
        handle_processor_objs = list()
        handles_lists = list()

        for index in range(0, options.use_threads):
            logger_obj = instance_logger_obj(f"thread#{index}", True)
            logger_objs.append(logger_obj)
            data_store_objs.append(Data_Store(logger_obj))
            handles_lists.append(list())

        # The instances_dict is shared between threads. This is especially important
        # where it stores an Instance object that is tracking a ratelimit that has
        # been imposed on the program by an instance. The program should only need
        # to get a status 429 response *once*, after which all threads need to
        # respect that ratelimit.
        instances_dict = Instance.fetch_all_instances(data_store_objs[0], main_logger_obj)

        for index in range(0, options.use_threads):
            handle_processor_obj = Handle_Processor(data_store_objs[index], logger_objs[index], instances_dict,
                                                    save_profiles=save_profiles, save_relations=save_relations,
                                                    dont_discard_bc_wifi=options.dont_discard_bc_wifi,
                                                    conn_err_wait_time=options.conn_err_wait_time)
            handle_processor_objs.append(handle_processor_obj)

        # If this is a dry run, stop here.
        if options.dry_run:
            exit(0)

        if options.fetch_relations_only:
            handles_generator = data_store_objs[0].users_in_profiles_not_in_relations()
        elif options.handles_join_profiles:
            handles_generator = data_store_objs[0].users_in_handles_not_in_profiles()
        elif options.relations_join_profiles:
            handles_generator = data_store_objs[0].users_in_relations_not_in_profiles()

        # This setup repeatedly iterates across the handles_lists list, appending
        # a handle from the handles_generator to each list in turn, until the
        # generator finally raises StopIteration. This populates the handles_lists
        # lists with equal or nearly equal numbers of handles.
        try:
            while True:
                for index in range(0, options.use_threads):
                    handles_lists[((index + 1) % options.use_threads) - 1].append(next(handles_generator))
        except StopIteration:
            pass

        handles_lists_lens_expr = ", ".join(map(str, map(len, handles_lists)))
        main_logger_obj.info(f"populated handles lists, lengths {handles_lists_lens_expr}")

        # Instancing & saving the thread objects.
        for index in range(0, options.use_threads):
            thread_obj = threading.Thread(target=handle_processor_objs[index].process_handle_iterable,
                                          args=(iter(handles_lists[index]),),
                                          daemon=True)
            thread_objs.append(thread_obj)
            main_logger_obj.info(f"instantiated thread #{index}")

        # Starting the threads.
        for index in range(0, options.use_threads):
            thread_objs[index].start()
            main_logger_obj.info(f"started thread #{index}")

        # Waiting for the threads to exit.
        for index in range(0, options.use_threads):
            thread_objs[index].join()
            main_logger_obj.info(f"closed thread #{index}")
    else:

        # Instancing the objects needed.
        data_store_obj = Data_Store(main_logger_obj)
        instances_dict = Instance.fetch_all_instances(data_store_obj, main_logger_obj)
        handle_processor = Handle_Processor(Data_Store(main_logger_obj), main_logger_obj, instances_dict,
                                            save_profiles=save_profiles, save_relations=save_relations,
                                            dont_discard_bc_wifi=options.dont_discard_bc_wifi,
                                            conn_err_wait_time=options.conn_err_wait_time)

        # If this is a dry run, stop here.
        if options.dry_run:
            exit(0)

        # Getting the correct handles generator depending on arguments.
        if options.fetch_relations_only:
            handles_generator = data_store_obj.users_in_profiles_not_in_relations()
        elif options.handles_join_profiles:
            handles_generator = data_store_obj.users_in_handles_not_in_profiles()
        elif options.relations_join_profiles:
            handles_generator = data_store_obj.users_in_relations_not_in_profiles()

        # Processing the handles. Main loop here.
        handle_processor.process_handle_iterable(handles_generator)


def instance_logger_obj(name, use_threads=False):
    logger_obj = logging.getLogger(name=name)
    logger_obj.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    if use_threads:
        formatter = logging.Formatter('[%(asctime)s] <%(name)s> %(levelname)s: %(message)s')
    else:
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    logger_obj.addHandler(handler)
    return logger_obj


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

        :param handle_id: The primary key of the row in the MySQL handles table that
                          furnished the data this Handle object is instanced from, if
                          any.
        :type handle_id:  int, optional
        :param username:  The part of the handle that represents the indicated user's
                          username.
        :type username:   str
        :param host:      The part of the handle that represents the indicated user's
                          instance.
        :type host:       str
        """
        # FIXME should do input checking on args
        assert isinstance(handle_id, int) or handle_id is None
        self.handle_id = handle_id
        self.username = username
        self.host = host

    def convert_to_deleted_user(self):
        """
        Instances a Deleted_User object from the state of this Handle object.

        :return: A Deleted_User object with the same values for its handle_id, username
                 and host state variables.
        :rtype:  Deleted_User
        """
        return Deleted_User(handle_id=self.handle_id, username=self.username, host=self.host)

    def fetch_or_set_handle_id(self, data_store):
        """
        If the Handle object was instanced from another source than a row in the
        MySQL handles table, set the handle_id from the table, inserting the data if
        necessary.

        :param data_store: The Data_Store object to use to access the handles table.
        :type data_store:  Data_Store
        :return:           True if the handle_id value was newly set; False if the
                           handle_id instance variable was already set.
        :rtype:            bool
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
    """
    Intermediates a connection to the MySQL database.
    """
    __slots__ = 'db_connection', 'db_cursor', 'logger'

    host = 'localhost'
    user = decouple.config('DB_USER')
    password = decouple.config('DB_PASSWORD')
    db = 'arachnea'

    def __init__(self, logger):
        """
        Instances the Data_Store object.

        :param logger: A Logger object to log events to.
        :type logger:  logging.Logger
        """
        self.logger = logger
        self.logger.info("opening connection to database")
        self.db_connection = MySQLdb.Connect(host=self.host, user=self.user, password=self.password, db=self.db)
        self.db_connection.autocommit(True)
        self.db_cursor = self.db_connection.cursor()

    def users_in_relations_not_in_profiles(self):
        """
        Executes a statement of the form SELECT ... FROM relations LEFT JOIN profiles
        ... WHERE .... IS NULL on the database, selecting records from the relations
        table that don't have a corresponding row in the profiles table. Such a record
        represents a user who has been found in someone's following or followers list
        but hasn't had their profile loaded yet.

        :return: A generator that yields tuples of (handle_id, username, instance)
                 values.
        """
        self.logger.info("selecting handles from relations left join profiles")
        relations_left_join_profiles_sql = """SELECT DISTINCT relation_handle_id, relation_username, relation_instance
                                              FROM relations LEFT JOIN profiles ON relations.relation_handle_id
                                              = profiles.profile_handle_id WHERE profiles.profile_handle_id IS NULL
                                              ORDER BY RAND();"""
        return self._execute_sql_generator(relations_left_join_profiles_sql)

    def users_in_profiles_not_in_relations(self):
        """
        Executes a statement of the form SELECT ... FROM profiles LEFT JOIN relations
        ... WHERE .... IS NULL on the database, selecting records from the profiles
        table that don't have a corresponding row in the relations table. Such a record
        represents a user whose profile has been loaded but who doesn't appear in any of
        the followers or following lists that have been downloaded so far.

        :return: A generator that yields 3-tuples of (handle_id, username, instance)
                 values.
        """
        self.logger.info("selecting handles from profiles left join relations")
        profiles_left_join_relations_sql = """SELECT profiles.profile_handle_id, username, instance
                                              FROM profiles LEFT JOIN relations
                                              ON profiles.profile_handle_id = relations.profile_handle_id
                                              WHERE relations.profile_handle_id IS NULL ORDER BY RAND();"""
        return self._execute_sql_generator(profiles_left_join_relations_sql)

    def users_in_handles_not_in_profiles(self):
        """
        Executes a statement of the form SELECT ... FROM handles LEFT JOIN profiles
        ... WHERE .... IS NULL on the database, selecting records from the handles
        table that don't have a corresponding row in the profiles table. Such a record
        represents a handle that was saved from one of a number of sources, but whose
        profile hasn't been loaded yet.

        :return: A generator that yields 3-tuples of (handle_id, username, instance)
                 values.
        """
        self.logger.info("selecting handles from handles left join profiles")
        handles_left_join_profiles_sql = """SELECT handles.handle_id, handles.username, handles.instance FROM handles
                                            LEFT JOIN profiles ON handles.handle_id = profiles.profile_handle_id
                                            WHERE profiles.profile_handle_id IS NULL ORDER BY RAND();"""
        return self._execute_sql_generator(handles_left_join_profiles_sql)

    def _execute_sql_generator(self, select_sql):
        """
        A private method used by other methods on this class to execute an SQL statement
        and then return a generator which retrieves & yields rows from the database
        one at a time. Used to avoid pulling a large tuple-of-tuples and storing it in
        memory when a query returns a large number of rows.

        :param select_sql: A SELECT SQL statement to execute.
        :type select_sql:  str
        :return:           A generator that yields one row at a time from the query
                           executed.
        :rtype:            types.GeneratorType
        """
        # FIXME should raise an error if the statement argument isn't a SELECT
        # statement.
        self.db_cursor.execute(select_sql)
        row = self.db_cursor.fetchone()
        while row is not None:
            yield Handle(*row)
            row = self.db_cursor.fetchone()

    def execute(self, sql):
        """
        Executes a query on the database and returns all the matching rows.

        :return: If a SELECT statement was executed, returns a tuple-of-tuples where
                 each inner tuple is one matching row from the query that was executed.
                 The length of the inner tuples and the data contained depends on the
                 columns selected. Otherwise, returns a zero-length tuple.
        """
        self.db_cursor.execute(sql)
        return self.db_cursor.fetchall()

    def close(self):
        """
        Closes the database cursor and the database connection.

        :return: None
        """
        self.db_cursor.close()
        self.db_connection.close()

    def __del__(self):
        self.close()


# This class adapted from robotstxt_to_df.py at
# https://github.com/jcchouinard/SEO-Projects/ . Repository has no LICENSE file
# so presuming open availability to reuse and adapt without limitations.
class Robots_Txt_File:
    """
    Represents a robots.txt file, implementing functionality to test whether a
    User-Agent + path combination is allowed or not.
    """
    __slots__ = 'user_agent', 'url', 'robots_dict'

    user_agent_re = re.compile("^(?=User-Agent: )", re.I | re.M)
    disallow_re = re.compile("^Disallow: ", re.I)
    allow_re = re.compile("^Allow: ", re.I)

    def __init__(self, user_agent, url):
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
        # Parsing robots.txt to a dict-of-dicts-of-sets. The outer dict keys are
        # User-Agents, the inner dict keys are either "Allow" or "Disallow", and
        # the sets are sets of robots.txt path patterns.
        self.robots_dict = None

    def load_and_parse(self):
        """
        Loads the indicated robots.txt file and parses it, such that after this call the
        can_fetch() method will be operational.

        :return: None
        :rtype:  types.NoneType
        """
        robots_txt_url = self._get_robots_txt_url()
        robots_txt_content = self._read_robots_txt(robots_txt_url)
        self.robots_dict = self._parse_robots_txt(robots_txt_content)

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
        # If of matching_allow_pats and matching_disallow_pats one is
        # zero-length and one is nonzero-length, then it's allowed if Allowed is
        # the nonzero one.
        elif (len(matching_allow_pats), len(matching_disallow_pats)).count(0) == 1:
            return bool(matching_allow_pats)
        # If none of the patterns matched, but an Allow block *exists* in the
        # robots.txt, that implies that only paths matching an Allow pattern are
        # allowed, so the path is disallowed.
        elif robots_block["Allow"]:
            return False
        # No patterns matched and the robots.txt didn't have any Allow patterns.
        # That implies any path not explicitly blocked is permitted, so the path
        # is allowed.
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
        response = requests.get(robots_txt_url)
        if response.status_code != 200:
            raise Internal_Exception(f"couldn't fetch {robots_txt_url}: got status code {response.status_code}")
        robots_txt_content = response.content.decode('utf-8')
        return robots_txt_content

    def _parse_robots_txt(self, robots_txt_content):
        # Parse the robots.txt content to a dict-of-dicts-of-sets. The outer
        # dict keys are User-Agents, the inner dict keys are either "Allow" or
        # "Disallow", and the sets are sets of robots.txt path patterns.
        robots_dict = dict()

        # Breaks the robots.txt file content on "^User-Agent: " and iterate
        # across the blocks starting at the second substring.
        user_agent_blocks = self.user_agent_re.split(robots_txt_content)
        for user_agent_block in user_agent_blocks[1:]:
            user_agents, disallow_lines, allow_lines = set(), set(), set()
            index = 0
            robot_lines = user_agent_block.split("\n")
            while self.user_agent_re.match(robot_lines[index]):
                robot_line = robot_lines[index]
                user_agents.add(robot_line[robot_line.index(':')+1:].strip())
                index += 1
            while index < len(robot_lines):
                robot_line = robot_lines[index]
                if self.disallow_re.match(robot_line):
                    disallow_lines.add(robot_line[robot_line.index(':')+1:].strip())
                elif self.allow_re.match(robot_line):
                    allow_lines.add(robot_line[robot_line.index(':')+1:].strip())
                index += 1
            directives_dict = {"Allow": allow_lines, "Disallow": disallow_lines}
            for user_agent in user_agents:
                robots_dict[user_agent] = directives_dict
        return robots_dict


class Instance(object):
    """
    Represents a mastodon instance.
    """
    __slots__ = 'host', 'logger', 'rate_limit_expires', 'attempts', 'malfunctioning', 'suspended', 'unparseable', 'robots_txt_file_obj'

    @property
    def rate_limit_expires_isoformat(self):
        return datetime.datetime.fromtimestamp(self.rate_limit_expires).time().isoformat()

    @property
    def status(self):
        return 'malfunctioning' if self.malfunctioning \
                else 'suspended' if self.suspended \
                else 'unparseable' if self.unparseable \
                else 'ingoodstanding'

    def __init__(self, host, logger, malfunctioning=False, suspended=False, unparseable=False, rate_limited=False,
                       x_ratelimit_limit=None, attempts=0):
        """
        Instances a Instance object.

        :param attempts:          The number of unsuccessful attempts the program has
                                  made to contact this instance.
        :type attempts:           int, optional
        :param host:              The hostname of the instance (str).
        :type host:               str
        :param logger:            The logger object to log events to.
        :type logger:             logging.Logger
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
        self.logger = logger
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
        self.logger.info(f"set rate limit on instance '{self.host}': rate limit expires "
                         f"at {self.rate_limit_expires_isoformat}")

    @classmethod
    def fetch_all_instances(self, data_store, logger):
        """
        Loads all lines from the bad_instances table, converts them to Instance objects,
        and returns a dict mapping hostnames to Instance objects.

        :param data_store: The Data_Store object to use to connect to the database.
        :type data_store:  Data_Store
        :param logger:     The logger object to use to log events to.
        :type logger:      logging.Logger
        :return:           A dict mapping hostnames (strs) to Instance objects.
        :rtype:            dict
        """
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
        """
        Accepts a dict mapping hostnames to Instance objects, and commits every novel
        one to the database. (Class method.)

        :param instances_dict: A dict mapping hostnames (strs) to Instance objects.
        :type instances_dict:  dict
        :param data_store:     The Data_Store object to use to connect to the database.
        :type data_store:      Data_Store
        :param logger:         The logger object to use to log events to.
        :type logger:          logging.Logger
        :return:               None
        :rtype:                types.NoneType
        """
        # FIXME should detect changed instance state between database and memory
        existing_instances_dict = self.fetch_all_instances(data_store, logger)
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
        logger.info(f"saving {len(instances_to_insert)} bad instances to bad_instances table")
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
        self.logger.info(f"saving bad instance {self.host} to bad_instances table")
        data_store.execute(f"INSERT INTO bad_instances (instance, issue) VALUES ('{self.host}', '{status}');")
        return True

    def fetch_robots_txt(self):
        try:
            robots_txt_file_obj = Robots_Txt_File(f"https://{self.host}/")
            robots_txt_file_obj.load_and_parse()
        except Internal_Exception:
            robots_txt_file_obj = None
        self.robots_txt_file_obj = robots_txt_file_obj

    def can_fetch(self, query_url):
        if self.malfunctioning or self.suspended or self.unparseable:
            raise Internal_Exception(f"instance {self.host} has status {self.status}; nothing there can be fetched")
        elif self.robots_txt_file_obj is None or not self.robots_txt_file_obj.has_been_loaded():
            raise Internal_Exception(f"{self._get_robots_txt_url()} hasn't been loaded; can't judge whether "
                                     f"{query_url} can be fetched")
        return self.robots_txt_file_obj.can_fetch(query_url)


class Failed_Request(object):
    """
    Represents the outcome of a failed HTTP request. Encapsulates details on
    exactly how the request failed and for what reason. Used by Page_Fetcher's
    various methods as a failure signal value.
    """
    __slots__ = ('host', 'status_code', 'ratelimited', 'user_deleted', 'malfunctioning', 'unparseable', 'suspended',
                 'ssl_error', 'too_many_redirects', 'timeout', 'connection_error', 'posts_too_old', 'no_public_posts',
                 'forwarding_address', 'is_dynamic', 'webdriver_error', 'x_ratelimit_limit')

    def __init__(self, host, connection_error=False, forwarding_address='', is_dynamic=False, malfunctioning=False,
                       no_public_posts=False, posts_too_old=False, ratelimited=False, ssl_error=False, status_code=0,
                       suspended=False, timeout=False, too_many_redirects=False, unparseable=False, user_deleted=False,
                       webdriver_error=False, x_ratelimit_limit=0):
        """
        Instances a Failed_Request object.

        :param connection_error:   If there was a connection error when contacting the
                                   instance.
        :type connection_error:    bool, optional
        :param forwarding_address: If the profile had a forwarding address, indicating
                                   it was defunct.
        :type forwarding_address:  bool, optional
        :param host:               The hostname of the instance that the failed request
                                   occurred with.
        :type host:                str
        :param is_dynamic:         If the page had a <noscript> tag, indicating that
                                   JavaScript evaluation is required to view the page's
                                   content.
        :type is_dynamic:          bool, optional
        :param malfunctioning:     If the instance returned a request that indicates the
                                   Mastodon software on the instance is malfunctioning
                                   (or misconfigured).
        :type malfunctioning:      bool, optional
        :param no_public_posts:    If the profile retrieved had no publicly accessible
                                   posts.
        :type no_public_posts:     bool, optional
        :param posts_too_old:      If the newest post that was retrieved from the
                                   instance for the particular user was older than the
                                   minimum period for consideration.
        :type posts_too_old:       bool, optional
        :param ratelimited:        If the program has been ratelimited.
        :type ratelimited:         bool, optional
        :param ssl_error:          If the SSL negotiation with the instance failed.
        :type ssl_error:           bool, optional
        :param status_code:        The status code the instance used in the HTTP request
                                   that indicated failure.
        :type status_code:         int, optional
        :param suspended:          If the instance that the program was meant to contact
                                   is a suspended instance.
        :type suspended:           bool, optional
        :param timeout:            If the instance did not response before the timeout
                                   period had elapsed.
        :type timeout:             bool, optional
        :param too_many_redirects: If the instance sent the program through too many
                                   redirects.
        :type too_many_redirects:  bool, optional
        :param unparseable:        If the HTML returned in the HTTP connection could not
                                   be parsed by the program.
        :type unparseable:         bool, optional
        :param user_deleted:       If the user has been deleted from the instance that
                                   was contacted.
        :type user_deleted:        bool, optional
        :param webdriver_error:    If selenium.webdriver had an internal error.
        :type webdriver_error:     bool, optional
        :param x_ratelimit_limit:  If the request failed with a Status 429 error, and
                                   the response had an X-Ratelimit-Limit header, the
                                   integer value of that header.
        :type x_ratelimit_limit:   int, optional
        """
        # FIXME should raise an error if *none* of the optional args are specified
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


class Deleted_User(Handle):
    """
    Represents a user who has been deleted from their instance. Inherits from Handle.
    """
    __slots__ = 'logger',

    @classmethod
    def fetch_all_deleted_users(self, data_store):
        # FIXME if the Handle and Deleted_User classes are made hashable then
        # the dict can be replaced with set.
        """
        Retrieves all records from the deleted_users table and returns them in a dict.

        :param data_store: The Data_Store object to use to contact the database.
        :type data_store:  Data_Store
        :return:           A dict mapping 2-tuples of (username, host) to Deleted_User
                           objects.
        :rtype:            dict
        """
        deleted_users_dict = dict()
        for row in data_store.execute("SELECT handle_id, username, instance FROM deleted_users;"):
            handle_id, username, host = row
            deleted_users_dict[username, host] = Deleted_User(handle_id=handle_id, username=username, host=host)
        return deleted_users_dict

    def save_deleted_user(self, data_store):
        # FIXME this code should check for the presence of the record in the
        # database rather than relying on an IntegrityError
        # FIXME should return True if successful, False if the record is already
        # present
        """
        Saves this deleted user to the deleted_users table.

        :param data_store: The Data_Store object to use to contact the database.
        :type data_store:  Data_Store
        :return:           None
        :rtype:            types.NoneType
        """
        insert_sql = f"""INSERT INTO deleted_users (handle_id, username, instance) VALUES
                         ({self.handle_id}, '{self.username}', '{self.host}');"""
        try:
            data_store.execute(insert_sql)
        except MySQLdb._exceptions.IntegrityError:
            self.logger.info(f"got an SQL IntegrityError when inserting {self.handle} into table deleted_users")
        else:
            self.logger.info(f"inserted {self.handle} into table deleted_users")


class Page_Fetcher(object):
    """
    An originator of Page objects that executes this workflow:

    * Prepares the request
    * Fails fast if it is unsatisfiable
    * Instances the Page object
    * Has the Page object execute the request
    * If it fails, handles a variety of failed requests in different ways
    * If it succeeds, yields the Page object.
    """
    __slots__ = ('instances_dict', 'data_store', 'logger', 'deleted_users_dict', 'save_profiles', 'save_relations',
                 'dont_discard_bc_wifi', 'conn_err_wait_time')

    def __init__(self, data_store, logger, instances_dict, save_profiles=False, save_relations=False,
                       dont_discard_bc_wifi=False, conn_err_wait_time=0.0):
        """
        Instances the Page_Fetcher object.

        :param data_store:                 The Data_Store object to use when saving a
                                           Page or Deleted_User object.
        :type data_store:                  Data_Store
        :param logger:                     The Logger object to use to log events.
        :type logger:                      logger.Logger
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
        # FIXME a nonzero value for conn_err_wait_time and a False value
        # for dont_discard_bc_wifi should result in an error
        self.data_store = data_store
        self.logger = logger
        self.instances_dict = instances_dict
        self.deleted_users_dict = Deleted_User.fetch_all_deleted_users(self.data_store)
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.dont_discard_bc_wifi = dont_discard_bc_wifi
        self.conn_err_wait_time = conn_err_wait_time

    def instantiate_and_fetch_page(self, handle, url):
        host = handle.host
        instance = self.instances_dict.get(host, None)

        # There exists a record of this instance in the instances_dict. It is
        # almost certainly not contactable. Figuring out *how* and handle it.
        if instance is not None:
            if instance.malfunctioning or instance.unparseable or instance.suspended:
                if self.save_profiles:
                    # If in a profile-saving mode, a handle that turns out to
                    # have a bad instance gets a null profile bio saved to the
                    # data store. The empty Page for that profile is returned.
                    self.logger.info(f"instance {host} on record as {instance.status}; "
                                     f"didn't load {url}; saving null bio to database")
                    page = Page(handle, url, self.logger, save_profiles=self.save_profiles,
                                save_relations=self.save_relations)
                    page.save_page(self.data_store)
                    return page, Failed_Request(host,
                                                malfunctioning=instance.malfunctioning,
                                                unparseable=instance.unparseable,
                                                suspended=instance.suspended)
                else:
                    # If in a relations-saving mode, no Page is generated or
                    # saved.
                    self.logger.info(f"instance {host} on record as {instance.status}; didn't load {url}")
                    return None, Failed_Request(host,
                                                malfunctioning=instance.malfunctioning,
                                                unparseable=instance.unparseable,
                                                suspended=instance.suspended)
            elif instance.still_rate_limited():

                # The other case for an unreachable instance is if the program
                # is rate-limited from it.
                self.logger.info(f"instance {host} still rate limited, expires at "
                                 f"{instance.rate_limit_expires_isoformat}, didn't load {url}")
                return None, Failed_Request(host, ratelimited=True)

        # There exists a record of this user-instance combination in the
        # deleted_users_dict. Handling it.
        elif (handle.username, handle.host) in self.deleted_users_dict:
            # FIXME: this step can be skipped if a JOIN against deleted_users is
            # added to the handles loading step
            # FIXME should save a null bio
            self.logger.info(f"user {handle.handle} known to be deleted; didn't load {url}")
            return None, Failed_Request(handle.host, user_deleted=True)

        # Possibilities for aborting transfer don't apply; proceeding with a
        # normal attempt to load the page.
        page = Page(handle, url, self.logger, save_profiles=self.save_profiles, save_relations=self.save_relations)
        result = page.requests_fetch()

        # If the request failed because the page is dynamic (ie. has a
        # <noscript> tag), trying again using webdriver.
        if isinstance(result, Failed_Request) and result.is_dynamic:
            self.logger.info(f"loaded {url}: page has <noscript>; loading with webdriver")
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
                    instance = Instance(host, self.logger, rate_limited=True,
                                        x_ratelimit_limit=result.x_ratelimit_limit)
                    self.instances_dict[host] = instance
                else:
                    instance = self.instances_dict[host]
                    instance.set_rate_limit(x_ratelimit_limit=result.x_ratelimit_limit)
                self.logger.info(f"failed to load {url}: rate limited: expires at " +
                                 instance.rate_limit_expires_isoformat)

            # The instance malfunctioned.
            elif result.malfunctioning:

                # Saving that fact to the instances_dict.
                if host in self.instances_dict:
                    instance = self.instances_dict[host]
                    instance.attempts += 1
                else:
                    instance = Instance(host, self.logger, attempts=1)
                    self.instances_dict[host] = instance

                # Logging the precise type malfunction it was.
                if result.ssl_error:
                    self.logger.info(f"failed to load {url}, host malfunctioning: ssl error "
                                     f"(error #{instance.attempts} for this host)")
                elif result.too_many_redirects:
                    self.logger.info(f"failed to load {url}, host malfunctioning: too many redirects "
                                     f"(error #{instance.attempts} for this host)")
                elif result.timeout:
                    self.logger.info(f"failed to load {url}, host malfunctioning: connection timeout "
                                     f"(error #{instance.attempts} for this host)")
                elif result.connection_error:
                    self.logger.info(f"failed to load {url}, host malfunctioning: connection error "
                                     f"(error #{instance.attempts} for this host)")
                else:
                    self.logger.info(f"failed to load {url}, host malfunctioning: got status code {result.status_code}"
                                     f"(error #{instance.attempts} for this host)")

            elif result.user_deleted:

                # The user has been deleted from the instance. Saving that fact
                # to the data store.
                deleted_user = handle.convert_to_deleted_user()
                deleted_user.logger = self.logger
                self.deleted_users_dict[handle.username, handle.host] = deleted_user
                deleted_user.save_deleted_user(self.data_store)
                self.logger.info(f"failed to load {url}: user deleted")

            # Several other kinds of error that only need to be logged.
            elif result.webdriver_error:
                self.logger.info(f"loaded {url}: webdriver loading failed with internal error")
            elif result.no_public_posts:
                self.logger.info(f"loaded {url}: no public posts")
            elif result.posts_too_old:
                self.logger.info(f"loaded {url}: posts too old")
            elif result.unparseable:
                self.logger.info(f"loaded {url}: parsing failed")

            # The profile gave the program a forwarding address.
            # FIXME should save these to the handles table.
            elif result.forwarding_address:
                if result.forwarding_address is True:
                    self.logger.info(f"loaded {url}: forwarding page (could not recover handle)")
                else:
                    self.logger.info(f"loaded {url}: forwarding page")
            else:
                self.logger.info(f"loaded {url}: unanticipated error {repr(result)}")
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

                self.logger.info(f"handle {handle.handle}: fetching {what_fetched} returned connection error; "
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
            self.logger.info(f"loaded {url}: detected profile bio, length {len(page.profile_bio_text)}")
        elif self.save_relations and page.is_following:
            self.logger.info(f"loaded {url}: found {result} following handles")
        elif self.save_relations and page.is_followers:
            self.logger.info(f"loaded {url}: found {result} followers handles")

        return page, result


class Page(object):
    """
    Represents a single page; handles retrieving the page and the ensuing errors
    itself.
    """
    __slots__ = ('handle', 'username', 'host', 'logger', 'url', 'logger', 'document', 'is_dynamic', 'loaded',
                 'is_profile', 'is_following', 'is_followers', 'page_number', 'profile_no_public_posts',
                 'profile_posts_too_old', 'profile_bio_text', 'relations_list', 'unparseable', 'save_profiles',
                 'save_relations')

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

    def __init__(self, handle, url, logger, save_profiles=False, save_relations=False):
        """
        Instances the Page object.

        :param handle:         The handle of the profile the page belongs to.
        :type handle:          Handle
        :param url:            The URL of the page.
        :type url:             str
        :param logger:         The Logger object to log events to.
        :type logger:          logger.Logger
        :param save_profiles:  If the program is in a profiles-saving mode.
        :type save_profiles:   bool
        :param save_relations: If the program is in a relations-saving mode.
        :type save_relations:  bool
        """
        # Setting instance vars from the args and their attributes.
        self.handle = handle
        self.url = url
        self.logger = logger
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.username = handle.username
        self.host = handle.host

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
        # A big try/except statement to handle a variet of different Exceptions
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
        try:
            # Instancing the headless puppet firefox instance.
            options = selenium.webdriver.firefox.options.Options()
            options.add_argument('-headless')
            self.logger.info("webdriver instantiating headless Firefox program")
            browser = selenium.webdriver.Firefox(options=options)
            self.logger.info(f"webdriver loading URL {self.url}")

            browser.get(self.url)

            if self.is_profile and self.save_profiles:
                # If this is a profile page, then it doesn't need to be
                # scrolled, and no further interaction with the page is
                # necessary after capturing the initial JS rendering.
                html = browser.page_source
                self.document = bs4.BeautifulSoup(markup=html, features='lxml')
                page_height = browser.execute_script("return document.body.scrollHeight")
                self.logger.info(f"webdriver loaded page of height {page_height}")

                # Contrast with parse_relations_page(), which *does* need to
                # interact with the page further.
                return self.parse_profile_page()
            elif (self.is_following or self.is_followers) and self.save_relations:
                # The page needs to be scrolled to the bottom, moving the pane
                # down by its height step by step, to ensure the entire page
                # is loaded (may be other lazy-loaded elements) and so that
                # parse_relations_page() starts from the bottom.
                last_height = browser.execute_script("return document.body.scrollHeight")
                self.logger.info(f"webdriver loaded initial page height {last_height}")
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
                        self.logger.info(f"webdriver scrolled down to page height {last_height} and finished scrolling")
                        break
                    last_height = new_height
                    self.logger.info(f"webdriver scrolled down to page height {last_height}")

                # Time to parse the page. More scrolling and detection of
                # elements will be involved so parse_relations_page() takes the
                # browser object.
                return self.parse_relations_page(browser)
            else:
                return False
        except (selenium.common.exceptions.NoSuchElementException, selenium.common.exceptions.WebDriverException):
            # selenium.webdriver failed fsr. There's no diagnosing this sort of
            # thing, so a Failed_Request is returned.
            self.logger.info("webdriver experienced an internal error, failing")
            return Failed_Request(self.host, webdriver_error=True)
        finally:
            self.logger.info("closing out webdriver Firefox instance")
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
        self.logger.info(f"parsing profile at {self.url}")
        # FIXME correct time tag parsing to reflect the latest format in use
#       time_tags = self.document.find_all('time', {'class': 'time-ago'})
#        if len(time_tags) == 0:
#            self.profile_no_public_posts = True
#            return Failed_Request(self.host, no_public_posts=True)
#        else:
#            time_tags = [time_tag['datetime'] for time_tag in time_tags]
#            if '+' in time_tags[0]:
#                time_tags = [time_split[0]+'Z' for time_split in (time_tag.split('+') for time_tag in time_tags)]
#            toot_datetimes = sorted(map(lambda time_tag: datetime.datetime.strptime(time_tag, '%Y-%m-%dT%H:%M:%SZ'), time_tags))
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
        self.logger.info(f"parsing {self.relation_type} at {self.url}")

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
                self.logger.info(f"using selenium.webdriver to page over dynamic {self.relation_type} page forcing "
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
                    self.logger.info(f"pass #{pass_counter}: {empty_article_tags_count_diff} <article> tags text found")
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
            select_sql = f"""SELECT profile_handle_id, profile_snippet FROM profiles
                             WHERE profile_handle_id = {handle.handle_id};"""
            rows = data_store.execute(select_sql)
            if rows:
                ((handle_id, profile_snippet),) = rows
                if profile_snippet:
                    return 0
                elif profile_bio_text:
                    # If by some chance this handle_id already has a row in the
                    # profiles table, but its profile_snippet is null, and the
                    # bio text the program is going to save here is *not* null,
                    # then use an UPDATE statement to set the profile bio.
                    update_sql = f"""UPDATE profiles SET profile_snippet = {profile_bio_text}
                                     WHERE profile_handle_id = {handle.handle_id};"""
                    data_store.execute(update_sql)
                    return 1
            else:
                # Otherwise use an INSERT statement like usual.
                insert_sql = f"""INSERT INTO profiles (profile_handle_id, username, instance,
                                                       considered, profile_snippet)
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
                self.logger.info(f"page {self.page_number} of {relation} for "
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
                        self.logger.info(f"got an SQL IntegrityError when inserting {relation_handle.handle} %s "
                                         f"{profile_handle.handle} into table relations" % (
                                             'follower of' if relation == 'followers' else relation))
                    else:
                        insertion_count += 1
            else:
                insertion_count = len(value_sql_list)
            relation_expr = 'followings' if relation == 'following' else relation
            self.logger.info(f"saved {insertion_count} {relation_expr} to the database")
            return insertion_count


class Handle_Processor(object):
    """
    Implements a class for processing a list of handles and fetching the profile,
    relations, or both for each one depending on configuration.
    """
    __slots__ = ('data_store', 'logger', 'instances_dict', 'save_from_wifi', 'last_time_point', 'current_time_point',
                 'save_profiles', 'save_relations', 'page_fetcher', 'logger', 'dont_discard_bc_wifi',
                 'conn_err_wait_time')

    def __init__(self, data_store, logger, instances_dict, save_profiles=False, save_relations=False,
                       dont_discard_bc_wifi=False, conn_err_wait_time=0.0):
        """
        Initializes the Handle_Processor object.

        :param data_store:           The Data_Store object to use to contact the
                                     database.
        :type data_store:            Data_Store
        :param logger:               The Logger object to use to log events.
        :type logger:                logger.Logger
        :param instances_dict:       A dict associating hostnames to Instance objects,
                                     used to identify problematic instances (or ones the
                                     program has been ratelimited from) and avoid
                                     contacting them.
        :type instances_dict:        dict
        :param save_profiles:        If the program is in a profiles-saving mode.
        :type save_profiles:         bool
        :param save_relations:       If the program is in a following/followers-saving
                                     mode.
        :type save_relations:        bool
        :param dont_discard_bc_wifi: If the program has been instructed not to interpret
                                     a connection error as a reason to mark a profile as
                                     unfetchable (by saving a null bio to the database).
        :type dont_discard_bc_wifi:  bool
        :param conn_err_wait_time:   If the program is not discarding profiles on a
                                     connection error, the period of time (in seconds)
                                     to sleep after each connection error. (Done to
                                     avoid chewing through a large number of unreachable
                                     profiles while the WiFi is out.)
        :type conn_err_wait_time:    float
        """
        self.data_store = data_store
        self.logger = logger
        self.instances_dict = instances_dict
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.dont_discard_bc_wifi = dont_discard_bc_wifi
        self.conn_err_wait_time = conn_err_wait_time

        # Instancing the Page_Fetcher object that Handle_Processor will use
        # to fetch the appropriate pages for each handle. The save_profiles,
        # save_relations, dont_discard_bc_wifi, and conn_err_wait_time values
        # were specified on the commandline and passed to this object on
        # instantiation; now they're being passed down to Page_Fetcher where
        # they'll actually be used.
        self.page_fetcher = Page_Fetcher(data_store, self.logger, instances_dict, save_profiles=save_profiles,
                                         save_relations=save_relations, dont_discard_bc_wifi=self.dont_discard_bc_wifi,
                                         conn_err_wait_time=self.conn_err_wait_time)

    def process_handle_iterable(self, handle_iterable):
        """
        Iterates over a provided iterable that yields Handle objects, fetching &
        processing the appropriate page(s) for each one.

        :param handle_iterable: An iterable obprocess_handle_iterableject that's
                                comprised of Handle objects, or a generator that yields
                                Handle objects.
        :type handle_iterable:  tuple, list, set, or types.GeneratorType
        :return:                None
        :rtype:                 types.NoneType
        """
        skipped_handles = list()

        for handle in handle_iterable:
            # Get a handle_id, which inserts this handle into the handles table
            # as a side effect.
            if not handle.handle_id:
                handle.fetch_or_set_handle_id(write_data_store)

            profile_url = handle.profile_url
            result = results = None
            try:
                if self.save_profiles and not self.save_relations:
                    # Retrieves the profile page and saves its bio text to the
                    # database if possible.
                    result = self.retrieve_profile(handle, profile_url)
                else:
                    # Retrieves the profile page if possible, uses it to find
                    # the profile's following/followers pages, retrieves those
                    # pages in full if possible and saves them to the database.
                    results = self.retrieve_relations_from_profile(handle, profile_url)
            except Internal_Exception:
                continue

            if result is not None and isinstance(result, Failed_Request):
                if result.ratelimited or result.connection_error:
                    skipped_handles.append(handle)
            elif results is not None and any(isinstance(result, Failed_Request) for result in results):
                if any(isinstance(result, int) for result in results):
                    # So within the retrieve_relations_from_profile() call, one
                    # retrieve_relations() call succeeded and one failed. That
                    # situation is too complex to reach any conclusions from so
                    # the program just passes.
                    #
                    # This *might* result in dropping a handle when it could
                    # have been saved to skipped_handles; but half its content
                    # was saved correctly, so re-processing the handle down the
                    # line would create IntegrityErrors when trying to save its
                    # content. This is a rare enough occurrence that dropping
                    # the occasional handle isn't a big deal.
                    pass
                elif any(result.ratelimited or result.connection_error for result in results):
                    skipped_handles.append(handle)

        # Repeatedly iterates over skipped_handles until it's empty.
        while len(skipped_handles):
            # A count of loop passes where a request was completed. If an entire
            # inner for loop is completed without incrementing this variable,
            # the outer while loop exits since all the remaining handles failed.
            # There may be salvageable handles here but there needs to be a
            # point at which the salvage operation quits and this is the one
            # that's used.
            successful_requests = 0

            for index in range(len(skipped_handles) - 1, 0, -1):
                handle = skipped_handles[index]
                result = self.retrieve_relations_from_profile(handle, profile_url)

                # On a second pass, connection errors aren't tolerated, even
                # with dont_discard_bc_wifi True. Connection errors can happen
                # for other, persistent reasons, and if handles that yield
                # connection errors aren't dropped, the program could end up
                # aggressively hammering on the same disconnected hosts in an
                # infinite loop.
                if isinstance(result, Failed_Request):
                    continue

                del skipped_handles[index]
                successful_requests += 1

            if successful_requests == 0:
                self.logger.info("An entire skipped_handles salvage pass completed with no successful connections; "
                                 "giving up on salvage process.")
                exit(0)

    def retrieve_profile(self, handle, profile_page_url):
        """
        Retrieves a profile from the given URL and attempts to save its bio to the
        database.

        :param handle:           A Handle object to use to define the Page object with.
        :type handle:            Page
        :param profile_page_url: The profile URL to retrieve.
        :type profile_page_url:  str
        :return:                 If the request succeeded, then the length of the
                                 profile page's bio in characters; if it failed, a
                                 Failed_Request object.
        :rtype:                  int or Failed_Request
        """
        profile_page, result = self.page_fetcher.instantiate_and_fetch_page(handle, profile_page_url)

        # If the page isn't None and the result is an integer then the fetch
        # succeeded and the page has a bio that can be saved.
        if profile_page is not None and isinstance(result, int) and self.save_profiles:
            self.logger.info("saving bio to database")
            profile_page.save_page(self.data_store)

        return result

    def retrieve_relations_from_profile(self, handle, profile_page_url):
        """
        Retrieves a profile from the given URL, uses it to find the user's
        following/followers pages, and retrieves those in full.

        :param handle:           A Handle object to use to define the Page object with.
        :type handle:            Page
        :param profile_page_url: The profile URL to retrieve.
        :type profile_page_url:  str
        :return:                 If the request succeeded, then the number of
                                 following/followers handles retrieved; if it
                                 failed, a Failed_Request object.
        :rtype:                  int or Failed_Request
        """
        profile_page, result = self.page_fetcher.instantiate_and_fetch_page(handle, profile_page_url)
        if isinstance(result, Failed_Request):
            return result, result
        first_following_page_url, first_followers_page_url = profile_page.generate_initial_relation_page_urls()
        result1 = self.retrieve_relations(handle, first_following_page_url)
        result2 = self.retrieve_relations(handle, first_followers_page_url)
        return result1, result2

    def retrieve_relations(self, handle, first_relation_page_url):
        """
        Retrieves a following/followers page from the given URL, and uses it to fetch
        all the following/followers handles accessible via that page.

        :param handle:           A Handle object to use to define the Page object with.
        :type handle:            Page
        :param profile_page_url: The following/followers URL to retrieve.
        :type profile_page_url:  str
        :return:                 If the request succeeded, then the number of
                                 following/followers handles retrieved; if it
                                 failed, a Failed_Request object.
        :rtype:                  int or Failed_Request
        """
        first_relation_page, result = self.page_fetcher.instantiate_and_fetch_page(handle, first_relation_page_url)

        if isinstance(result, Failed_Request):
            return result

        # A dynamic following/followers page uses infinite scroll to convey all
        # the handles on a single page, so one save action is all that's needed.
        first_relation_page.save_page(self.data_store)
        if first_relation_page.is_dynamic:
            return result

        # A static initial following/followers is used to generate all the
        # following/followers page URLs, which are fetched (and parsed), and
        # stored.
        total_result = 0
        for relation_page_url in first_relation_page.generate_all_relation_page_urls():
            relation_page, result = self.page_fetcher.instantiate_and_fetch_page(handle, relation_page_url)
            if isinstance(result, Failed_Request):
                return result
            relation_page.save_page(self.data_store)
            total_result += result

        return total_result


if __name__ == "__main__":
    main()
