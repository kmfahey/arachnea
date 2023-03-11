#!/usr/bin/python3

import logging
import MySQLdb
import re
import sys
import threading
import types

from arachnea.retrieval import Instance, Page_Fetcher
from arachnea.handles import Handle
from arachnea.succeedfail import Failed_Request, Internal_Exception


class Main_Processor:
    """
    Encapsulates the state and methods needed to run the main processing job of the program.
    """
    __slots__ = ('options', 'args', 'logger_obj', 'data_store_obj', 'save_profiles', 'save_relations',
                 'db_host', 'db_user', 'db_password', 'db_database')

    def __init__(self, options, args, logger_obj, save_profiles, save_relations,
                       db_host, db_user, db_password, db_database):
        """
        Initializes the Main_Processor object.

        :param options:        The options object that is the first return value of
                               optparse.OptionParser.parse_args().
        :type options:         optparse.Values
        :param args:           The program's commandline arguments absent flags; the second
                               return value of optparse.OptionParser.parse_args().
        :type args:            tuple
        :param logger_obj:     The logger object to use to log events.
        :type logger_obj:      logger.Logger
        :param save_profiles:  If the program is in a saving-profiles mode.
        :type save_profiles:   bool
        :param save_relations: If the program is in a saving-followers/following mode.
        :type save_relations:  bool
        """
        self.options = options
        self.args = args
        self.logger_obj = logger_obj
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.db_host = db_host
        self.db_user = db_user
        self.db_password = db_password
        self.db_database = db_database
        self.data_store_obj = Data_Store(self.db_host, self.db_user, self.db_password,
                                         self.db_database, self.logger_obj)

    @classmethod
    def instance_logger_obj(self, name, use_threads=False):
        """
        Instances a logger.Logger object and configures it appropriately.

        :param name:        The name for the Logger object to use when logging.
        :type name:         str
        :param use_threads: If the program is in threaded mode or not.
        :type use_threads:  bool, optional
        """
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

    def process_handles_from_args(self):
        """
        Executes the main logic of the program if the program is processing handles
        from its commandline arguments.

        :return:               False if this is a dry run, True otherwise.
        :rtype:                bool
        """
        # Intializing the needed objects.
        handle_objs_from_args = list()
        handle_re = re.compile("^@([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+)$")
        instances_dict = Instance.fetch_all_instances(self.data_store_obj, self.logger_obj)

        # The save_profiles, save_relations, dont_discard_bc_wifi, and
        # conn_err_wait_time args are passed to the Handle_Processor init, which
        # uses them to instance its captive Page_Fetcher object, which actually uses
        # them.
        handle_processor = Handle_Processor(Data_Store(self.db_host, self.db_user, self.db_password,
                                                       self.db_database, self.logger_obj),
                                            self.logger_obj, instances_dict, save_profiles=self.save_profiles,
                                            save_relations=self.save_relations,
                                            dont_discard_bc_wifi=self.options.dont_discard_bc_wifi,
                                            conn_err_wait_time=self.options.conn_err_wait_time)

        # Iterating across the non-flag arguments, treating each one
        # as a handle (in @user@instance form) and prepping the
        # Handle_Processor.process_handle_iterable iterable argument.
        for handle_str in self.args:
            match = handle_re.match(handle_str)
            if match is None:
                self.logger_obj.error(f"got argument {handle_str} that doesn't parse as a mastodon handle; fatal error")
                exit(1)
            username, host = match.group(1, 2)
            handle = Handle(username=username, host=host)
            handle.fetch_or_set_handle_id(self.data_store_obj)
            handle_objs_from_args.append(handle)

        # If this is a dry run, stop here.
        if self.options.dry_run:
            return False

        handle_processor.process_handle_iterable(handle_objs_from_args, self.data_store_obj)

        return True

    def process_handles_from_db_w_threads(self):
        """
        Executes the main logic of the program if the program is processing handles
        from the database using threaded execution.

        :return:               False if this is a dry run, True otherwise.
        :rtype:                bool
        """

        parallelism_objs = self.set_up_parallelism()

        if self.options.dry_run and not parallelism_objs:
            return False

        data_store_objs = parallelism_objs["data_store_objs"]
        handle_processor_objs = parallelism_objs["handle_processor_objs"]
        handles_lists = parallelism_objs["handles_lists"]

        handles_lists_lens_expr = ", ".join(map(str, map(len, handles_lists)))
        self.logger_obj.info(f"populated handles lists, lengths {handles_lists_lens_expr}")

        thread_objs = list()

        # Instancing & saving the thread objects.
        for index in range(0, self.options.use_threads):
            thread_obj = threading.Thread(target=handle_processor_objs[index].process_handle_iterable,
                                          args=(iter(handles_lists[index]), data_store_objs[index]),
                                          daemon=True)
            thread_objs.append(thread_obj)
            self.logger_obj.info(f"instantiated thread #{index}")

        # Starting the threads.
        for index in range(0, self.options.use_threads):
            thread_objs[index].start()
            self.logger_obj.info(f"started thread #{index}")

        # Waiting for the threads to exit.
        for index in range(0, self.options.use_threads):
            thread_objs[index].join()
            self.logger_obj.info(f"closed thread #{index}")

        return True

    def set_up_parallelism(self):
        """
        Prepares the objects that the main logic of the program (when executing using
        threads) will need to set up threads with parallel execution on parallel data
        sets.

        :return:               A dict containing a list of Data Store objects, a list
                               of Handle Processor objects, and a list of lists of
                               Handle objects, or an empty dict if this is a dry run.
        :rtype:                dict
        """

        # SETTING UP PARALLELISM
        #
        # Each thread needs its own Logger object, its own Data_Store object,
        # its own Handle_Processor object, and its own roughly equal-sized list
        # of handles to process.

        logger_objs = list()
        data_store_objs = list()
        handle_processor_objs = list()
        handles_lists = list()

        for index in range(0, self.options.use_threads):
            threads_logger_obj = self.instance_logger_obj(f"thread#{index}", True)
            logger_objs.append(threads_logger_obj)
            data_store_objs.append(Data_Store(self.db_host, self.db_user, self.db_password,
                                              self.db_database, threads_logger_obj))
            handles_lists.append(list())

        # The instances_dict is shared between threads. This is especially
        # important where it stores an Instance object that is tracking a
        # ratelimit that has been imposed on the program by an instance, or
        # that has loaded a robots.txt file.
        #
        # The program should only need to get a status 429 response once, after
        # which all threads need to respect that ratelimit. Likewise robots.txt
        # should only need to be loaded once, after which all threads should
        # have access to that information.
        instances_dict = Instance.fetch_all_instances(self.data_store_obj, self.logger_obj)

        for index in range(0, self.options.use_threads):
            handle_processor_obj = Handle_Processor(data_store_objs[index], logger_objs[index], instances_dict,
                                                    save_profiles=self.save_profiles,
                                                    save_relations=self.save_relations,
                                                    dont_discard_bc_wifi=self.options.dont_discard_bc_wifi,
                                                    conn_err_wait_time=self.options.conn_err_wait_time)

            handle_processor_objs.append(handle_processor_obj)

        # If this is a dry run, stop here.
        if self.options.dry_run:
            return dict()

        if self.options.fetch_relations_only:
            handles_generator = self.data_store_obj.users_in_profiles_not_in_relations()
        elif self.options.handles_join_profiles:
            handles_generator = self.data_store_obj.users_in_handles_not_in_profiles()
        elif self.options.relations_join_profiles:
            handles_generator = self.data_store_obj.users_in_relations_not_in_profiles()

        # This setup repeatedly iterates across the handles_lists list, appending
        # a handle from the handles_generator to each list in turn, until the
        # generator finally raises StopIteration. This populates the handles_lists
        # lists with equal or nearly equal numbers of handles.
        try:
            while True:
                for index in range(0, self.options.use_threads):
                    this_threads_handles_list = handles_lists[((index + 1) % self.options.use_threads) - 1]
                    this_threads_handles_list.append(next(handles_generator))
        except StopIteration:
            pass

        return {"data_store_objs": data_store_objs,
                "handle_processor_objs": handle_processor_objs,
                "handles_lists": handles_lists}

    def process_handles_from_db_single_thread(self):
        """
        Executes the main logic of the program if the program is processing handles
        from the database without using threads.

        :return:               False if this is a dry run, True otherwise.
        :rtype:                bool
        """
        # Instancing the objects needed.
        instances_dict = Instance.fetch_all_instances(self.data_store_obj, self.main_logger_obj)

        handle_processor = Handle_Processor(Data_Store(self.db_host, self.db_user, self.db_password,
                                                       self.db_database, self.main_logger_obj),
                                            self.main_logger_obj, instances_dict, save_profiles=self.save_profiles,
                                            save_relations=self.save_relations,
                                            dont_discard_bc_wifi=self.options.dont_discard_bc_wifi,
                                            conn_err_wait_time=self.options.conn_err_wait_time)

        # If this is a dry run, stop here.
        if self.options.dry_run:
            return False

        # Getting the correct handles generator depending on arguments.
        if self.options.fetch_relations_only:
            handles_generator = self.data_store_obj.users_in_profiles_not_in_relations()
        elif self.options.handles_join_profiles:
            handles_generator = self.data_store_obj.users_in_handles_not_in_profiles()
        elif self.options.relations_join_profiles:
            handles_generator = self.data_store_obj.users_in_relations_not_in_profiles()

        # Processing the handles. Main loop here.
        handle_processor.process_handle_iterable(handles_generator, self.data_store_obj)

        return True


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

    def process_handle_iterable(self, handle_iterable, data_store_obj):
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
                handle.fetch_or_set_handle_id(data_store_obj)

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


class Data_Store(object):
    """
    Intermediates a connection to the MySQL database.
    """
    __slots__ = 'db_host', 'db_user', 'db_password', 'db_database', 'db_connection', 'db_cursor', 'logger'

    def __init__(self, db_host, db_user, db_password, db_database, logger):
        """
        Instances the Data_Store object.

        :param logger: A Logger object to log events to.
        :type logger:  logging.Logger
        """
        self.db_host = db_host
        self.db_user = db_user
        self.db_password = db_password
        self.db_database = db_database
        self.logger = logger
        self.logger.info("opening connection to database")
        self.db_connection = MySQLdb.Connect(host=self.db_host, user=self.db_user,
                                             password=self.db_password, db=self.db_database)
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
        return self.execute_select_generator(relations_left_join_profiles_sql)

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
        return self.execute_select_generator(profiles_left_join_relations_sql)

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
        return self.execute_select_generator(handles_left_join_profiles_sql)

    def fulltext_profiles_search(self, data_store, query_term_or_terms):
        """
        Execute a fulltext search on the profile_bio_markdown column of the profiles
        table. If query_term_or_terms is a string, it will be used as the argument to
        MATCH ... AGAINST() unmodified. If query_term_or_terms is a tuple, list, set,
        map object, filter object, or generator, the terms will be joined with a boolean
        OR and that string with be the argument to MATCH ... AGAINST(). Returns a list
        of Handle objects (can be 0-length).

        :param data_store:          The Data_Store object to use to contact the database.
        :type data_store:           arachnea.processing.Data_Store
        :param query_term_or_terms: The query term or terms to use as an argument to
                                    MATCH ... AGAINST().
        :type query_term_or_terms:  str, tuple, list, set, map, filter, or
                                    types.GeneratorType
        :return:                    List of 0 or more Handle objects.
        :rtype:                     list
        """
        escape_quotes_tr_d = {ord('"'): '\\"', ord("'"): "\\'"}
        if isinstance(query_term_or_terms, str):
            query_str = '"' + query_terms.translate(escape_quotes_tr_d) + '"'
        elif isinstance(query_term_or_terms, (tuple, list, set, map, filter, types.GeneratorType)):
            query_terms_tr_map = map(lambda term: term.translate(escape_quotes_tr_d), query_terms)
            query_terms_qtd_map = map(lambda term: f'"{term}"', query_terms_tr_map)
            query_str = "'{query_terms}'".format(query_terms=" OR ".join(query_terms_qtd_map)
        search_sql = f"""SELECT handle_id, username, instance FROM profiles
                     WHERE profile_bio_markdown <> '' AND
                           MATCH(profile_bio_markdown) AGAINST({query_str})
                           AND considered = 0;"""
        rows_generator = data_store.execute_select_generator(search_sql)
        return [Handle(handle_id, username, instance) for handle_id, username, instance in rows_generator]

    def execute_select_generator(self, select_sql):
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
        if select_sql.split()[0].upper() != "SELECT":
            raise Internal_Exception("Data_Store.execute_select_generator() method can only execute SELECT statements.")
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
