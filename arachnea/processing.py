#!/usr/bin/python3

import logging
import sys
import threading
import collections

from arachnea.retrieval import Instance, PageFetcher, DataStore
from arachnea.outcomes import InternalException, SuccessfulRequest, FailedRequest, RELATIONS


ParallelismPrereqs = collections.namedtuple("ParallelismPrereqs", ("data_store_objs", "handle_processor_objs", "handles_lists"))


class MainProcessor:
    """
    Encapsulates the state and methods needed to run the main processing job of the program.
    """
    __slots__ = ('logger_obj', 'db_host', 'db_user', 'db_password', 'db_database', 'data_store_obj', 'handles_input',
                 'save_profiles', 'save_relations', 'handles_join_profiles', 'relations_join_profiles',
                 'fetch_relations_only', 'threads_count', 'dont_discard_bc_wifi', 'conn_err_wait_time', 'dry_run')

    def __init__(self, logger_obj, db_host, db_user, db_password, db_database, handles_input=(), save_profiles=False,
                 save_relations=False, handles_join_profiles=False, relations_join_profiles=False,
                 fetch_relations_only=False, threads_count=0, dont_discard_bc_wifi=False, conn_err_wait_time=0.0,
                 dry_run=False):
        """
        Initializes the Main_Processor object.

        :param logger_obj:              The Logger object to use to log events.
        :type logger_obj:               logging.Logger
        :param save_profiles:           If the program is in a mode where it saves
                                        profiles.
        :type save_profiles:            bool
        :param save_relations:          If the program is in a mode where it saves
                                        followers/following accounts.
        :type save_relations:           bool
        :param handles_input:           A list of Handle objects used in the
                                        process_handles_from_args() method.
        :type handles_input:            collections.abc.Sequence
        :param save_profiles:           True if the program is in a mode where it
                                        saves profiles, False otherwise.
        :type save_profiles:            bool
        :param save_relations:          True if the program is in a mode where it
                                        saves following/followers accounts, False
                                        otherwise.
        :type save_relations:           bool
        :param handles_join_profiles:   True if the program is sourcing its handles to
                                        process from handles that are present in the
                                        handles table but absent from the profiles
                                        table, False otherwise.
        :type handles_join_profiles:    bool
        :param relations_join_profiles: True if the program is sourcing its handles to
                                        process from handles that are present in the
                                        relations table but absent from the profiles
                                        table, False otherwise.
        :type relations_join_profiles:  bool
        :param fetch_relations_only:    True if the program is fetching only
                                        following/followers data and skipping profile
                                        bios, False otherwise. In this mode it will
                                        source handles to process from handles that are
                                        in the profiles table but not in the relations
                                        table.
        :type fetch_relations_only:     bool
        :param threads_count:           The number of threads to use when processing
                                        handles. If the value is 0 or 1, the threading
                                        module will not be used.
        :type threads_count:            int
        :param dont_discard_bc_wifi:    True if the program should respond to a
                                        connection error by saving the handle, False if
                                        it should respond by saving a null bio to the
                                        profiles table.
        :type dont_discard_bc_wifi:     bool
        :param conn_err_wait_time:      If nonzero, and the dont_discard_bc_wifi
                                        argument is True, then when a connection error
                                        occurs, the program will sleep this number of
                                        seconds before continuing the algorithm.
        :type conn_err_wait_time:       float
        :param dry_run=False:           True if the program is running a dry run,
                                        False otherwise.
        :type dry_run=False:            bool
        """
        self.logger_obj = logger_obj
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.db_host = db_host
        self.db_user = db_user
        self.db_password = db_password
        self.db_database = db_database
        self.data_store_obj = DataStore(self.db_host, self.db_user, self.db_password,
                                        self.db_database, self.logger_obj)
        self.conn_err_wait_time = conn_err_wait_time
        self.dont_discard_bc_wifi = dont_discard_bc_wifi
        self.dry_run = dry_run
        self.fetch_relations_only = fetch_relations_only
        self.handles_input = handles_input
        self.handles_join_profiles = handles_join_profiles
        self.relations_join_profiles = relations_join_profiles
        self.threads_count = threads_count

    @classmethod
    def instance_logger_obj(cls, name, use_threads=False, no_output=False):
        """
        Instances a logging.Logger object and configures it appropriately.

        :param name:        The name for the Logger object to use when logging.
        :type name:         str
        :param use_threads: If the program is in threaded mode or not.
        :type use_threads:  bool, optional
        :param no_output:   If True, configure the Logger object not to print,
                            if False it prints to stdout.
        :type:              bool
        :return:            A logger.Logger object.
        :rtype:             logger.Logger
        """
        logger_obj = logging.getLogger(name=name)
        logger_obj.setLevel(logging.INFO)
        if no_output:
            handler = logging.NullHandler()
        else:
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

        :return: False if this is a dry run, True otherwise.
        :rtype:  bool
        """
        # Intializing the needed objects.
        handle_objs_from_args = list()
        instances_dict = Instance.fetch_all_instances(self.data_store_obj, self.logger_obj)

        # The save_profiles, save_relations, dont_discard_bc_wifi, and
        # conn_err_wait_time args are passed to the Handle_Processor init, which
        # uses them to instance its captive Page_Fetcher object, which actually uses
        # them.
        handle_processor = HandleProcessor(DataStore(self.db_host, self.db_user, self.db_password,
                                                     self.db_database, self.logger_obj),
                                           self.logger_obj, instances_dict, save_profiles=self.save_profiles,
                                           save_relations=self.save_relations,
                                           dont_discard_bc_wifi=self.dont_discard_bc_wifi,
                                           conn_err_wait_time=self.conn_err_wait_time)

        # Iterating across the non-flag arguments, treating each one
        # as a handle_obj (in @user@instance form) and prepping the
        # Handle_Processor.process_handle_iterable iterable argument.
        for handle_obj in self.handles_input:
            handle_obj.fetch_or_set_handle_id(self.data_store_obj)
            handle_objs_from_args.append(handle_obj)

        # If this is a dry run, stop here.
        if self.dry_run:
            return False

        handle_processor.process_handle_iterable(handle_objs_from_args, self.data_store_obj)

        return True

    def process_handles_from_db_w_threads(self):
        """
        Executes the main logic of the program if the program is processing handles
        from the database using threaded execution.

        :return: False if this is a dry run, True otherwise.
        :rtype:  bool
        """

        prq = self.set_up_parallelism()

        if self.dry_run:
            return False

        handles_lists_lens_expr = ", ".join(map(str, map(len, prq.handles_lists)))
        self.logger_obj.info(f"populated handles lists, lengths {handles_lists_lens_expr}")

        thread_objs = list()

        # Instancing & saving the thread objects.
        for index in range(0, self.threads_count):
            thread_obj = threading.Thread(target=prq.handle_processor_objs[index].process_handle_iterable,
                                          args=(iter(prq.handles_lists[index]), prq.data_store_objs[index]),
                                          daemon=True)
            thread_objs.append(thread_obj)
            self.logger_obj.info(f"instantiated thread #{index}")

        # Starting the threads.
        for index in range(0, self.threads_count):
            thread_objs[index].start()
            self.logger_obj.info(f"started thread #{index}")

        # Waiting for the threads to exit.
        for index in range(0, self.threads_count):
            thread_objs[index].join()
            self.logger_obj.info(f"closed thread #{index}")

        return True

    def set_up_parallelism(self):
        """
        Prepares the objects that the main logic of the program (when executing using
        threads) will need to set up threads with parallel execution on parallel data
        sets.

        :return: A dict containing a list of Data Store objects, a list of Handle
                 Processor objects, and a list of lists of Handle objects, or an empty
                 dict if this is a dry run.
        :rtype:  dict
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

        for index in range(0, self.threads_count):
            threads_logger_obj = self.instance_logger_obj(f"thread#{index}", True)
            logger_objs.append(threads_logger_obj)
            data_store_objs.append(DataStore(self.db_host, self.db_user, self.db_password,
                                             self.db_database, threads_logger_obj))
            handles_lists.append(list())

        # The instances_dict is shared between threads. This is especially
        # important where it stores an Instance object that is tracking a
        # ratelimit that has been imposed on the program by an instance, or
        # that has loaded a robots.txt file.
        #
        # The program should only need to get a status 429 response once, after
        # which all threads need to respect that ratelimit. Likewise, robots.txt
        # should only need to be loaded once, after which all threads should
        # have access to that information.
        instances_dict = Instance.fetch_all_instances(self.data_store_obj, self.logger_obj)

        for index in range(0, self.threads_count):
            handle_processor_obj = HandleProcessor(data_store_objs[index], logger_objs[index], instances_dict,
                                                   save_profiles=self.save_profiles,
                                                   save_relations=self.save_relations,
                                                   dont_discard_bc_wifi=self.dont_discard_bc_wifi,
                                                   conn_err_wait_time=self.conn_err_wait_time)

            handle_processor_objs.append(handle_processor_obj)

        # If this is a dry run, stop here.
        if self.dry_run:
            return ParallelismPrereqs([], [], [])

        if self.fetch_relations_only:
            handles_generator = self.data_store_obj.users_in_profiles_not_in_relations()
        elif self.handles_join_profiles:
            handles_generator = self.data_store_obj.users_in_handles_not_in_profiles()
        elif self.relations_join_profiles:
            handles_generator = self.data_store_obj.users_in_relations_not_in_profiles()
        else:
            raise InternalException("none of fetch_relations_only, handles_join_profiles, or relations_join_profiles "
                                    "defined; don't know where to get handles from")

        # This setup repeatedly iterates across the handles_lists list, appending
        # a handle from the handles_generator to each list in turn, until the
        # generator finally raises StopIteration. This populates the handles_lists
        # lists with equal or nearly equal numbers of handles.
        try:
            while True:
                for index in range(0, self.threads_count):
                    this_threads_handles_list = handles_lists[((index + 1) % self.threads_count) - 1]
                    this_threads_handles_list.append(next(handles_generator))
        except StopIteration:
            pass

        return ParallelismPrereqs(data_store_objs, handle_processor_objs, handles_lists)

    def process_handles_from_db_single_thread(self):
        """
        Executes the main logic of the program if the program is processing handles
        from the database without using threads.

        :return: False if this is a dry run, True otherwise.
        :rtype:  bool
        """
        # Instancing the objects needed.
        instances_dict = Instance.fetch_all_instances(self.data_store_obj, self.logger_obj)

        handle_processor = HandleProcessor(DataStore(self.db_host, self.db_user, self.db_password,
                                                     self.db_database, self.logger_obj),
                                           self.logger_obj, instances_dict, save_profiles=self.save_profiles,
                                           save_relations=self.save_relations,
                                           dont_discard_bc_wifi=self.dont_discard_bc_wifi,
                                           conn_err_wait_time=self.conn_err_wait_time)

        # If this is a dry run, stop here.
        if self.dry_run:
            return False

        # Getting the correct handles generator depending on arguments.
        if self.fetch_relations_only:
            handles_generator = self.data_store_obj.users_in_profiles_not_in_relations()
        elif self.handles_join_profiles:
            handles_generator = self.data_store_obj.users_in_handles_not_in_profiles()
        elif self.relations_join_profiles:
            handles_generator = self.data_store_obj.users_in_relations_not_in_profiles()
        else:
            raise InternalException("none of fetch_relations_only, handles_join_profiles, or relations_join_profiles "
                                    "defined; don't know where to get handles from")

        # Processing the handles. Main loop here.
        handle_processor.process_handle_iterable(handles_generator, self.data_store_obj)

        return True

    def fulltext_profiles_search(self, fulltext_pos_query, fulltext_neg_query=''):
        if fulltext_neg_query:
            return self.data_store_obj.fulltext_profiles_search(fulltext_pos_query, fulltext_neg_query)
        else:
            return self.data_store_obj.fulltext_profiles_search(fulltext_pos_query)

    def update_profiles_set_considered(self, handles, considered):
        return self.data_store_obj.update_profiles_set_considered(handles, considered)


class HandleProcessor:
    """
    Implements a class for processing a list of handles and fetching the profile,
    relations, or both for each one depending on configuration.
    """
    __slots__ = ('data_store_obj', 'logger_obj', 'instances_dict', 'save_from_wifi', 'last_time_point',
                 'current_time_point', 'save_profiles', 'save_relations', 'page_fetcher', 'dont_discard_bc_wifi',
                 'conn_err_wait_time')

    def __init__(self, data_store_obj, logger_obj, instances_dict, save_profiles=False, save_relations=False,
                       dont_discard_bc_wifi=False, conn_err_wait_time=0.0):
        """
        Initializes the Handle_Processor object.

        :param data_store_obj:       The Data_Store object to use to contact the
                                     database.
        :type data_store_obj:        DataStore
        :param logger_obj:           The Logger object to use to log events.
        :type logger_obj:            logging.Logger
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
        self.data_store_obj = data_store_obj
        self.logger_obj = logger_obj
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
        self.page_fetcher = PageFetcher(data_store_obj, self.logger_obj, instances_dict, save_profiles=save_profiles,
                                        save_relations=save_relations, dont_discard_bc_wifi=self.dont_discard_bc_wifi,
                                        conn_err_wait_time=self.conn_err_wait_time)

    def process_handle_iterable(self, handle_iterable, data_store_obj):
        """
        Iterates over a provided iterable that yields Handle objects, fetching &
        processing the appropriate page(s) for each one. This method is written to be
        the target of a threading.Thread object, so it has no return value.

        :param handle_iterable: An iterable that's yields Handle objects.
        :type handle_iterable:  collections.abc.Iterable
        :param data_store_obj:  The Data_Store object to contact the database with.
        :type:                  Data_Store
        :return:                None
        :rtype:                 types.NoneType
        """
        skipped_handles = list()

        for handle_obj in handle_iterable:
            # Get a handle_id, which inserts this handle_obj into the handles table
            # as a side effect.
            if not handle_obj.handle_id:
                handle_obj.fetch_or_set_handle_id(data_store_obj)

            profile_url = handle_obj.profile_url
            outcome_obj = outcome_objs = None
            try:
                if self.save_profiles and not self.save_relations:
                    # Retrieves the profile page and saves its bio text to the
                    # database if possible.
                    outcome_obj = self.retrieve_profile(handle_obj, profile_url)
                else:
                    # Retrieves the profile page if possible, uses it to find
                    # the profile's following/followers pages, retrieves those
                    # pages in full if possible and saves them to the database.
                    outcome_objs = self.retrieve_relations_from_profile(handle_obj, profile_url)
            except InternalException:
                continue

            if outcome_obj is not None and isinstance(outcome_obj, FailedRequest):
                if outcome_obj.ratelimited or outcome_obj.connection_error:
                    skipped_handles.append(handle_obj)
            elif outcome_objs is not None and any(isinstance(outcome_obj, FailedRequest)
                                                  for outcome_obj in outcome_objs):
                if any(isinstance(outcome_obj, SuccessfulRequest) for outcome_obj in outcome_objs):
                    # So within the retrieve_relations_from_profile() call, one
                    # retrieve_relations() call succeeded and one failed. That
                    # situation is too complex to reach any conclusions from so
                    # the program just passes.
                    #
                    # This *might* result in dropping a Handle object when
                    # it could have been saved to skipped_handles; but half
                    # its content was saved correctly, so re-processing the
                    # handle_obj down the line would create IntegrityErrors
                    # when trying to save its content. This is a rare enough
                    # occurrence that dropping the occasional handle_obj isn't a
                    # big deal.
                    pass
                elif any(outcome_obj.ratelimited or outcome_obj.connection_error for outcome_obj in outcome_objs):
                    skipped_handles.append(handle_obj)

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
                handle_obj = skipped_handles[index]
                outcome_obj = self.retrieve_relations_from_profile(handle_obj, handle_obj.profile_url)

                # On a second pass, connection errors aren't tolerated, even
                # with dont_discard_bc_wifi=True. Connection errors can happen
                # for other, persistent reasons, and if handles that yield
                # connection errors aren't dropped, the program could end up
                # aggressively hammering on the same disconnected hosts in an
                # infinite loop.
                if isinstance(outcome_obj, FailedRequest):
                    continue

                del skipped_handles[index]
                successful_requests += 1

            if successful_requests == 0:
                self.logger_obj.info("An entire skipped_handles salvage pass completed with no successful connections; "
                                 "giving up on salvage process.")
                exit(0)

    def retrieve_profile(self, handle_obj, profile_page_url):
        """
        Retrieves a profile from the given URL and attempts to save its bio to the
        database.

        :param handle_obj:       A Handle object to use to define the Page object with.
        :type handle_obj:        Page
        :param profile_page_url: The profile URL to retrieve.
        :type profile_page_url:  str
        :return:                 An object of a RequestOutcome subclass. If the request
                                 succeeded, then a SuccessfulRequest object; otherwise,
                                 a FailedRequest object.
        :rtype:                  RequestOutcome
        """
        outcome_obj = self.page_fetcher.instantiate_and_fetch_page(handle_obj, profile_page_url)

        # If the page isn't None and the result is an integer then the fetch
        # succeeded and the page has a bio that can be saved.
        if outcome_obj.page_obj is not None and isinstance(outcome_obj, SuccessfulRequest) and self.save_profiles:
            self.logger_obj.info("saving bio to database")
            outcome_obj.page_obj.save_page(self.data_store_obj)

        return outcome_obj

    def retrieve_relations_from_profile(self, handle_obj, profile_page_url):
        """
        Retrieves a profile from the given URL, uses it to find the user's
        following/followers pages, and retrieves those in full.

        :param handle_obj:       A Handle object to use to define the Page object with.
        :type handle_obj:        Page
        :param profile_page_url: The profile URL to retrieve.
        :type profile_page_url:  str
        :return:                 An object of a RequestOutcome subclass. If the request
                                 succeeded, then a SuccessfulRequest object; otherwise,
                                 a FailedRequest object.
        :rtype:                  RequestOutcome
        """
        outcome_obj = self.page_fetcher.instantiate_and_fetch_page(handle_obj, profile_page_url)
        if isinstance(outcome_obj, FailedRequest):
            return outcome_obj, outcome_obj
        first_following_page_url, first_followers_page_url = outcome_obj.page_obj.generate_initial_relation_page_urls()
        following_outcome_obj = self.retrieve_relations(handle_obj, first_following_page_url)
        followers_outcome_obj = self.retrieve_relations(handle_obj, first_followers_page_url)
        return following_outcome_obj, followers_outcome_obj

    def retrieve_relations(self, handle_obj, first_relation_page_url):
        """
        Retrieves a following/followers page from the given URL, and uses it to fetch
        all the following/followers handles accessible via that page.

        :param handle_obj:              A Handle object to use to define the Page object
                                        with.
        :type handle_obj:               Page
        :param first_relation_page_url: The following/followers URL to retrieve.
        :type first_relation_page_url:  str
        :return:                        An object of a RequestOutcome subclass. If the
                                        request succeeded, then a SuccessfulRequest
                                        object; otherwise, a FailedRequest object.
        :rtype:                         RequestOutcome
        """
        outcome_obj = self.page_fetcher.instantiate_and_fetch_page(handle_obj, first_relation_page_url)

        if isinstance(outcome_obj, FailedRequest):
            return outcome_obj

        first_relation_page = outcome_obj.page_obj

        # A dynamic following/followers page uses infinite scroll to convey all
        # the handles on a single page, so one save action is all that's needed.
        first_relation_page.save_page(self.data_store_obj)
        if first_relation_page.is_dynamic:
            return outcome_obj

        # A static initial following/followers is used to generate all the
        # following/followers page URLs, which are fetched (and parsed), and
        # stored.

        relations_count = 0

        last_page_obj = None

        for relation_page_url in first_relation_page.generate_all_relation_page_urls():
            outcome_obj = self.page_fetcher.instantiate_and_fetch_page(handle_obj, relation_page_url)
            if isinstance(outcome_obj, FailedRequest):
                return outcome_obj
            outcome_obj.page_obj.save_page(self.data_store_obj)
            last_page_obj = outcome_obj.page_obj
            relations_count += outcome_obj.retrieved_len

        return SuccessfulRequest(last_page_obj.instance, retrieved_len=relations_count, retrieved_type=RELATIONS,
                                 page_obj=last_page_obj)
