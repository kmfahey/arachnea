#!/usr/bin/python3

import logging
import time
import urllib
import MySQLdb

from arachnea.entities import Handle, DeletedUser, Page, Instance
from arachnea.outcomes import InternalException, FailedRequest


class PageFetcher:
    """
    An originator of Page objects that executes this workflow:

    * Prepares the request
    * Fails fast if it is unsatisfiable
    * Instances the Page object
    * Has the Page object execute the request
    * If it fails, handles a variety of failed requests in different ways
    * If it succeeds, yields the Page object.
    """
    __slots__ = ('instances_dict', 'data_store_obj', 'logger_obj', 'deleted_users_dict', 'save_profiles',
                 'save_relations', 'dont_discard_bc_wifi', 'conn_err_wait_time')

    def __init__(self, data_store_obj, logger_obj, instances_dict, save_profiles=False, save_relations=False,
                       dont_discard_bc_wifi=False, conn_err_wait_time=0.0):
        """
        Instances the Page_Fetcher object.

        :param data_store_obj:             The Data_Store object to use when saving a
                                           Page or Deleted_User object.
        :type data_store_obj:              Data_Store
        :param logger_obj:                 The Logger object to use to log events.
        :type logger_obj:                  logging.Logger
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
        :type conn_err_wait_time:          float
        """
        self.data_store_obj = data_store_obj
        self.logger_obj = logger_obj
        self.instances_dict = instances_dict
        self.deleted_users_dict = DeletedUser.fetch_all_deleted_users(self.data_store_obj)
        self.save_profiles = save_profiles
        self.save_relations = save_relations
        self.dont_discard_bc_wifi = dont_discard_bc_wifi
        self.conn_err_wait_time = conn_err_wait_time

    def instantiate_and_fetch_page(self, handle_obj, url):
        instance = handle_obj.instance
        if instance in self.instances_dict:
            instance_obj = self.instances_dict[instance]
        else:
            self.instances_dict[instance] = instance_obj = Instance(instance, self.logger_obj,
                                                                    dont_discard_bc_wifi=self.dont_discard_bc_wifi)

        self._handle_reasons_not_to_connect(url, handle_obj, instance_obj)

        # Possibilities for aborting transfer don't apply; proceeding with a
        # normal attempt to load the page.
        instance = urllib.parse.urlparse(url).netloc
        if instance in self.instances_dict:
            instance_obj = self.instances_dict[instance]
        else:
            self.instances_dict[instance] = instance_obj = Instance(instance, self.logger_obj,
                                                                    dont_discard_bc_wifi=self.dont_discard_bc_wifi)
        page_obj = Page(handle_obj, url, self.logger_obj, instance_obj, save_profiles=self.save_profiles,
                        save_relations=self.save_relations, dont_discard_bc_wifi=self.dont_discard_bc_wifi)
        outcome_obj = page_obj.requests_fetch()

        # If the request failed because the page is dynamic (i.e. has a
        # <noscript> tag), trying again using webdriver.
        if isinstance(outcome_obj, FailedRequest) and outcome_obj.is_dynamic:
            self.logger_obj.info(f"loaded {url}: page has <noscript>; loading with webdriver")
            outcome_obj = page_obj.webdriver_fetch()

        if isinstance(outcome_obj, FailedRequest):
            self._handle_failed_request(url, instance, handle_obj, page_obj, outcome_obj)
            return outcome_obj

        # Logging what kind of page was loaded
        if self.save_profiles and page_obj.is_profile:
            self.logger_obj.info(f"loaded {url}: detected profile bio, length {outcome_obj.retrieved_len}")
        elif self.save_relations and page_obj.is_following:
            self.logger_obj.info(f"loaded {url}: found {outcome_obj.retrieved_len} following handles")
        elif self.save_relations and page_obj.is_followers:
            self.logger_obj.info(f"loaded {url}: found {outcome_obj.retrieved_len} followers handles")

        return outcome_obj

    def _handle_reasons_not_to_connect(self, url, handle_obj, instance_obj):
        # There exists a record of this instance_obj in the instances_dict.
        # This might just be to save a RobotsTxt object, or it might show the
        # instance is malfunctioning/suspended/unparseable or is ratelimited.
        if instance_obj is not None and instance_obj.status != 'ingoodstanding':
            if self.save_profiles:
                # If in a profile-saving mode, a handle that turns out to
                # have a bad instance_obj gets a null profile bio saved to the
                # data store. The empty Page for that profile is returned.
                self.logger_obj.info(f"instance_obj {instance_obj.instance_host} on record as {instance_obj.status}; "
                                 f"didn't load {url}; saving null bio to database")
                page_obj = Page(handle_obj, url, self.logger_obj, instance_obj, save_profiles=self.save_profiles,
                                save_relations=self.save_relations, dont_discard_bc_wifi=self.dont_discard_bc_wifi)
                page_obj.save_page(self.data_store_obj)
            else:
                # If in a relations-saving mode, no Page is generated or
                # saved.
                self.logger_obj.info(f"instance_obj {instance_obj.instance_host} on record as {instance_obj.status}; "
                                     f"didn't load {url}")
                page_obj = None
            return FailedRequest(instance_obj.instance_host,
                                 malfunctioning=instance_obj.malfunctioning,
                                 unparseable=instance_obj.unparseable,
                                 suspended=instance_obj.suspended,
                                 page_obj=page_obj)
        elif instance_obj is not None and instance_obj.still_rate_limited():
            # The other case for an unreachable instance_obj is if the program
            # is rate-limited from it.
            self.logger_obj.info(f"instance_obj {instance_obj.instance_host} still rate limited, expires at "
                             f"{instance_obj.rate_limit_expires_isoformat}, didn't load {url}")
            return FailedRequest(instance_obj.instance_host, ratelimited=True, page_obj=None)

        # There exists a record of this user-instance_obj combination in the
        # deleted_users_dict. Handling it.
        elif (handle_obj.username, handle_obj.instance) in self.deleted_users_dict:
            self.logger_obj.info(f"user {handle_obj.handle_in_at_form} known to be deleted; didn't load {url}; "
                                 "saving null bio to database")
            page_obj = Page(handle_obj, url, self.logger_obj, instance_obj, save_profiles=self.save_profiles,
                            save_relations=self.save_relations, dont_discard_bc_wifi=self.dont_discard_bc_wifi)
            page_obj.save_page(self.data_store_obj)
            return FailedRequest(handle_obj.instance, user_deleted=True, page_obj=None)

    def _handle_failed_request(self, url, instance, handle_obj, page_obj, failed_req_obj):
        # Beginning the elaborate process of testing for and handling every
        # possible error case. There's quite a few.

        # BEGIN *inner* big conditional
        if failed_req_obj.ratelimited:

            # The program is rate-limited. Saving that fact to
            # self.instances_dict.
            if instance not in self.instances_dict:
                instance_obj = Instance(instance, self.logger_obj, rate_limited=True,
                                        x_ratelimit_limit=failed_req_obj.x_ratelimit_limit,
                                        dont_discard_bc_wifi=self.dont_discard_bc_wifi)
                self.instances_dict[instance] = instance_obj
            else:
                instance_obj = self.instances_dict[instance]
                instance_obj.set_rate_limit(x_ratelimit_limit=failed_req_obj.x_ratelimit_limit)
            self.logger_obj.info(f"failed to load {url}: rate limited: expires at " +
                             instance_obj.rate_limit_expires_isoformat)

        # The instance_obj malfunctioned.
        elif failed_req_obj.malfunctioning:

            # Saving that fact to the instances_dict.
            if instance in self.instances_dict:
                instance_obj = self.instances_dict[instance]
                instance_obj.attempts += 1
            else:
                instance_obj = Instance(instance, self.logger_obj, attempts=1,
                                        dont_discard_bc_wifi=self.dont_discard_bc_wifi)
                self.instances_dict[instance] = instance_obj

            # Logging the precise type malfunction it was.
            if failed_req_obj.ssl_error:
                self.logger_obj.info(f"failed to load {url}, instance malfunctioning: ssl error "
                                     f"(error #{instance_obj.attempts} for this instance)")
            elif failed_req_obj.too_many_redirects:
                self.logger_obj.info(f"failed to load {url}, instance malfunctioning: too many redirects "
                                     f"(error #{instance_obj.attempts} for this instance)")
            elif failed_req_obj.timeout:
                self.logger_obj.info(f"failed to load {url}, instance malfunctioning: connection timeout "
                                     f"(error #{instance_obj.attempts} for this instance)")
            elif failed_req_obj.connection_error:
                self.logger_obj.info(f"failed to load {url}, instance malfunctioning: connection error "
                                     f"(error #{instance_obj.attempts} for this instance)")
            else:
                self.logger_obj.info(f"failed to load {url}, instance malfunctioning: "
                                     f"got status code {failed_req_obj.status_code} "
                                     f"(error #{instance_obj.attempts} for this instance)")

        elif failed_req_obj.user_deleted:

            # The user has been deleted from the instance_obj. Saving that fact
            # to the data store.
            deleted_user = DeletedUser.from_handle_obj(handle_obj)
            deleted_user.logger_obj = self.logger_obj
            self.deleted_users_dict[handle_obj.username, handle_obj.instance] = deleted_user
            deleted_user.save_deleted_user(self.data_store_obj)
            self.logger_obj.info(f"failed to load {url}: user deleted")

        # Several other kinds of error that only need to be logged.
        elif failed_req_obj.webdriver_error:
            self.logger_obj.info(f"loading {url}: webdriver loading failed with internal error")
        elif failed_req_obj.no_public_posts:
            self.logger_obj.info(f"loaded {url}: no public posts")
        elif failed_req_obj.posts_too_old:
            self.logger_obj.info(f"loaded {url}: posts too old")
        elif failed_req_obj.unparseable:
            self.logger_obj.info(f"loaded {url}: parsing failed")
        elif failed_req_obj.robots_txt_disallowed:
            self.logger_obj.info(f"loading {url}: site's robots.txt does not allow it")

        # The profile gave the program a forwarding address.
        elif failed_req_obj.forwarding_address:
            if failed_req_obj.forwarding_address is True:
                self.logger_obj.info(f"loaded {url}: forwarding page (could not recover handle)")
            else:
                handle_obj = failed_req_obj.forwarding_address
                username, instance = handle_obj.lstrip('@').split('@')
                handle_obj = Handle(username=username, instance=instance)
                handle_obj.save_handle(self.data_store_obj)
                self.logger_obj.info(f"loaded {url}: forwarding page; saved to handles table")
        elif failed_req_obj.unfulfillable_request:
            self.logger_obj.info(f"loading {url}: unfulfillable request")
        else:
            self.logger_obj.info(f"loading {url}: unanticipated error {repr(failed_req_obj)}")
        # END *first* big conditional

        # A connection failure when retrieving a profile normally leads to
        # saving a null profile bio to the data store. The only exception is
        # if --dont-discard-bc-wifi was specified on the commandline.
        if failed_req_obj.connection_error and self.dont_discard_bc_wifi:
            # Handling the case of when the --dont-discard-bc-wifi flag
            # is in effect and a connection error has happened.

            what_fetched = ('profile' if page_obj.is_profile
                            else 'following' if page_obj.is_following
                            else 'followers' if page_obj.is_followers else '???')

            self.logger_obj.info(f"handle {handle_obj.handle_in_at_form}: fetching {what_fetched} returned "
                                 "connection error; but the wifi might've gone out, saving for later")

            # If the WiFi goes out, it's possible for this program to chew
            # through hundreds of passes of the main loop before it's
            # restored. That expends lot of queued handles that can't be
            # recovered until the program is restarted.
            #
            # The --conn-err-wifi-sleep-period flag is used to specify a
            # wait time to sleep for when the (self.dont_discard_bc_wifi and
            # failed_req_obj.connection_error) condition is True.
            if self.conn_err_wait_time:
                time.sleep(self.conn_err_wait_time)
        else:
            page_obj.save_page(self.data_store_obj)


# This class adapted from robotstxt_to_df.py at
# https://github.com/jcchouinard/SEO-Projects/ . Repository has no LICENSE file
# so presuming open availability to reuse and adapt without limitations.
class DataStore(object):
    """
    Intermediates a connection to the MySQL database.
    """
    __slots__ = 'db_host', 'db_user', 'db_password', 'db_database', 'db_connection', 'db_cursor', 'logger_obj'

    def __init__(self, db_host, db_user, db_password, db_database, logger_obj):
        """
        Instances the Data_Store object.

        :param logger_obj: A Logger object to log events to.
        :type logger_obj:  logging.Logger
        """
        self.db_host = db_host
        self.db_user = db_user
        self.db_password = db_password
        self.db_database = db_database
        self.logger_obj = logger_obj
        self.logger_obj.info("opening connection to database")
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
        self.logger_obj.info("selecting handles from relations left join profiles")
        relations_left_join_profiles_sql = """SELECT DISTINCT relation_handle_id, relation_username, relation_instance
                                              FROM relations LEFT JOIN profiles ON relations.relation_handle_id
                                              = profiles.profile_handle_id WHERE profiles.profile_handle_id IS NULL
                                              ORDER BY RAND();"""
        return self._handle_select_generator(relations_left_join_profiles_sql)

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
        self.logger_obj.info("selecting handles from profiles left join relations")
        profiles_left_join_relations_sql = """SELECT profiles.profile_handle_id, username, instance
                                              FROM profiles LEFT JOIN relations
                                              ON profiles.profile_handle_id = relations.profile_handle_id
                                              WHERE relations.profile_handle_id IS NULL ORDER BY RAND();"""
        return self._handle_select_generator(profiles_left_join_relations_sql)

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
        self.logger_obj.info("selecting handles from handles left join profiles")
        handles_left_join_profiles_sql = """SELECT handles.handle_id, handles.username, handles.instance FROM handles
                                            LEFT JOIN profiles ON handles.handle_id = profiles.profile_handle_id
                                            WHERE profiles.profile_handle_id IS NULL ORDER BY RAND();"""
        return self._handle_select_generator(handles_left_join_profiles_sql)

    def fulltext_profiles_search(self, pos_query_strs, neg_query_strs=()):
        """
        Executes a fulltext search on the profile_bio_markdown column of the profiles
        table.

        The results are those where the profile bio matches all terms in the
        pos_query_strs argument, and does not match any of the terms in the
        neg_query_strs argument (if present). pos_query_strs must not be 0-length;
        neg_query_strs may be.

        Returns a list of 2-tuples where the 1st elem is a Handle object and the 2nd
        elem is a str which is the value of the profile_bio_markdown column for that
        handle in the profiles table.

        :param pos_query_strs: A tuple, list or set of one or more boolean expression
                               terms to match against the profile_bio_markdown column.
                               A positive match against *all* the expressions includes
                               that profile from the results.
        :type pos_query_strs:  tuple, list or set
        :param neg_query_strs: A tuple, list or set of zero or more boolean expression
                               terms to match against the profile_bio_markdown column. A
                               negative match against *any* of the expressions excludes
                               that profile from the results.
        :type neg_query_strs:  tuple, list or set
        :return:               List of 0 or more 2-tuples, where each tuple is a Handle
                               object and the profile_bio_markdown value string.
        :rtype:                list
        """
        escape_quotes_tr_d = {ord('"'): '\\"', ord("'"): "\\'"}

        def _format_query_str(query_str):
            query_str = query_str.translate(escape_quotes_tr_d)
            query_str = f"'{query_str}'"
            return f"MATCH(profile_bio_markdown) AGAINST({query_str})"

        if len(pos_query_strs) == 0:
            raise InternalException("DataStore.fulltext_profiles_search() called with a zero-length pos_query_strs "
                                    "argument.")

        # If the sequence is 0-length str.join() returns the null string.
        pos_bool_sql = " AND ".join(map(_format_query_str, pos_query_strs))
        neg_bool_sql = " OR ".join(map(_format_query_str, neg_query_strs))

        if neg_bool_sql:
            match_boolean_sql = f"{pos_bool_sql} AND NOT ({neg_bool_sql})"
        else:
            match_boolean_sql = pos_bool_sql

        search_sql = f"""SELECT profile_handle_id, username, instance, profile_bio_markdown FROM profiles
                         WHERE profile_bio_markdown <> ''
                               AND {match_boolean_sql}
                               AND considered = 0;"""
        return [(Handle(handle_id=handle_id, username=username, instance=instance), profile_bio_markdown)
                for handle_id, username, instance, profile_bio_markdown in self.execute(search_sql)]

    def update_profiles_set_considered(self, handles_in_at_form, considered):
        """
        Updates the profiles table, setting considered = {considered argument} where the
        handle_in_at_form is one of the handles in the handles argument.

        :param handles_in_at_form: A sequence of strs, each of which is a mastodon
                                   handle in @ form.
        :type handles_in_at_form:  tuple, list, set, map, filter, or types.GeneratorType
        :param considered:         The new value to set the `considered` BOOLEAN column
                                   to; either 0, 1, False, or True.
        :type considered:          int or bool
        :return:                   The number of rows affected by the UPDATE statement.
        :rtype:                    int
        """
        # Validating the considered argument.
        if considered not in (0.0, 1.0, 0, 1, False, True):
            raise InternalException("the 'considered' argument must be 0, 1, False, or True")
        considered = int(considered)
        iter_count = 0

        # Validating the handles argument.
        for handle_in_at_form in handles_in_at_form:
            if not Handle.validate_handle(handle_in_at_form):
                raise InternalException(f"the 'handles' argument must consist of a sequence of strs "
                                         f"that match the regex {Handle.handle_re.pattern}; "
                                         f"element #{iter_count} was '{handle_in_at_form}'")
            iter_count += 1

        # Building the SQL statement.
        handles_list_sql = "({handles_list})".format(handles_list=', '.join(f"'{handle_in_at_form}'"
                                                                            for handle_in_at_form
                                                                            in handles_in_at_form))

        # Using CONCAT to assemble the username and instance column values into
        # a handle_in_at_form string and then IN to test it for membership in a list of all
        # the handles (which can number 100 or more). Less complex than testing
        # username=X and instance=Y or username=A and instance=B or ... etc. for
        # all handles.
        update_sql = f"""UPDATE profiles SET considered = {considered}
                         WHERE CONCAT('@', username, '@', instance) IN {handles_list_sql};"""

        self.execute(update_sql)

        # Returning the # of affected rows.
        return self.db_cursor.rowcount

    def _handle_select_generator(self, select_sql):
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
            raise InternalException("Data_Store.execute_select_generator() method can only execute SELECT statements.")
        self.db_cursor.execute(select_sql)
        row = self.db_cursor.fetchone()
        while row is not None:
            yield Handle(handle_id=row[0], username=row[1], instance=row[2])
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
