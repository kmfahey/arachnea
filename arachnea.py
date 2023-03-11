#!/usr/bin/python3

import decouple
import optparse

from arachnea.processing import Main_Processor


db_host = 'localhost'
db_user = decouple.config('DB_USER')
db_password = decouple.config('DB_PASSWORD')
db_database = 'arachnea'


# Setting up the options accepted by the program on the commandline
parser = optparse.OptionParser()
parser.add_option("-C", "--handles-from-args", action="store_true", default=False, dest="handles_from_args",
                  help="skip querying the database for handles, instead process only the handles specified on the "
                       "commandline")
parser.add_option("-H", "--handles-join-profiles", action="store_true", default=False, dest="handles_join_profiles",
                  help="when fetching profiles, utilize handles that are present in the `handles` table but are not "
                       "present in the `profiles` table")
parser.add_option("-R", "--relations-join-profiles", action="store_true", default=False, dest="relations_join_profiles",
                  help="when fetching profiles, utilize handles that are present in the `relations` table but are "
                       "not present in the `profiles` table")
parser.add_option("-p", "--fetch-profiles-only", action="store_true", default=False, dest="fetch_profiles_only",
                  help="fetch profiles only, disregard following & followers pages")
parser.add_option("-q", "--fetch-relations-only", action="store_true", default=False, dest="fetch_relations_only",
                  help="fetch following & followers pages only, disregard profiles")
parser.add_option("-r", "--fetch-profiles-and-relations", action="store_true", default=False,
                  dest="fetch_profiles_and_relations", help="fetch both profiles and following & followers pages")

parser.add_option("-t", "--use-threads", action="store", default=0, type="int", dest="use_threads",
                  help="use the specified number of threads")
parser.add_option("-w", "--dont-discard-bc-wifi", action="store_true", default=False, dest="dont_discard_bc_wifi",
                  help="when loading a page leads to a connection error, assume it's the wifi and don't store a null "
                       "bio, rather save it for later and try again")
parser.add_option("-W", "--conn-err-wait-time", action="store", default=0.0, type="float",
                  dest="conn_err_wait_time", help="when loading a page leads to a connection error, and the "
                                                  "-w flag was specified, sleep the specified number of seconds "
                                                  "before resuming the web spidering")
parser.add_option("-x", "--dry-run", action="store_true", default=False, dest="dry_run",
                  help="don't fetch anything, just load data structures from the database and then exit")


def main():
    """
    The main logic of the program. Parses the commandline arguments, validates the
    flags specified, then executes either processing handles from the commandline,
    processing handles from the database using threads, or processing handles from
    the database without using threads, depending on the commandline flags.

    :return: None
    :rtype:  types.NoneType
    """
    (options, args) = parser.parse_args()

    # Instance the main logger. This is the only logger needed unless threaded mode is used.
    main_logger_obj = Main_Processor.instance_logger_obj("main", options.use_threads)

    validate_cmdline_flags(options, args, main_logger_obj)

    log_cmdline_flags(options, main_logger_obj)

    save_profiles = (options.fetch_profiles_only or options.fetch_profiles_and_relations)
    save_relations = (options.fetch_relations_only or options.fetch_profiles_and_relations)

    # FIXME add database-searching mode and database-matching-rows-clearing mode

    # The three main cases are processing handles from the commandline,
    # processing handles from the database in a threaded fashion,
    # and processing handles from the database in a single-tasking fashion.

    main_processor_obj = Main_Processor(options, args, main_logger_obj, save_profiles, save_relations,
                                        db_host, db_user, db_password, db_database)

    if options.handles_from_args:
        main_processor_obj.process_handles_from_args()
    elif options.use_threads:
        main_processor_obj.process_handles_from_db_w_threads()
    else:
        main_processor_obj.process_handles_from_db_single_thread()


def validate_cmdline_flags(options, args, logger_obj):
    """
    Validates the commandline flags received. Checks for invalid combinations of
    flags. If an invalid combination is found, an error message is printed and the
    program exits with status 1.

    :param options:    The options object that is the first return value of
                       optparse.OptionParser.parse_args().
    :type options:     optparse.Values
    :param logger_obj: The logger object to use to log events.
    :type logger_obj:  logger.Logger
    :return:           None
    :rtype:            types.NoneType
    """
    # Argument integrity check; catching illegal combinations of commandline
    # arguments and emitting the appropriate error messages.
    if (not options.fetch_profiles_only and not options.fetch_relations_only
            and not options.fetch_profiles_and_relations):
        print("please specify one of either -p, -q or -r on the commandline to choose the scraping mode")
        exit(1)
    elif options.fetch_profiles_only and options.fetch_relations_only or \
            options.fetch_profiles_only and options.fetch_profiles_and_relations or \
            options.fetch_relations_only and options.fetch_profiles_and_relations:
        print("more than just one of -p, -q and -r specified on the commandline; please supply only one")
        exit(1)
    elif ((options.fetch_profiles_only or options.fetch_profiles_and_relations)
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
        print("-t and -x were both specified; cannot run in these two modes simultaneously")
        exit(1)
    elif options.conn_err_wait_time and not options.dont_discard_bc_wifi:
        print("-W was specified but -w was not; -W value is unusable if not in -w mode")
        exit(1)
    elif options.conn_err_wait_time and options.conn_err_wait_time < 0:
        print(f"argument for -W is a negative number; can't sleep {options.conn_err_wait_time} seconds")
        exit(1)


def log_cmdline_flags(options, logger_obj):
    """
    Logs the commandline flags specified.

    :return:           None
    :rtype:            types.NoneType
    """
    # Logging the commandline flags received.
    if options.fetch_profiles_only:
        logger_obj.info("got -p flag, entering profiles-only mode")
    elif options.fetch_relations_only:
        logger_obj.info("got -q flag, entering relations-only mode")
    else:
        logger_obj.info("got -r flag, entering profiles & relations mode")

    if options.relations_join_profiles:
        logger_obj.info("got -R flag, loading handles present in the relations table "
                                     "but absent from the profiles tables")
    elif options.handles_join_profiles:
        logger_obj.info("got -H flag, loading handles present in the handles table "
                                     "but absent from the profiles table")
    elif options.fetch_relations_only:
        logger_obj.info("got -q flag, loading handles present in the profiles table "
                                     "but absent from the relations table")

    if options.dry_run:
        logger_obj.info("got -x flag, doing a dry run")

    if options.dont_discard_bc_wifi:
        logger_obj.info("got -w flag, saving handles for later if a generic connection error occurs")
    if options.conn_err_wait_time:
        logger_obj.info(f"got -W flag, when saving handles that were unfetchable due to a connection error, "
                        f"will sleep {options.conn_err_wait_time} seconds each time")


if __name__ == "__main__":
    main()
