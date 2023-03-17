#!/usr/bin/python3

import decouple
import argparse
import shutil
import collections
import sys

from arachnea.processing import MainProcessor
from arachnea.handles import Handle


DB_HOST = 'localhost'
DB_USER = decouple.config('DB_USER')
DB_PASSWORD = decouple.config('DB_PASSWORD')
DB_DATABASE = 'arachnea'


# Setting up the options accepted by the program on the commandline
parser = argparse.ArgumentParser("arachnea")

main_mode_args_group = parser.add_mutually_exclusive_group()

main_mode_args_group.add_argument("-s", "--web-spider", action="store_true", default=False, dest="web_spider",
                                  help="Operate in web spider mode, recursively scraping mastodon profiles for bios "
                                       "and following/followers profile links, which are chased and those bios are "
                                       "scraped in turn.")
main_mode_args_group.add_argument("-f", "--fulltext-search", action="store_true", default=False, dest="fulltext_search",
                                  help="Operate in database fulltext search mode, accepting query terms on the "
                                       "commandline and querying the profile table for profiles with matching bios, "
                                       "which are then displayed.")
main_mode_args_group.add_argument("-m", "--mark-handles-considered", action="store_true", default=False,
                                  dest="mark_handles_considered_eq_1",
                                  help="Operate in mark handles considered mode, accepting handles in @ form on "
                                       "standard input, and setting considered = 1 on each corresponding row in the "
                                       "profiles table; rows with considered = 1 don't show up in fulltext searches.")
main_mode_args_group.add_argument("-M", "--mark-handles-not-considered", action="store_true", default=False,
                                  dest="mark_handles_considered_eq_0",
                                  help="Operate in mark handles NOT considered mode, accepting handles in @ form on "
                                       "standard input, and setting considered = 0 on each corresponding row in the "
                                       "profiles table; a row must have considered = 0 to show up in fulltext "
                                       "searches.")

### WEB SPIDER OPTIONS ###
spider_handles_from_group = parser.add_mutually_exclusive_group()


spider_handles_from_group.add_argument("-C", "--handles-from-args", action="store_true", default=False,
                                       dest="handles_from_args",
                                       help="In web spider mode, skip querying the database for handles, instead "
                                            "process only the handles specified on the commandline.")
spider_handles_from_group.add_argument("-H", "--handles-join-profiles", action="store_true", default=False,
                                       dest="handles_join_profiles",
                                       help="In web spider mode, when fetching profiles, utilize handles that are "
                                            "present in the `handles` table but are not present in the `profiles` "
                                            "table.")
spider_handles_from_group.add_argument("-R", "--relations-join-profiles", action="store_true", default=False,
                                       dest="relations_join_profiles",
                                       help="In web spider mode, when fetching profiles, utilize handles that are "
                                            "present in the `relations` table but are not present in the `profiles` "
                                            "table.")

spider_to_fetch_group = parser.add_mutually_exclusive_group()

spider_to_fetch_group.add_argument("-p", "--fetch-profiles-only", action="store_true", default=False,
                                   dest="fetch_profiles_only",
                                   help="In web spider mode, fetch profiles only, disregard following & followers "
                                        "pages.")
spider_to_fetch_group.add_argument("-q", "--fetch-relations-only", action="store_true", default=False,
                                   dest="fetch_relations_only",
                                   help="In web spider mode, fetch following & followers pages only, disregard "
                                        "profiles.")
spider_to_fetch_group.add_argument("-r", "--fetch-profiles-and-relations", action="store_true", default=False,
                                   dest="fetch_profiles_and_relations",
                                   help="In web spider mode, fetch both profiles and following & followers pages.")

parser.add_argument("handles", action="store", default=(), type=Handle, nargs="*",
                    help="Zero or more handles, in @username@instance form.")

parser.add_argument("-t", "--threads-count", action="store", default=0, type=int, dest="threads_count",
                    help="In web spider mode, use the specified number of threads. (If the argument is 0 or 1, "
                         "threading is not used.")
parser.add_argument("-w", "--dont-discard-bc-wifi", action="store_true", default=False, dest="dont_discard_bc_wifi",
                    help="In web spider mode, when loading a page leads to a connection error, assume it's the wifi "
                         "and don't store a null bio, rather save it for later and try again.")
parser.add_argument("-W", "--conn-err-wait-time", action="store", default=0.0, type=float,
                    dest="conn_err_wait_time", help="In web spider mode, when loading a page leads to a connection "
                                                    "error, and the -w flag was specified, sleep the specified number "
                                                    "of seconds before resuming the web spidering.")
parser.add_argument("-x", "--dry-run", action="store_true", default=False, dest="dry_run",
                    help="In web spider mode, don't fetch anything, just load data structures from the database "
                         "and then exit.")
### END WEB SPIDER OPTIONS ###

### FULLTEXT SEARCH OPTIONS ###
parser.add_argument("-c", "--width-cols", action="store", default=0, type=int, dest="width_cols",
                    help="In fulltext search mode, use this width in columns for displaying the table of search "
                         "results.")
parser.add_argument("-Q", "--fulltext-query", action="store", default='', type=str, nargs='+',
                    dest="fulltext_pos_query",
                    help="In fulltext search mode, match bios against these boolean expressions to include the "
                         "profiles in the results; required if -f is used. Accepts 1 or more expressions: if 2 or more "
                         "expressions are used, all expressions must match for the bio to be included in the "
                         "results.")
parser.add_argument("-N", "--fulltext-negative-query", action="store", default='', type=str, nargs="+",
                    dest="fulltext_neg_query",
                    help="In fulltext search mode, match bios against this boolean expression to exclude them from the "
                         "results when they've matched the -Q expression(s). Accepts 1 or more expressions: if 2 or "
                         "more expressions are used, a bio matching any one of the expressions is excluded from the "
                         "results.")
parser.add_argument("-i", "--output-handles", action="store_true", default=False, dest="output_handles",
                    help="In fulltext search mode, suppress normal output; just output matching handles in @ form, "
                         "one per line.")
parser.add_argument("-u", "--output-urls", action="store_true", default=False, dest="output_urls",
                    help="In fulltext search mode, suppress normal output; just output the profile URLs of matching "
                         "handles, one per line.")
### END FULLTEXT SEARCH OPTIONS ###

# N.B. The 'mark handles considered' and 'mark handles not considered' modes
# have no flags to modify their execution at the moment.


def main():
    """
    The main logic of the program. Parses the commandline arguments, validates the
    flags specified, then executes either processing handles from the commandline,
    processing handles from the database using threads, or processing handles from
    the database without using threads, depending on the commandline flags.

    :return: None
    :rtype:  types.NoneType
    """
    options = parser.parse_args()

    # Instance the main Logger. This is the only Logger needed unless threaded mode is used.
    if options.web_spider:
        main_logger_obj = MainProcessor.instance_logger_obj("main", use_threads=bool(options.threads_count))
    else:
        main_logger_obj = MainProcessor.instance_logger_obj("main", use_threads=bool(options.threads_count), no_output=True)

    validate_cmdline_flags(options)

    log_cmdline_flags(options, main_logger_obj)

    if options.web_spider:
        execute_web_spider_mode(options, main_logger_obj)
    elif options.fulltext_search:
        execute_fulltext_search_mode(options, main_logger_obj)
    elif options.mark_handles_considered_eq_1 or options.mark_handles_considered_eq_0:
        execute_mark_handles_considered_or_not_mode(options, main_logger_obj)


def validate_cmdline_flags(options):
    """
    Validates the commandline flags received. Checks for invalid combinations of
    flags. If an invalid combination is found, an error message is printed and the
    program exits with status 1.

    :param options:    The argparse.Namespace object that is the return value of
                       argparse.OptionParser.parse_args().
    :type options:     argparse.Namespace
    :return:           None
    :rtype:            types.NoneType
    """
    # Shorthand private function that automatically iterates through a dict
    # of all the flags that don't apply in this mode, and errors out wiht an
    # appropriate message if any one of them was used.
    def _exclude_non_mode_flags(mode_flag, mode_name, illeg_args):
        # Private function that iterates over dict of illegal arguments.
        for flag, arg_value in illeg_args.items():
            if arg_value:
                print(f"with {mode_flag} flag used, {flag} cannot be used; does not apply to {mode_name} mode")
                exit(1)

    # Compact way of testing whether more than one of these four booleans is
    # True. Better than constructing a big boolean expression that checks each
    # permuation round-robin.
    if ((options.web_spider, options.fulltext_search, options.mark_handles_considered_eq_1,
             options.mark_handles_considered_eq_0).count(True) > 1):
        print("please specify only one of -s, -f, -m or -M; these flags are mutually exclusive")
        exit(1)

    # Argument integrity check; catching illegal combinations of commandline
    # arguments and emitting the appropriate error messages.

    # Argument parsing for webspider mode (-s flag).
    if options.web_spider:
        # Checking for any of the flags that don't apply in this mode.
        _exclude_non_mode_flags("-s", "fulltext search",
                                {"-c": options.width_cols, "-Q": options.fulltext_pos_query,
                                 "-N": options.fulltext_neg_query, "-i": options.output_handles,
                                 "-u": options.output_urls})

        if options.width_cols:
            print("with -s flag used, -c cannot be used; does not apply to webspider mode")
            exit(1)
        elif (not options.fetch_profiles_only and not options.fetch_relations_only
                  and not options.fetch_profiles_and_relations):
            print("when -s flag is used, please specify one of either -p, -q or -r on the commandline to choose "
                  "the scraping mode")
            exit(1)
        elif options.fetch_profiles_only and options.fetch_relations_only or \
                options.fetch_profiles_only and options.fetch_profiles_and_relations or \
                options.fetch_relations_only and options.fetch_profiles_and_relations:
            print("when -s flag was used, more than just one of -p, -q and -r used on the commandline; please "
                  "supply only one")
            exit(1)
        elif ((options.fetch_profiles_only or options.fetch_profiles_and_relations)
                and not (options.handles_join_profiles or options.relations_join_profiles
                         or options.handles_from_args)):
            print("when -s flag is used, if -p or -r is used, please specify one of -H, -R or -C on the commandline "
                  "to indicate where to source handles to process")
            exit(1)
        elif (options.fetch_profiles_only or options.fetch_profiles_and_relations) and \
                ((options.handles_join_profiles and options.relations_join_profiles) or
                 (options.handles_join_profiles and options.handles_from_args) or
                 (options.relations_join_profiles and options.handles_from_args)):
            print("when -s flag is used, with either -p or -r, please specify _only one_ of -H, -R or -C on the "
                  "commandline to indicate where to source handles to process")
            exit(1)
        elif options.fetch_relations_only and (options.handles_join_profiles or options.relations_join_profiles):
            print("with -s and -q flags used, please don't specify -H or -R; relations-only fetching sources its "
                  "handles from those present in the profiles table which aren't in the relations table")
            exit(1)
        elif options.handles_from_args and len(options.handles) == 0:
            print("when -s and -C flags are used, please supply one or more handles on the commandline")
            exit(1)
        elif not options.handles_from_args and len(options.handles) != 0:
            print("with -s flag used, -C was not used, but handles supplied on the commandline")
            exit(1)
        elif options.threads_count < 0:
            print("with -s flag used, the argument to -t was less than 0: please only use a value for --threads-count "
                  "that is greater than or equal to 0")
            exit(1)
        elif options.threads_count > 1 and options.dry_run:
            print("with -s flag used, and both -t and -x used; cannot run in these two modes simultaneously")
            exit(1)
        elif options.conn_err_wait_time and not options.dont_discard_bc_wifi:
            print("with -s flag used, -W was used but -w was not; -W value is unusable if not in -w mode")
            exit(1)
        elif options.conn_err_wait_time and options.conn_err_wait_time < 0:
            print("with -s flag used, and -w and -W flags used, argument for -W is a negative number; please only "
                  "use an argument of 0.0 or greater with -W flag")
            exit(1)
    # Argument parsing for fulltext search mode (-f flag).
    elif options.fulltext_search:
        _exclude_non_mode_flags("-f", "webspider",
                                {"-C": options.handles_from_args, "-H": options.handles_join_profiles,
                                 "-R": options.relations_join_profiles, "-p": options.fetch_profiles_only,
                                 "-q": options.fetch_relations_only, "-r": options.fetch_profiles_and_relations,
                                 "-t": options.threads_count, "-w": options.dont_discard_bc_wifi,
                                 "-W": options.conn_err_wait_time, "-x": options.dry_run})

        if options.width_cols < 0:
            print("with -f flag used, argument for -c is a negative number; please only use an argument "
                  "of 1 or greater with -c flag")
            exit(1)
        elif not options.fulltext_pos_query:
            print("with -f flag used, -Q flag must be used to supply the search query to conduct the fulltext "
                  "search with")
            exit(1)
        elif options.output_handles and options.output_urls:
            print("with -f flag used, cannot use both -i and -u flags: options are mutually exclusive")
            exit(1)
        elif options.width_cols and (options.output_handles or options.output_urls):
            print("with -f flag used, using -c flag with either -i or -u flags is nonsensical, can't control "
                  "the width of the output table while also not printing it")
            exit(1)
        elif len(options.handles) != 0:
            print("with -f flag used, handles supplied on the commandline")
            exit(1)
    # Argument parsing for either handle marking mode (-m flag or -M flag).
    elif options.mark_handles_considered_eq_0 or options.mark_handles_considered_eq_1:
        # Checking for any of the flags that don't apply in this mode.
        illegal_flags_d = {"-c": options.width_cols, "-Q": options.fulltext_pos_query, "-N": options.fulltext_neg_query,
                           "-i": options.output_handles, "-u": options.output_urls, "-C": options.handles_from_args,
                           "-H": options.handles_join_profiles, "-R": options.relations_join_profiles,
                           "-p": options.fetch_profiles_only, "-q": options.fetch_relations_only,
                           "-r": options.fetch_profiles_and_relations, "-t": options.threads_count,
                           "-w": options.dont_discard_bc_wifi, "-W": options.conn_err_wait_time, "-x": options.dry_run}

        if options.mark_handles_considered_eq_0:
            _exclude_non_mode_flags("-m", "mark handles considered", illegal_flags_d)
            if len(options.handles) != 0:
                print("with -m flag used, handles supplied on the commandline")
                exit(1)
        else:
            _exclude_non_mode_flags("-M", "mark handles not considered", illegal_flags_d)
            if len(options.handles) != 0:
                print("with -M flag used, handles supplied on the commandline")
                exit(1)
    # None of the mode flags were used, which is itself an error; the program
    # can't run without one of those flags to indicate which mode to run in. It
    # doesn't have a default.
    else:
        print("none of the flags -s, -f, -m or -M used; please indicate a mode to run in")
        exit(1)


def log_cmdline_flags(options, logger_obj):
    """
    Logs the commandline flags specified.

    :return:           None
    :rtype:            types.NoneType
    """
    # Logging the commandline flags received.
    if options.web_spider:
        logger_obj.info("got -s flag, entering webspider mode")
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
    elif options.fulltext_search:
        logger_obj.info("got -s flag, entering fulltext search mode")
        if options.width_cols:
            logger_obj.info("got -c flag, when printing results will conform the output table to a screen width "
                            f"of {options.width_cols}")
        if options.output_handles:
            logger_obj.info("got -i flag, will omit output table and just output matching handles in @ form, "
                            "one per line")
        elif options.output_urls:
            logger_obj.info("got -u flag, will omit output table and just output the profile URLs of matching "
                            "handles, one per line")
    elif options.mark_handles_considered_eq_1:
        logger_obj.info("got -m flag, will accept handles on standard input and update the profiles table to "
                        "set considered = 1 on matching rows")
    elif options.mark_handles_considered_eq_0:
        logger_obj.info("got -m flag, will accept handles on standard input and update the profiles table to "
                        "set considered = 0 on matching rows")


def execute_web_spider_mode(options, main_logger_obj):
    """
    Execute the program's webspider mode.

    :param options:         The argparse.Namespace object that is the return value of
                            argparse.OptionParser.parse_args().
    :type options:          argparse.Namespace
    :param main_logger_obj: The Logger object to log events to.
    :type main_logger_obj:  logging.Logger
    :return:                None
    :rtype:                 types.NoneType
    """
    save_profiles = (options.fetch_profiles_only or options.fetch_profiles_and_relations)
    save_relations = (options.fetch_relations_only or options.fetch_profiles_and_relations)

    # The three main cases are processing handles from the commandline,
    # processing handles from the database in a threaded fashion,
    # and processing handles from the database in a single-tasking fashion.

    main_processor_obj = MainProcessor(options, main_logger_obj, DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE,
                                       save_profiles, save_relations)

    if options.handles_from_args:
        main_processor_obj.process_handles_from_args()
    elif options.threads_count > 1:
        main_processor_obj.process_handles_from_db_w_threads()
    else:
        main_processor_obj.process_handles_from_db_single_thread()


def execute_fulltext_search_mode(options, logger_obj):
    """
    Execute the program's fulltext search mode. Uses the content of
    options.fulltext_pos_query as its search terms. If options.fulltext_neg_query is
    set, uses it as accompanying negative search terms; i.e. the results will be all
    rows that match the expression in options.fulltext_pos_query but do *not* match
    the expression in options.fulltext_neg_query.

    :param options:    The argparse.Namespace object that is the return value of
                       argparse.OptionParser.parse_args().
    :type options:     argparse.Namespace
    :param logger_obj: The Logger object to log events to.
    :type logger_obj:  logging.Logger
    :return:           False if no results were found, True otherwise.
    :rtype:            bool
    """
    main_processor_obj = MainProcessor(options, logger_obj, DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE)

    # Fetching the current columns of the terminal to use as a maximum width for
    # the output table to be constrained to.
    terminal_width_cols = shutil.get_terminal_size().columns

    # Executing the fulltext search.
    if options.fulltext_neg_query:
        results = main_processor_obj.fulltext_profiles_search(options.fulltext_pos_query, options.fulltext_neg_query)
    else:
        results = main_processor_obj.fulltext_profiles_search(options.fulltext_pos_query)

    if options.output_handles:
        for handle_obj, _ in results:
            print(handle_obj.handle_in_at_form)
        exit(0)
    elif options.output_urls:
        for handle_obj, _ in results:
            print(handle_obj.profile_url)
        exit(0)

    # Reporting results.
    pos_query_expr = ' and '.join(f"'{term}'" for term in options.fulltext_pos_query)
    if options.fulltext_neg_query:
        neg_query_expr = ' or '.join(f"'{term}'" for term in options.fulltext_neg_query)
        matching_expr = f"{pos_query_expr} and not matching {neg_query_expr}"
    else:
        matching_expr = pos_query_expr

    match len(results):
        case 0:
            print(f"For query matching {matching_expr}:", "No results.", end="\n\n", sep="\n\n")
            return False
        case 1:
            print(f"For query matching {matching_expr}, 1 result:", end="\n\n", sep="\n\n")
        case no_of_results:
            print(f"For query matching {matching_expr}, {no_of_results} results:", end="\n\n", sep="\n\n")

    # Calling a pre-prep method that does a lot of deriving vars from other vars
    # to compute values needed to build the ASCII art output table.
    prq = query_output_prereqs(options, results, terminal_width_cols)

    output_3_column_width = (2 + prq.max_handle_at_len + 3 + prq.max_handle_url_len + 3
                             + min(16, prq.max_profile_bio_len) + 2)

    if output_3_column_width <= prq.output_width_cols:
        # It's possible to display the 3rd column, the bio samples.
        #
        # Trimming the list of profile bio texts to the maximum length afforded
        # by the display cols constraint and the amount of each line taken up by
        # the handles at forms and profile URL columns.
        max_len_for_snippets = prq.output_width_cols - (2 + prq.max_handle_at_len + 3 + prq.max_handle_url_len + 3 + 2)

                                     # Right-pads the bio_text str with spaces to width {max_len_for_snippets}.
        bio_texts_trim_padded = list(map(lambda bio_text: bio_text.ljust(max_len_for_snippets, ' '),
                                         # Trims the bio texts to the upper bound {max_len_for_snippets}
                                         map(lambda bio_text: bio_text[:max_len_for_snippets],
                                             prq.profiles_bio_texts)))

        print_query_output_3_col(prq.handles_at_form_padded, prq.handles_urls_padded, bio_texts_trim_padded,
                                 prq.max_handle_at_len, prq.max_handle_url_len, max_len_for_snippets)
    else:
        # Can only display the 1st two columns, the handle in @ form and the
        # profile URL.
        print_query_output_2_col(prq.handles_at_form_padded, prq.handles_urls_padded,
                                 prq.max_handle_at_len, prq.max_handle_url_len)

    return True


def execute_mark_handles_considered_or_not_mode(options, logger_obj):
    """
    Executes either the mark-handles-considered or the mark-handles-not-considered
    mode. Draws a list of handles in @ form from stdin, and calls a method that
    executes an UPDATE statement on the database's profiles table. (Executing the
    mark-handles-considered mode with a specific list of handles, and then executing
    the mark-handles-not-considered mode with the same handles will restore the
    profiles table to its original state.)

    :param options:    The argparse.Namespace object that is the return value of
                       argparse.OptionParser.parse_args().
    :type options:     argparse.Namespace
    :param logger_obj: The Logger object to log events to.
    :type logger_obj:  logging.Logger
    :return:           False if no results were found, True otherwise.
    :rtype:            bool
    """
    considered = int(options.mark_handles_considered_eq_1)

    handles = list()

    # Validating data from stdin; errors out if a line doesn't validate
    # according to Handle.validate_handle() (which is applying
    # re.compile("^@[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+\.[A-Za-z0-9]+$")). Keeps a
    # count of lines so it can detect if stdin was zero-length, and error out in
    # that case as well.

    line_count = 0
    for stdin_line in sys.stdin:
        line_count += 1
        stdin_data = stdin_line.rstrip("\n")
        if not Handle.validate_handle(stdin_data):
            print(f"with -m or -M flag used, got an argument on the commandline which isn't a handle: {stdin_data}")
            exit(1)
        handles.append(stdin_data)

    if line_count == 0:
        print("with -m or -M flag used, got immediate EOF on stdin; nothing to do")
        exit(1)

    # Instancing a Main_Processor object, and calling the update method.
    main_processor_obj = MainProcessor(options, logger_obj, DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE)

    rows_affected = main_processor_obj.update_profiles_set_considered(handles, considered)

    match rows_affected:
        case 0:
            print("No rows affected.")
        case 1:
            print("1 row affected.")
        case _:
            print(f"{rows_affected} rows affected.")


def query_output_prereqs(options, results, terminal_width_cols):
    """
    Derive the prerequisite values for printing the results of the fulltext query.
    Returns a dict of the values handles_at_form_padded, handles_urls_padded,
    profiles_bio_texts, max_handle_at_len, max_handle_url_len, max_profile_bio_len,
    and output_width_cols.

    :param options:             The options object that is the first return value of
                                optparse.OptionParser.parse_args().
    :type options:              optparse.Values
    :param results:             The output of the
                                Handles_Processor.fulltext_profiles_search() method
                                applied to the commandline arguments.
    :type results:              list
    :param terminal_width_cols: The width the output table is allowed to be, in
                                columns.
    :type terminal_width_cols:  int
    :return:                    A dict of the values handles_at_form_padded,
                                handles_urls_padded, profiles_bio_texts,
                                max_handle_at_len, max_handle_url_len,
                                max_profile_bio_len, and output_width_cols.
    :rtype:                     dict
    """
    Prereqs = collections.namedtuple("Prereqs", ('handles_at_form_padded', 'handles_urls_padded', 'profiles_bio_texts',
                                                 'max_handle_at_len', 'max_handle_url_len', 'max_profile_bio_len',
                                                 'output_width_cols'))

    # Preparing the lists of handles in @ form, profile URLs, and profile bio
    # texts. The bios have their newlines replaced with \n and their tabs
    # replaced with 4 spaces.
    bio_text_tr_d = {ord('\n'): '\\n', ord('\t'): '    '}
    handles_at_form = [handle_obj.handle_in_at_form for handle_obj, _ in results]
    handles_urls = [handle_obj.profile_url for handle_obj, _ in results]
    profiles_bio_texts = [profile_bio_text.translate(bio_text_tr_d) for _, profile_bio_text in results]

    # Recording the maximum lengths in the previously defined 3 lists.
    max_handle_at_len = max(map(len, handles_at_form))
    max_handle_url_len = max(map(len, handles_urls))
    max_profile_bio_len = max(map(len, profiles_bio_texts))

    # Calculating what the minimum cols are needed to display a ASCII art table
    # with just the handles_at_form and handles_urls lists.
    min_table_display_width = 2 + max_handle_at_len + 3 + max_handle_url_len + 2

    # Testing if the table can even be displayed with display column
    # limitations, erroring out if it can't.
    if 0 < options.width_cols < min_table_display_width:
        print(f"output requires a minimum of {min_table_display_width} columns; commandline -c arg specified a width "
              f"of only {options.width_cols}; cannot display output in compliance with that constraint")
        exit(1)
    elif min_table_display_width > terminal_width_cols:
        print(f"output requires a minimum of {min_table_display_width} columns; current terminal width is only "
              f"{terminal_width_cols}; please resize your terminal window to at least {min_table_display_width} "
              "and re-run the program")
        exit(1)

    # Setting the display column limit. If using the terminal width, adding a
    # slop factor of 5 cols for emoji and other characters that take up more
    # than 1 col.
    if 0 < options.width_cols < terminal_width_cols:
        output_width_cols = options.width_cols
    else:
        output_width_cols = terminal_width_cols - 5

    # Derives a list of handles in @ form that are right-padded to {max_handle_at_len}.
    handles_at_form_padded = [handle_in_at_form.ljust(max_handle_at_len, ' ')
                            for handle_in_at_form in handles_at_form]
    # Derives a list of profile URLs that are right-padded to {max_handle_url_len}.
    handles_urls_padded = [handle_url.ljust(max_handle_url_len, ' ') for handle_url in handles_urls]

    # Returning all the derived values as a dictionary. 7 is just too many to
    # return as a tuple.
    return Prereqs(handles_at_form_padded, handles_urls_padded, profiles_bio_texts,
                   max_handle_at_len, max_handle_url_len, max_profile_bio_len, output_width_cols)


def print_query_output_3_col(handles_at_form_padded, handles_urls_padded, bio_texts_trim_padded,
                             max_handle_at_len, max_handle_url_len, max_len_for_snippets):
    """
    Prints the output of the search query in fulltext mode, with the handle at form,
    profile URL, and profile snippet columns.

    :param handles_at_form_padded: A list of the handles in @username@instance
                                   forms, space-padded to the length of the longest
                                   handle in the list.
    :type handles_at_form_padded:  list
    :param handles_urls_padded:    A list of the profile URLs for each handle,
                                   space-padded to the length of the longest URL in
                                   the list.
    :type handles_urls_padded:     list
    :param bio_texts_trim_padded:  A list of the profile bio texts trimmed to max
                                   allowed length and then space-padded to that
                                   length.
    :type bio_texts_trim_padded:   list
    :param max_handle_at_len:      Length of the longest handle in
                                   handles_at_form_padded.
    :type max_handle_at_len:       int
    :param max_handle_url_len:     Length of the longest URL in handles_urls_padded.
    :type max_handle_url_len:      int
    :param max_len_for_snippets:   The maximum length a bio snippet can be.
    :type max_len_for_snippets:    int
    :return:                       None
    :rtype:                        types.NoneType
    """

    # Assembling the top and bottom lines of the ASCII art results table.
    table_top_bottom_border = ('+-' + '-' * max_handle_at_len + '-+-' + '-' * max_handle_url_len + '-+-'
                               + '-' * max_len_for_snippets + '-+')

    print(table_top_bottom_border)

    # Printing the rows of the ASCII art results table, having zip'd the
    # handles_at_form_padded, handles_urls_padded, and bio_texts_trim_padded
    # lists back together into result rows.
    for handle_padded, handle_url_padded, bio_text_trim_padded in zip(handles_at_form_padded,
                                                                              handles_urls_padded,
                                                                              bio_texts_trim_padded):
        print('| ' + handle_padded + ' | ' + handle_url_padded + ' | ' + bio_text_trim_padded + ' |')

    print(table_top_bottom_border)


def print_query_output_2_col(handles_at_form_padded, handles_urls_padded, max_handle_at_len,
                             max_handle_url_len):
    """
    Prints the output of the search query in fulltext mode, with just the handle at
    form and profile URL columns.

    :param handles_at_form_padded: A list of the handles in @username@instance
                                   forms, space-padded to the length of the longest
                                   handle in the list.
    :type handles_at_form_padded:  list
    :param handles_urls_padded:    A list of the profile URLs for each handle,
                                   space-padded to the length of the longest URL in
                                   the list.
    :type handles_urls_padded:     list
    :param max_handle_at_len:      Length of the longest handle in handles_at_form_padded.
    :type max_handle_at_len:       int
    :param max_handle_url_len:     Length of the longest URL in handles_urls_padded.
    :type max_handle_url_len:      int
    :return:                       None
    :rtype:                        types.NoneType
    """

    # Assembling the top and bottom lines of the ASCII art results table.
    table_top_bottom_border = '+-' + '-' * max_handle_at_len + '-+-' + '-' * max_handle_url_len + '-+'

    print(table_top_bottom_border)

    # Printing the rows of the ASCII art results table, having zip'd the
    # handles_at_form_padded and handles_urls_padded lists back together into
    # result rows.
    for handle_padded, handle_url_padded in zip(handles_at_form_padded, handles_urls_padded):
        print('| ' + handle_padded + ' | ' + handle_url_padded + ' |')

    print(table_top_bottom_border)


if __name__ == "__main__":
    main()
