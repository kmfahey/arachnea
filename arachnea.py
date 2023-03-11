#!/usr/bin/python3

import decouple
import optparse
import shutil

from arachnea.processing import Main_Processor, Data_Store


DB_HOST = 'localhost'
DB_USER = decouple.config('DB_USER')
DB_PASSWORD = decouple.config('DB_PASSWORD')
DB_DATABASE = 'arachnea'


# Setting up the options accepted by the program on the commandline
parser = optparse.OptionParser()

parser.add_option("-s", "--web-spider", action="store_true", default=False, dest="web_spider",
                  help="operate in web spider mode, recursively scraping mastodon profiles for bios and "
                       "following/followers profile links, which are chased and those bios are scraped in turn")
parser.add_option("-f", "--fulltext-search", action="store_true", default=False, dest="fulltext_search",
                  help="operate in database fulltext search mode, accepting query terms on the commandline and "
                       "querying the profile table for profiles with matching bios, which are then displayed")

### WEB SPIDER OPTIONS ###
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
### END WEB SPIDER OPTIONS ###

### FULLTEXT SEARCH OPTIONS ###
parser.add_option("-c", "--width-cols", action="store", default=0, type="int", dest="width_cols",
                  help="the width in columns of the table of search results to display")
### END FULLTEXT SEARCH OPTIONS ###


def main():
    """
    "The main logic of the program. Parses the commandline arguments, validates the
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

    if options.web_spider:
        execute_web_spider_mode(options, args, main_logger_obj)
    elif options.fulltext_search:
        execute_fulltext_search_mode(options, args, main_logger_obj)


def execute_web_spider_mode(options, args, main_logger_obj):
    """
    Execute the program's webspider mode. If processing handles from the
    commandline, the args argument is used as the source of handles.

    :param options:    The options object that is the first return value of
                       optparse.OptionParser.parse_args().
    :type options:     optparse.Values
    :param args:       The commandline arguments to the program. If the program is
                       processing handles from the commandline, must be nonzero
                       in length and consist of strings which are handles in
                       @user@instance form.
    :type args:        tuple
    :param logger_obj: The Logger object to log events to.
    :type logger_obj:  logger.Logger
    :return:           None
    :rtype:            types.NoneType
    """
    save_profiles = (options.fetch_profiles_only or options.fetch_profiles_and_relations)
    save_relations = (options.fetch_relations_only or options.fetch_profiles_and_relations)

    # FIXME add database-matching-rows-clearing mode

    # The three main cases are processing handles from the commandline,
    # processing handles from the database in a threaded fashion,
    # and processing handles from the database in a single-tasking fashion.

    main_processor_obj = Main_Processor(options, args, main_logger_obj, DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE,
                                        save_profiles, save_relations)

    if options.handles_from_args:
        main_processor_obj.process_handles_from_args()
    elif options.use_threads:
        main_processor_obj.process_handles_from_db_w_threads()
    else:
        main_processor_obj.process_handles_from_db_single_thread()


def execute_fulltext_search_mode(options, args, logger_obj):
    """
    Execute the program's fulltext search mode, using the args argument as the
    query terms. If args is longer than 1 term, the query terms are joined with OR
    booleans.

    :param options:    The options object that is the first return value of
                       optparse.OptionParser.parse_args().
    :type options:     optparse.Values
    :param args:       The commandline arguments to the program, which are used
                       as query terms to the fulltext search. If there's more than
                       one, query terms are joined with OR booleans.
    :type args:        tuple
    :param logger_obj: The Logger object to log events to.
    :type logger_obj:  logger.Logger
    :return:           None
    :rtype:            types.NoneType
    """
    main_processor_obj = Main_Processor(options, args, logger_obj, DB_HOST, DB_USER, DB_PASSWORD, DB_DATABASE)

    # Fetching the current columns of the terminal to use as a maximum width for
    # the output table to be constrained to.
    terminal_width_cols = shutil.get_terminal_size().columns

    # Executing the fulltext search, and then using the same utility function
    # that method does to get the search query it used.
    results = main_processor_obj.fulltext_profiles_search(args)

    query_str = Data_Store.format_query(args)

    if not len(results):
        print()
        print(f"For query {query_str}: no results.")
        efulltext_profiles_searchxit(0)
    else:
        print()
        print(f"For query {query_str}: {len(results)} results.")
        print()

    # Calling a pre-prep method that does a lot of deriving vars from other vars
    # to compute values needed to build the ASCII art output table.
    prereqs = query_output_prereqs(options, results, terminal_width_cols)

    handles_at_form_padded = prereqs['handles_at_form_padded']
    handles_urls_padded = prereqs['handles_urls_padded']
    profiles_bio_texts = prereqs['profiles_bio_texts']
    max_handle_at_len = prereqs['max_handle_at_len']
    max_handle_url_len = prereqs['max_handle_url_len']
    max_profile_bio_len = prereqs['max_profile_bio_len']
    output_width_cols = prereqs['output_width_cols']

    can_output_w_profile_snippet = (2 + max_handle_at_len + 3 + max_handle_url_len + 3 +
                                                        min(16, max_profile_bio_len) + 2) <= output_width_cols

    if can_output_w_profile_snippet:

        # Trimming the list of profile bio texts to the maximum length afforded
        # by the display cols constraint and the amount of each line taken up by
        # the handles at forms and profile URL columns.
        max_len_for_snippets = output_width_cols - (2 + max_handle_at_len + 3 + max_handle_url_len + 3 + 2)
        bio_texts_trim_padded = list(map(lambda bio_text: bio_text + ' ' * (max_len_for_snippets - len(bio_text)),
                                         map(lambda bio_text: bio_text[:max_len_for_snippets],
                                             profiles_bio_texts)))

        print_query_output_3_col(handles_at_form_padded, handles_urls_padded, bio_texts_trim_padded,
                                 max_handle_at_len, max_handle_url_len, max_len_for_snippets)
    else:
        print_query_output_2_col(handles_at_form_padded, handles_urls_padded,
                                 max_handle_at_len, max_handle_url_len)


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
    # Preparing the lists of handles in @ form, profile URLs, and profile bio
    # texts. The bios have their newlines replaced with \n and their tabs
    # replaced with 4 spaces.
    bio_text_tr_d = {ord('\n'): '\\n', ord('\t'): '    '}
    handles_at_form = [handle_obj.handle for handle_obj, _ in results]
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
    if options.width_cols > 0 and min_table_display_width > options.width_cols:
        print(f"output requires a minimum of {min_table_display_width} columns; commandline -c arg specified a width "
              f"of only {options.width_cols}; cannot display output in compliance with that constraint")
        exit(1)
    elif min_table_display_width > terminal_width_cols:
        print(f"output requires a minimum of {min_table_display_width} columns; current terminal width is only "
              f"{terminal_width_cols}; please resize your terminal window to at least {terminal_width_cols} "
              "and re-run the program")
        exit(1)

    # Setting the display column limit. If using the terminal width, adding a
    # slop factor of 5 cols for emoji and other characters that take up more
    # than 1 col.
    if options.width_cols > 0 and options.width_cols < terminal_width_cols:
        output_width_cols = options.width_cols
    else:
        output_width_cols = terminal_width_cols - 5

    # Deriving space-padded versions of the handles_at_form and handles_urls
    # lists.
    handles_at_form_padded = [handle_at_form + ' ' * (max_handle_at_len - len(handle_at_form))
                            for handle_at_form in handles_at_form]
    handles_urls_padded = [handle_url + ' ' * (max_handle_url_len - len(handle_url)) for handle_url in handles_urls]

    # Returning all the derived values as a dictionary. 7 is just too many to
    # return as a tuple.
    return {'handles_at_form_padded': handles_at_form_padded, 'handles_urls_padded': handles_urls_padded,
            'profiles_bio_texts': profiles_bio_texts, 'max_handle_at_len': max_handle_at_len,
            'max_handle_url_len': max_handle_url_len, 'max_profile_bio_len': max_profile_bio_len,
            'output_width_cols': output_width_cols}


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
    :param output_width_cols:      The width in columns of the output to print.
    :type output_width_cols:       int
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
    for handle_at_form_padded, handle_url_padded, bio_text_trim_padded in zip(handles_at_form_padded,
                                                                              handles_urls_padded,
                                                                              bio_texts_trim_padded):
        print('| ' + handle_at_form_padded + ' | ' + handle_url_padded + ' | ' + bio_text_trim_padded + ' |')

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
    for handle_at_form_padded, handle_url_padded in zip(handles_at_form_padded, handles_urls_padded):
        print('| ' + handle_at_form_padded + ' | ' + handle_url_padded + ' |')

    print(table_top_bottom_border)


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
    if options.web_spider:
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
                  "handle from those present in the profiles table which aren't in the relations table")
            exit(1)
        elif options.handles_from_args and not args:
            print("when -s and -C flags are used, please supply one or more handles on the commandline")
            exit(1)
        elif not options.handles_from_args and args:
            print("with -s flag used, -C was not used, but args supplied on the commandline")
            exit(1)
        elif options.use_threads and options.dry_run:
            print("with -s flag used, and both -t and -x used; cannot run in these two modes simultaneously")
            exit(1)
        elif options.conn_err_wait_time and not options.dont_discard_bc_wifi:
            print("with -s flag used, -W was used but -w was not; -W value is unusable if not in -w mode")
            exit(1)
        elif options.conn_err_wait_time and options.conn_err_wait_time < 0:
            print("with -s, -w and -W flags used, argument for -W is a negative number; please only use an argument "
                  "of 0.0 or greater with -W flag")
            exit(1)
    elif options.fulltext_search:
        illeg_args = {"-C": options.handles_from_args, "-H": options.handles_join_profiles,
                      "-R": options.relations_join_profiles, "-p": options.fetch_profiles_only,
                      "-q": options.fetch_relations_only, "-r": options.fetch_profiles_and_relations,
                      "-t": options.use_threads, "-w": options.dont_discard_bc_wifi, "-W": options.conn_err_wait_time,
                      "-x": options.dry_run}
        for flag, arg_value in illeg_args.items():
            if arg_value:
                print(f"with -f flag used, {flag} cannot be used; does not apply to fulltext search mode")
                exit(1)
        if not args:
            print("with -f flag used, no args were supplied on the commandline")
            exit(1)
        elif options.width_cols < 0:
            print("with -f flag used, argument for -c is a negative number; please only use an argument "
                  "of 1 or greater with -c flag")
            exit(1)
    else:
        print("neither -s or -f flag used; please specify one of either webspider mode or fulltext search mode")
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


if __name__ == "__main__":
    main()
