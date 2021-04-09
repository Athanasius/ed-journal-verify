"""Given a directory or set of files, scan and report any unknown Journal events."""
import argparse
import logging
import pathlib
import sys
from enum import Enum

APPNAME = 'scan-journals'


class ErrorCodes(Enum):
    OK = 0
    BAD_LOGLEVEL = 1
    NOT_DIR_OR_FILE = 2

def main() -> None:
    parser = argparse.ArgumentParser(
        prog=APPNAME,
        description='Scan directories and files for Elite Dangerous Journal files '
                    'and report on any unknown events found.'
    )

    parser.add_argument(
        '--loglevel',
        help='Set the log level to one of: '
             'CRITICAL, ERROR, WARNING, INFO, DEBUG'
    )

    parser.add_argument(
        '--errorcodes',
        action='store_true',
        help='Print a list of the exit error codes'
    )

    parser.add_argument(
        'files',
        help='Directories and files to be scanned',
        nargs='*'
    )

    args = parser.parse_args()

    if args.errorcodes:
        for e in ErrorCodes.__members__.values():
            print(f'{e.name:30} {e.value}')

        exit(0)

    logger = logging.getLogger(APPNAME)
    if args.loglevel:
        try:
            logger.setLevel(args.loglevel)

        except ValueError:
            print(f'Unknown loglevel: {args.loglevel}')
            parser.print_help()
            exit(ErrorCodes.BAD_LOGLEVEL.value)

    else:
        logger.setLevel(logging.INFO)

    for f in args.files:
        file = pathlib.Path(f)
        if file.is_dir():
            pass

        elif file.is_file():
            pass

        else:
            logger.error(f'"{file} is not a directory or plain file')
            exit(ErrorCodes.NOT_DIR_OR_FILE.value)


if __name__ == '__main__':
    main()
    exit(ErrorCodes.OK.value)
