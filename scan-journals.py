#!/usr/bin/env python
"""Given a directory or set of files, scan and report any unknown Journal events."""
import argparse
import json
import logging
import os
import pathlib
import re
import sys
import yaml
from enum import Enum

APPNAME = 'scan-journals'
CONFIG_FILE = 'scan-journals.yml'


class ErrorCodes(Enum):
    OK = 0
    BAD_LOGLEVEL = 1
    NOT_DIR_OR_FILE = 2
    BAD_CONFIG_FILE = 3
    NO_FILES = 4

class JournalScan:
    """Scan journals."""

    config = None
    logger = None
    _RE_ED_JOURNAL = re.compile(r'^Journal(Alpha|Beta)?\.[0-9]{12}\.[0-9]{2}\.log$')
    unknown_events = {}

    def __init__(self):
        """Perform initial setup."""
        self.parser = argparse.ArgumentParser(
            prog=APPNAME,
            description='Scan directories and files for Elite Dangerous Journal files '
                        'and report on any unknown events found.'
        )

        self.parser.add_argument(
            '--loglevel',
            help='Set the log level to one of: '
                 'CRITICAL, ERROR, WARNING, INFO, DEBUG'
        )

        self.parser.add_argument(
            '--errorcodes',
            action='store_true',
            help='Print a list of the exit error codes'
        )

        self.parser.add_argument(
            '--print-new-config',
            action='store_true',
            help='Print out what the new config would be with the new unknowns'
        )

        self.parser.add_argument(
            '--print-counts',
            action='store_true',
            help='Print counts on the output of unknown event names'
        )

        self.parser.add_argument(
            'files',
            help='Directories and files to be scanned',
            nargs='*'
        )

        self.args = self.parser.parse_args()

        if self.args.errorcodes:
            for e in ErrorCodes.__members__.values():
                print(f'{e.name:30} {e.value}')

            exit(ErrorCodes.OK.value)

        self.logger = logging.getLogger(APPNAME)
        self.logger_ch = logging.StreamHandler()
        self.logger_formatter = logging.Formatter('%(asctime)s;%(name)s;%(levelname)s;%(module)s.%(funcName)s: %(message)s')
        self.logger_formatter.default_time_format = '%Y-%m-%d %H:%M:%S';
        self.logger_formatter.default_msec_format = '%s.%03d'
        self.logger_ch.setFormatter(self.logger_formatter)
        self.logger.addHandler(self.logger_ch)
        if self.args.loglevel:
            try:
                self.logger.setLevel(self.args.loglevel)

            except ValueError:
                print(f'Unknown loglevel: {self.args.loglevel}')
                self.parser.print_help()
                exit(ErrorCodes.BAD_LOGLEVEL.value)

        else:
            self.logger.setLevel(logging.INFO)

        with (pathlib.Path(sys.argv[0]).parent / CONFIG_FILE).open('r') as config_file:
            self.config = yaml.safe_load(config_file)

        # Empty file means no data, but we need an empty list later.
        if self.config is None:
            self.config = {'known_events': []}

        if len(self.args.files) == 0:
            self.logger.error('You must specify at least one file or directory')
            self.parser.print_help()
            exit(ErrorCodes.NO_FILES.value)

    def scan_files(self):
        """Perform scan of all specified files."""
        for f in self.args.files:
            file = pathlib.Path(f)
            file = file.expanduser()
            self.process_file(file)

    def process_file(self, file):
        """Process a directory or single file."""
        if file.is_dir():
            for e in file.iterdir():
                self.process_file(e)

            return

        if file.is_file():
            if self._RE_ED_JOURNAL.search(file.name):
                self.scan_file(file)

            else:
                self.logger.info(f'Skipping non-Journal file: "{file}"')

            return

        self.logger.error(f'Not a directory or plain file: "{file}"')
        return


    def scan_file(self, file):
        """Scan a file for unknown events."""
        self.logger.debug(f'Processing "{file}"')
        with file.open('r', encoding='utf-8') as f:
            for l in f:
                entry = json.loads(l)
                # self.logger.debug(entry)
                if entry['event'] not in self.config.get('known_events'):
                    if not self.unknown_events.get(entry['event']):
                        self.logger.debug(f'Unknown event "{entry["event"]}"')

                        self.unknown_events[entry['event']] = {
                            'first_file': str(file),
                            'name': entry['event'],
                            'count': 1
                        }

                    else:
                        self.unknown_events[entry['event']]['count'] += 1

    def report_unknown_events(self):
        """Report the unknown events."""
        for u in sorted(self.unknown_events):
            if self.args.print_counts:
                print(f'{self.unknown_events[u]["name"]:40}{self.unknown_events[u]["count"]}')

            else:
                print(f'{self.unknown_events[u]["name"]}')

    def print_new_config(self):
        """Print out what the new config file should be."""
        # Merge the config list with the found unknowns.
        output = {}
        output['known_events'] = sorted(self.config.get('known_events') + list(self.unknown_events))

        print(
            yaml.safe_dump(
                output,
                indent=4,
            )
        )


if __name__ == '__main__':
    scanner = JournalScan()
    scanner.scan_files()
    if scanner.args.print_new_config:
        scanner.print_new_config()

    else:
        scanner.report_unknown_events()

    exit(ErrorCodes.OK.value)
