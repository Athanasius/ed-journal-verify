#!/usr/bin/env python
"""Check a Journal file for schema compliance."""
import argparse
import json
import logging
import os
import pathlib
import re
import sys
from enum import Enum
from typing import Dict

import jsonschema
import yaml

APPNAME = 'journal-check-schema'
CONFIG_FILE = 'journal-check-schema.yml'
SCHEMAS_DIR = 'journal-schemas/Journal-doc-v28'  # Default Journal schemas


class ErrorCodes(Enum):
    """Exit codes this program uses to indicate an error."""

    OK = 0
    BAD_LOGLEVEL = 1
    NOT_DIR_OR_FILE = 2
    BAD_CONFIG_FILE = 3
    NO_FILES = 4
    CONFIG_FILE_NOT_FOUND = 5
    SCHEMAS_DIR_NOT_EXIST = 6


class JournalSchemaCheck:
    """Scan journals."""

    _RE_ED_JOURNAL = re.compile(r'^Journal(Alpha|Beta)?\.[0-9]{12}\.[0-9]{2}\.log$')
    unknown_events: Dict = {}

    def __init__(self) -> None:
        """Perform initial setup."""
        self.parser = argparse.ArgumentParser(
            prog=APPNAME,
            description='Scan directories and files for Elite Dangerous Journal files '
                        'and report on any schema violations.'
        )

        self.parser.add_argument(
            '--loglevel',
            help='Set the log level to one of: '
                 'CRITICAL, ERROR, WARNING, INFO, DEBUG'
        )

        self.parser.add_argument(
            '--config',
            help='Specify an alternative config file'
        )

        self. parser.add_argument(
            '--schemas',
            help='Specify a directory holding per-event schema files'
        )

        self.parser.add_argument(
            '--errorcodes',
            action='store_true',
            help='Print a list of the exit error codes'
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
        self.logger_formatter = logging.Formatter('%(asctime)s - %(levelname)8s - %(module)s:%(lineno)d: %(message)s')
        self.logger_formatter.default_time_format = '%Y-%m-%d %H:%M:%S'
        self.logger_formatter.default_msec_format = '%s.%03d'
        self.logger_ch.setFormatter(self.logger_formatter)
        self.logger.addHandler(self.logger_ch)
        if self.args.loglevel:
            try:
                self.logger.setLevel(self.args.loglevel)

            except ValueError:
                print(f'Unknown loglevel: {self.args.loglevel}\n')
                self.parser.print_help()
                exit(ErrorCodes.BAD_LOGLEVEL.value)

        else:
            self.logger.setLevel(logging.INFO)

        if self.args.config:
            config_file = pathlib.Path(self.args.config).expanduser()
        else:
            config_file = (pathlib.Path(sys.argv[0]).parent / CONFIG_FILE).expanduser()

        try:
            with config_file.open('r') as cf:
                self.config = yaml.safe_load(cf)

        except FileNotFoundError as e:
            print(f'Bad config file "{config_file}": {e!r}')
            exit(ErrorCodes.CONFIG_FILE_NOT_FOUND.value)

        if self.args.schemas:
            self.schemas_dir = pathlib.Path(self.args.schemas)

        elif (s_dir := self.config.get('schemas_dir')) is not None:
            self.schemas_dir = pathlib.Path(s_dir)

        else:
            self.schemas_dir = pathlib.Path(SCHEMAS_DIR)

        if not self.schemas_dir.exists():
            print(f'Specified schemas directory "{self.schemas_dir}" does not exist\n')
            self.parser.print_help()
            exit(ErrorCodes.SCHEMAS_DIR_NOT_EXIST.value)

        # Dict, keyed on event name, to hold the loaded schemas
        self.schemas: Dict = {}

        if len(self.args.files) == 0:
            self.logger.error('You must specify at least one file or directory\n')
            self.parser.print_help()
            exit(ErrorCodes.NO_FILES.value)

        # JSON schemas referencing others is by relative path, so we'll have to
        # ensure CWD is in an expected place.
        os.chdir(pathlib.Path(sys.argv[0]).parent)

    def scan_files(self) -> None:
        """Perform scan of all specified files."""
        for f in self.args.files:
            file = pathlib.Path(f)
            file = file.expanduser()
            self.process_file(file)

    def process_file(self, file) -> None:
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

    def scan_file(self, file) -> None:  # noqa: CCR001
        """Check a file against schema."""
        self.logger.debug(f'Processing "{file}"')
        with file.open('r', encoding='utf-8') as f:
            lineno = 0
            for line in f:
                lineno += 1
                try:
                    entry = json.loads(line)

                except json.decoder.JSONDecodeError as e:
                    self.logger.exception(f'Line:\n{line}\n{e!r}')
                    continue

                self.logger.debug(f'entry:\n{entry}')

                event = entry.get('event')
                if event is None:
                    self.logger.error(f"Entry doesn't contain 'event' key:\n{line}")
                    continue

                # Load schema
                if self.schemas.get('event') is None:
                    try:
                        with (pathlib.Path(sys.path[0]) / self.schemas_dir / f'{entry["event"]}.json').open('r') as s:
                            try:
                                self.schemas[event] = json.load(s)

                            except json.decoder.JSONDecodeError as e:
                                self.logger.error(f"Error loading schema file for event '{event}':\n{e!r}")
                                continue

                    except FileNotFoundError:
                        self.logger.warning(f"No schema file for event type '{event}', "
                                            f"can't validate message:\n{line}")
                        continue

                # Validate
                try:
                    jsonschema.validate(entry, self.schemas[event])

                except jsonschema.ValidationError as e:
                    self.logger.error(f'The following entry in file "{file}" failed validation:\n{e}\n{entry}')

                except jsonschema.SchemaError as e:
                    self.logger.error(f'The following entry in file "{file}" has a schema error:\n{e}\n{entry}')


if __name__ == '__main__':
    scanner = JournalSchemaCheck()
    scanner.scan_files()

    exit(ErrorCodes.OK.value)
