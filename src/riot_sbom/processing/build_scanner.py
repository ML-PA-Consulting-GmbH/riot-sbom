"""
SPDX-FileCopyrightText: 2025 ML!PA Consulting GmbH
SPDX-License-Identifier: MIT
Author: Daniel Lockau <daniel.lockau@ml-pa.com>
"""

import glob
import logging
logger = logging.getLogger(__name__)
import os
import pathlib
import re
import subprocess
import tempfile
import unittest


if __name__ == "__main__":
    # update search path for local testing
    import pathlib
    import sys
    pkg_path = pathlib.Path(__file__).absolute().parents[2].as_posix()
    sys.path.insert(0, pkg_path)
    from riot_sbom.data.app_info import AppInfo
    from riot_sbom.data.package_info import PackageInfo, PackageReference
    from riot_sbom.data.file_info import FileInfo
    from riot_sbom.data.checked_url import CheckedUrl
    from riot_sbom.data.license_info import LicenseInfo, LicenseDeclarationType
    from riot_sbom.util import text_processing
    from riot_sbom.util import git_queries
else:
    from ..data.app_info import AppInfo
    from ..data.package_info import PackageInfo, PackageReference
    from ..data.file_info import FileInfo
    from ..data.checked_url import CheckedUrl
    from ..data.license_info import LicenseInfo, LicenseDeclarationType
    from ..util import text_processing
    from ..util import git_queries

__all__ = ["BuildScanner"]

class BuildScanner(object):
    def __init__(self, app_dir: pathlib.Path):
        """
        Initialize the build scanner with the given application directory.

        :param app_dir: The path to the application directory.
        :type app_dir: pathlib.Path
        """
        self._app_dir = app_dir
        self._app_data = {}
        self._riot_data = {}
        self._board_data = {}
        self._external_module_data = []
        self._package_data = []
        self._file_data = []
        self._executed = False

    def run(self):
        """
        Executes the build scanning process.
        This method performs the following steps:
        1. Extract sbom relevant package data from the Makefile build system.
        2. Run a traced build process for the application.
        3. Parse the trace file to gather the paths of the files actually used for the build.
        4. Build the file data by associating files with packages.
        """
        self._gather_build_info_from_make()
        names = set()
        names.add(self._app_data['name'])
        names.add(self._board_data['name'])
        names.update([mod['name'] for mod in self._external_module_data])
        if len(names) != len(self._external_module_data) + 2:
            logger.info('Duplicate names found in set of application, board and external modules. Prepending board name to application name.')
            self._app_data['name'] = f"APPLICATION_{self._app_data['name']}"
            self._board_data['name'] = f"BOARD_{self._board_data['name']}"
        with tempfile.TemporaryDirectory() as tempdir:
            trace_file = os.path.join(tempdir, 'trace.log')
            self._run_traced_build(trace_file)
            file_paths = self._parse_trace_file(trace_file)
        self._build_file_data(file_paths)
        self._executed = True

    def get_app_info(self) -> AppInfo:
        """
        Build an AppInfo object from the gathered build data for subsequent
        processing steps.

        :return: An AppInfo representation of the data gathered from build system and traced build.
        :rtype: AppInfo
        """
        if not self._executed:
            raise RuntimeError("Cannot create app info before running build.")
        app_package=PackageInfo(
            name=self._app_data['name'],
            source_dir=pathlib.Path(self._app_data['source_dir']).absolute(),
            version=None,
            licenses=None,
            download_url=None,
            copyrights=None,
            authors=None,
            supplier=None
        )
        riot_package=PackageInfo(
            name='RIOT OS',
            source_dir=pathlib.Path(self._riot_data['source_dir']).absolute(),
            version=self._riot_data['version'],
            licenses=[LicenseInfo(declaration_text=self._riot_data['license'],
                declaration_type=LicenseDeclarationType.EXACT_REFERENCE,
                license_text=None,
                url=None)],
            download_url=CheckedUrl(self._riot_data['url']),
            copyrights=None,
            authors=None,
            supplier=None
        )
        board_package=PackageInfo(
            name=self._board_data['name'],
            source_dir=pathlib.Path(self._board_data['source_dir']).absolute(),
            version=None,
            licenses=None,
            download_url=None,
            copyrights=None,
            authors=None,
            supplier=None)
        app_info = AppInfo(self._app_data['build_dir'],
                           PackageReference.from_package_info(app_package),
                           PackageReference.from_package_info(riot_package),
                           PackageReference.from_package_info(board_package),
                           {}, [])
        app_info.packages[app_info.app_package_ref] = app_package
        app_info.packages[app_info.riot_package_ref] = riot_package
        app_info.packages[app_info.board_package_ref] = board_package
        # add external modules
        for ext_mod in self._external_module_data:
            pkg = PackageInfo(
                name=ext_mod['name'],
                source_dir=pathlib.Path(ext_mod['source_dir']).absolute(),
                version=None,
                licenses=None,
                download_url=None,
                copyrights=None,
                authors=None,
                supplier=None
            )
            app_info.packages[PackageReference.from_package_info(pkg)] = pkg
        # add RIOT included packages
        for pkg in self._package_data:
            pkg = PackageInfo(
                name=pkg['name'],
                source_dir=pathlib.Path(pkg['source_dir']).absolute(),
                version=pkg['version'],
                licenses=[LicenseInfo(declaration_text=pkg['license'],
                                      declaration_type=LicenseDeclarationType.EXACT_REFERENCE,
                                      license_text=None,
                                      url=None)],
                download_url=CheckedUrl(pkg['url']),
                copyrights=None,
                authors=None,
                supplier=("RIOT OS"
                          if pkg['source_dir'].startswith(self._riot_data['source_dir'])
                          else None)
            )
            app_info.packages[PackageReference.from_package_info(pkg)] = pkg
        # add all files from build trace
        for file in self._file_data:
            app_info.files.append(FileInfo(
                path=pathlib.Path(file['path']).absolute(),
                package=PackageReference(file['package'][0],
                                         pathlib.Path(file['package'][1]).absolute()) if file['package'] else None,
                licenses=None,
                copyrights=None,
                authors=None))
        return app_info

    def _gather_build_info_from_make(self):
        """
        Retrieve package information for build by running 'make info-build-json'
        in the specified application directory.

        :param str app_dir: The directory where the 'make' command should be executed.
        :raises RuntimeError: If the 'make' command fails or if the output cannot be parsed.
        """
        logger.info('Running make info-build-json to retrieve basic build information')
        make_run = subprocess.run(['make', 'info-build-json'],
                                      cwd=self._app_dir.as_posix(),
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        if make_run.returncode != 0:
            raise RuntimeError('Failed to run make info-build-json')
        output = make_run.stdout.decode('utf-8')
        json_info = text_processing.get_trailing_json_object(output)
        if not isinstance(json_info, dict):
            raise RuntimeError('Invalid output from make info-build-json')
        # check completeness of output
        required_keys = set(["APPLICATION", "RIOTBASE", "APPDIR",
                         "BOARD", "RIOTPKG", "BOARDDIR", "EXTERNAL_BOARD_DIRS",
                         "BINDIR", "EXTERNAL_MODULE_DIRS", "EXTERNAL_MODULE_PATHS",
                         "EXTERNAL_PKG_DIRS", "DEFAULT_MODULE", "USEMODULE", "RIOTPKG"])
        if required_keys - set(json_info.keys()):
            print(json_info.keys())
            raise RuntimeError(f"Required keys are missing in the \"info-build-json\" output {required_keys - set(json_info.keys())}")
        self._app_data = {
            "name": json_info["APPLICATION"],
            "source_dir": json_info["APPDIR"],
            "build_dir": json_info["BINDIR"]
        }
        riot_remotes = git_queries.get_remotes_for_ref('HEAD', pathlib.Path(json_info['RIOTBASE']))
        if riot_remotes:
            if len(riot_remotes) > 1:
                logger.warning(f"Multiple remotes registered for HEAD of {json_info['RIOTBASE']}. Will pick one.")
            riot_remote_name = riot_remotes[0]
            riot_remote_url = git_queries.get_url_for_remote(riot_remote_name, pathlib.Path(json_info['RIOTBASE']))
        else:
            riot_remote_url = ""
        self._riot_data = {
            "source_dir": json_info["RIOTBASE"],
            "url": riot_remote_url,
            "version": git_queries.get_git_commit(pathlib.Path(json_info["RIOTBASE"])),
            "license": "LGPL-2.1-only"
        }
        self._board_data = {
            "name": json_info["BOARD"],
            "source_dir": json_info["BOARDDIR"]
        }
        self._external_module_data = []
        module_name_regex = re.compile(r' *MODULE[ \t]*[:\?]?=[ \t]*(?P<name>[A-Za-z0-9_]+)([\t ]*#.*)?')
        for module_path in json_info["EXTERNAL_MODULE_PATHS"]:
            module_path = module_path.rstrip('/')
            pkg_makefile = os.path.join(module_path, 'Makefile')
            if not os.path.isfile(pkg_makefile):
                raise RuntimeError(f"Loaded module at \"{module_path}\" does not have a Makefile.")
            module_name = os.path.basename(module_path)
            with open(pkg_makefile, 'rt') as makefile:
                for line in makefile:
                    m = module_name_regex.match(line)
                    if m and m.group("name"):
                        module_name = m.group("name")
                        break
            self._external_module_data.append(
                {
                    "name": module_name,
                    "source_dir": module_path
                }
            )
        self._package_data = []
        riotpkgs = [x for x in glob.glob(os.path.join(json_info["RIOTPKG"], "*"))
                                if os.path.isdir(x) and os.path.isfile(os.path.join(x, "Makefile"))]
        external_pkgs = []
        for pkgdir in json_info["EXTERNAL_PKG_DIRS"]:
            external_pkgs.extend([x for x in glob.glob(os.path.join(pkgdir, "*"))
                                if os.path.isdir(x) and os.path.isfile(os.path.join(x, "Makefile"))])
        available_pkgs = {}
        for pkg in riotpkgs + external_pkgs:
            available_pkgs[os.path.basename(pkg)] = pkg
        pkg_url_regex = re.compile(r'^ *PKG_URL[ \t]*[:\?]?=[ \t]*(?P<data>[^# \t\n\r]+)([\t ]*#.*)?$')
        pkg_ver_regex = re.compile(r'^ *PKG_VERSION[ \t]*[:\?]?=[ \t]*(?P<data>[^# \t\n\r]+)([\t ]*#.*)?$')
        pkg_lic_regex = re.compile(r'^ *PKG_LICENSE[ \t]*[:\?]?=[ \t]*(?P<data>[^# \t\n\r]+)([\t ]*#.*)?$')
        for pkg in json_info["USEPKG"]:
            if not pkg in available_pkgs:
                raise RuntimeError(f"Could not locate package \"{pkg}\"")
            pkg_path = available_pkgs[pkg]
            pkg_makefile = os.path.join(pkg_path, 'Makefile')
            if not os.path.isfile(pkg_makefile):
                raise RuntimeError(f"Loaded package at \"{pkg_path}\" does not have a Makefile.")
            pkg_url = ""
            pkg_license = ""
            pkg_version = ""
            with open(pkg_makefile, 'rt') as makefile:
                for line in makefile:
                    m = pkg_url_regex.match(line)
                    if m:
                        pkg_url = m.group('data')
                        continue
                    m = pkg_lic_regex.match(line)
                    if m:
                        pkg_license = m.group('data')
                        continue
                    m = pkg_ver_regex.match(line)
                    if m:
                        pkg_version = m.group('data')
                        continue
            self._package_data.append(
                {
                    "name": pkg,
                    "definition_dir": available_pkgs[pkg],
                    "source_dir": os.path.join(json_info["RIOTBASE"], "build", "pkg", pkg),
                    "url": pkg_url,
                    "version": pkg_version,
                    "license": pkg_license
                }
            )

    def _run_traced_build(self, trace_file: str):
        """
        Run a traced build of the application in the specified directory.

        This function performs a clean build followed by a traced build using `strace`.
        The traced build logs file access operations to the specified trace file.

        :param app_dir: The directory of the application to build.
        :type app_dir: str
        :param trace_file: The file where the trace output will be saved.
        :type trace_file: str
        :raises RuntimeError: If the clean or build process fails.
        """
        app_dir = self._app_dir.as_posix()
        logger.info('Retrieving file information for build (this may take a while)')
        clean_cmd = ["make", "-j", "clean"]
        clean_run = subprocess.run(clean_cmd,
                cwd=app_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        if clean_run.returncode != 0:
            raise RuntimeError(f'Failed to run make clean (stderr="{clean_run.stderr.decode("utf-8")}")')
        build_cmd = ["strace", "-f",
                    "-e", "trace=openat,open",
                    "-e", "quiet=attach,exit,path-resolution,personality,thread-execve,superseded",
                    "-o", f"{trace_file}", "make", "-j"]
        trace_run = subprocess.run(build_cmd,
                cwd=app_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        if trace_run.returncode != 0:
            raise RuntimeError(f'Failed to run make trace-build (stderr="{trace_run.stderr.decode("utf-8")}")')

    def _parse_trace_file(self, trace_file: str):
        """
        Parses a trace file to extract and resolve file paths.

        This function reads a trace file line by line, looking for lines that contain
        file open operations (`openat` or `open`). It extracts the file paths from these
        lines, resolves them to absolute paths, and filters out temporary files and
        non-regular files.

        :param trace_file: The path to the trace file to be parsed.
        :type trace_file: str
        :return: A sorted list of unique file paths found in the trace file.
        :rtype: list[str]
        """
        logger.info('Parsing trace file')
        file_paths = set()
        path_matcher = re.compile(r'[^"]*"(.*)"[^"]*')
        file_matcher = re.compile(r'.*\.(h|hpp|c|cpp|hxx|cxx|c\+\+|s|asm)$')
        with open(trace_file, 'r') as f:
            for line in f:
                if 'openat(' in line or "open(" in line:
                    match = path_matcher.match(line)
                    if match:
                        path = match.group(1)
                        if file_matcher.match(path):
                            path = str(pathlib.Path(path).resolve())
                            # ignore temporary files and only consider regular files
                            if (not path.startswith('/tmp/')
                                and os.path.isfile(path)):
                                file_paths.add(path)
        return sorted(file_paths)

    def _build_file_data(self, file_paths: list[str]):
        """
        Build file data for the given file paths.

        :param sbom_input: The input data for the SBOM (Software Bill of Materials).
        :type sbom_input: dict
        :param file_paths: A list of file paths to process.
        :type file_paths: list
        :param package_data: A list of package data.
        :type package_data: list
        """
        logger.info('Building file data')
        for file_path in file_paths:
            file_info = self._match_package_for_file(file_path)
            self._file_data.append(file_info)

    def _match_package_for_file(self, file_path):
        """
        Retrieve package name for a file, if possible.
        This function attempts to match a file path to a known package source directory.

        :param file_path: The path to the file being analyzed.
        :type file_path: str
        :return: A dictionary containing the file path and the associated package name.
        :rtype: dict
        """
        file_info = {
            'path': file_path,
            'package': None
        }
        if file_path.startswith(self._riot_data['source_dir']):
            file_info['package'] = ("RIOT OS", self._riot_data['source_dir'])
        # package data overrides RIOT data
        for package in self._package_data:
            if file_path.startswith(package['source_dir']):
                file_info['package'] = (package['name'], package['source_dir'])
                break
        for ext_mod in self._external_module_data:
            if file_path.startswith(ext_mod['source_dir']):
                file_info['package'] = (ext_mod['name'], ext_mod['source_dir'])
                break
        if file_path.startswith(self._app_data['source_dir']):
            file_info['package'] = (self._app_data['name'], self._app_data['source_dir'])
        return file_info


class BuildScannerTest(unittest.TestCase):
    def test_all(self):
        riot_dir = os.getenv('RIOTBASE', None)
        if riot_dir is None:
            self.skipTest("Environment variable RIOTBASE is not set.")
        riot_dir = pathlib.Path(riot_dir).absolute()
        app_dir = riot_dir.joinpath('tests', 'net', 'nanocoap_cli')
        if not app_dir.exists() or not app_dir.is_dir():
            self.skipTest(f"Application directory {app_dir} does not exist or is not a directory.")
        scanner = BuildScanner(app_dir)
        old_board = os.environ.get('BOARD')
        os.environ['BOARD'] = 'native64'
        scanner.run()
        if old_board is not None:
            os.environ['BOARD'] = old_board
        else:
            del os.environ['BOARD']
        self.assertEqual(scanner._app_data['name'], 'tests_nanocoap_cli')
        self.assertEqual(scanner._board_data['name'], 'native64')
        self.assertIsInstance(scanner._riot_data, dict)
        self.assertEqual(len(scanner._external_module_data), 0)
        self.assertGreater(len(scanner._package_data), 0)
        self.assertGreater(len(scanner._file_data), 0)
        app_info = scanner.get_app_info()
        self.assertIsInstance(app_info, AppInfo)
        self.assertIsNotNone(app_info.app_package_ref)
        self.assertIsNotNone(app_info.riot_package_ref)
        self.assertIsNotNone(app_info.board_package_ref)
        self.assertIn(app_info.app_package_ref, app_info.packages)
        self.assertEqual(app_info.packages[app_info.app_package_ref].name, 'tests_nanocoap_cli')
        self.assertIn(app_info.riot_package_ref, app_info.packages)
        self.assertEqual(app_info.packages[app_info.riot_package_ref].name, 'RIOT OS')
        self.assertIn(app_info.board_package_ref, app_info.packages)
        self.assertEqual(app_info.packages[app_info.board_package_ref].name, 'native64')
        self.assertEqual(len(app_info.packages), len(scanner._package_data)
                         + len(scanner._external_module_data) + 3)
        self.assertEqual(len(app_info.files), len(scanner._file_data))

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
