"""
SPDX-FileCopyrightText: 2025 ML!PA Consulting GmbH
SPDX-License-Identifier: MIT
Author: Daniel Lockau <daniel.lockau@ml-pa.com>
"""

if __name__ == "__main__":
    # update search path for local testing
    import sys
    import pathlib
    sys.path.insert(0,pathlib.Path(__file__).absolute().parents[3].as_posix())

import logging
logger = logging.getLogger(__name__)
import os
import pathlib
import shutil
import subprocess
from typing import Dict
import unittest

from riot_sbom.processing.plugin_type import Plugin
from riot_sbom.data.package_info import PackageInfo, PackageReference
from riot_sbom.data.app_info import AppInfo
from riot_sbom.util import purl_derivation

def _read_os_release() -> Dict[str, str]:
    """
    Read Linux distribution metadata from /etc/os-release if available.
    """
    os_release_path = pathlib.Path("/etc/os-release")
    if not os_release_path.is_file():
        return {}
    os_release: Dict[str, str] = {}
    with os_release_path.open("rt") as release_file:
        for line in release_file:
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.rstrip("\n").split("=", 1)
            os_release[key] = value.strip('"')
    return os_release


def _find_system_package_for_file(file_path: pathlib.Path,
                                  supplier: str | None,
                                  version: str | None) -> Dict[str, str] | None:
    """
    Finds the system package for a given file path, if any.
    """
    dpkg_query = subprocess.run(
        ["dpkg", "-S", str(file_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if dpkg_query.returncode != 0:
        return None
    package_name = dpkg_query.stdout.split(":", 1)[0].strip()
    if not package_name:
        return None
    package_info = {'name': package_name}
    if supplier:
        package_info['supplier'] = supplier
    if version:
        package_info['version'] = version
    return package_info


class SystemPackageProvider(Plugin):
    def __init__(self):
        self._enabled = False
        self._supplier: str | None = None
        self._version: str | None = None
        self._init_package_provider()

    def _init_package_provider(self):
        if os.name == "nt":
            logger.info("SystemPackageProvider is disabled: Microsoft Windows is not supported.")
            return
        if os.name != "posix":
            logger.info("SystemPackageProvider is disabled: unsupported os.name=%s", os.name)
            return
        if shutil.which("dpkg") is None:
            logger.info("SystemPackageProvider is disabled: dpkg was not found in PATH.")
            return
        os_release = _read_os_release()
        self._supplier = os_release.get("NAME", None)
        self._version = os_release.get("VERSION_ID", None)
        self._enabled = True

    def get_name(self):
        return "system-package-provider"

    def get_description(self):
        return "Will attempt to provide system package references for source files with no package relation."

    def run(self, app_info: AppInfo, _):
        if not self._enabled:
            logger.debug("SystemPackageProvider is disabled. Skipping package resolution.")
            return app_info
        for file in app_info.files:
            if not file.package and file.path.exists():
                system_package = _find_system_package_for_file(
                    file.path,
                    self._supplier,
                    self._version,
                )
                if system_package:
                    logger.debug(f"Found system package '{system_package}' for file: {file.path}")
                    package_ref = PackageReference(system_package['name'], pathlib.Path("/"))
                    if package_ref not in app_info.packages:
                        app_info.packages[package_ref] = PackageInfo(
                            name=system_package['name'],
                            version=system_package.get('version', None),
                            supplier=system_package.get('supplier', None),
                            authors=None,
                            source_dir=pathlib.Path("/"), # for relative file path representation
                            download_url=None,
                            licenses=None,
                            copyrights=None,
                            purl=purl_derivation.derive_debian_purl(
                                system_package['name'],
                                system_package.get('version', None)
                            ),
                        )
                    file.package = package_ref
                else:
                    logger.debug(f"No system package found for file: {file.path}")
        return app_info


class TestSystemPackageProvider(unittest.TestCase):
    def test_find_system_package_for_file(self):
        if os.name != "posix" or shutil.which("dpkg") is None:
            self.skipTest("This test requires dpkg on a POSIX system.")
        ls_location = subprocess.run(
            ["which", "ls"],
            capture_output=True,
            text=True,
            check=False,
        )
        if (ls_location.returncode != 0 or not ls_location.stdout.strip()
                or not pathlib.Path(ls_location.stdout.strip()).exists()):
            self.skipTest("The 'ls' command was not found on this system.")
        test_file = pathlib.Path(ls_location.stdout.strip())
        package_info = _find_system_package_for_file(test_file, "test-supplier", "test-version")
        self.assertIsNotNone(package_info)
        if not package_info:
            # make linter happy
            return
        self.assertIn('name', package_info)
        self.assertIn('supplier', package_info)
        self.assertIn('version', package_info)
        self.assertEqual(package_info['supplier'], "test-supplier")
        self.assertEqual(package_info['version'], "test-version")

    def test_no_system_package_found(self):
        if os.name != "posix" or shutil.which("dpkg") is None:
            self.skipTest("This test requires dpkg on a POSIX system.")
        import tempfile
        with tempfile.NamedTemporaryFile() as temp_file:
            test_file = pathlib.Path(temp_file.name)
            package_info = _find_system_package_for_file(test_file, None, None)
            self.assertIsNone(package_info, "Expected no system package to be found for a temporary file.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
