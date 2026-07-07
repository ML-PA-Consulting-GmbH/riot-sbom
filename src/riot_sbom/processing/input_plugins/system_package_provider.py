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
from unittest import mock

from riot_sbom.processing.plugin_type import Plugin
from riot_sbom.data.package_info import PackageInfo, PackageReference
from riot_sbom.data.app_info import AppInfo
from riot_sbom.util import purl_derivation


DEFAULT_DEBIAN_NAMESPACE = "ubuntu"

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
                                  ) -> str | None:
    """
    Finds the system package name for a given file path, if any.
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
    return package_name


def _query_package_version(package_name: str) -> str | None:
    """
    Look up a package version via dpkg tooling.
    """
    if not package_name:
        return None

    dpkg_query = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", package_name],
        capture_output=True,
        text=True,
        check=False,
    )
    if dpkg_query.returncode == 0:
        version = dpkg_query.stdout.strip()
        if version:
            return version

    dpkg_status = subprocess.run(
        ["dpkg", "-s", package_name],
        capture_output=True,
        text=True,
        check=False,
    )
    if dpkg_status.returncode != 0:
        return None

    for line in dpkg_status.stdout.splitlines():
        if line.startswith("Version:"):
            version = line.partition(":")[2].strip()
            return version if version else None
    return None


def _detect_architecture() -> str | None:
    """
    Detect the host package architecture for dpkg-based systems.
    """
    arch_query = subprocess.run(
        ["dpkg", "--print-architecture"],
        capture_output=True,
        text=True,
        check=False,
    )
    if arch_query.returncode != 0:
        return None
    architecture = arch_query.stdout.strip()
    return architecture if architecture else None


class SystemPackageProvider(Plugin):
    def __init__(
        self,
        default_distro_namespace: str | None = DEFAULT_DEBIAN_NAMESPACE,
        default_distro_qualifier: str | None = None,
    ):
        self._enabled = False
        self._supplier: str | None = None
        self._distro_id: str | None = None
        self._os_version: str | None = None
        self._architecture: str | None = None
        self._default_distro_namespace = (
            default_distro_namespace or DEFAULT_DEBIAN_NAMESPACE
        ).strip().lower()
        self._default_distro_qualifier = (
            default_distro_qualifier.strip().lower()
            if default_distro_qualifier else None
        )
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
        distro_id = os_release.get("ID", None)
        self._distro_id = distro_id.strip().lower() if distro_id else None
        self._os_version = os_release.get("VERSION_ID", None)
        self._architecture = _detect_architecture()
        self._enabled = True

    def _resolve_distro_namespace(self) -> str:
        if self._distro_id:
            return self._distro_id
        if self._default_distro_namespace:
            return self._default_distro_namespace
        return DEFAULT_DEBIAN_NAMESPACE

    def _resolve_distro_qualifier(self) -> str:
        if self._distro_id and self._os_version:
            return f"{self._distro_id}-{self._os_version}"
        if self._default_distro_qualifier:
            return self._default_distro_qualifier
        version = self._os_version if self._os_version else "unknown"
        return f"{DEFAULT_DEBIAN_NAMESPACE}-{version}"

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
                )
                if system_package:
                    package_version = _query_package_version(system_package)
                    logger.debug(f"Found system package '{system_package}' for file: {file.path}")
                    package_ref = PackageReference(system_package, pathlib.Path("/"))
                    if package_ref not in app_info.packages:
                        app_info.packages[package_ref] = PackageInfo(
                            name=system_package,
                            version=package_version,
                            supplier=self._supplier,
                            authors=None,
                            source_dir=pathlib.Path("/"), # for relative file path representation
                            download_url=None,
                            licenses=None,
                            copyrights=None,
                            purl=purl_derivation.derive_debian_purl(
                                system_package,
                                package_version,
                                namespace=self._resolve_distro_namespace(),
                                distro=self._resolve_distro_qualifier(),
                                arch=self._architecture,
                            ),
                        )
                    elif (not app_info.packages[package_ref].version
                          and package_version):
                        app_info.packages[package_ref].version = package_version
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
        package_name = _find_system_package_for_file(test_file)
        self.assertIsNotNone(package_name)
        if not package_name:
            # make linter happy
            return
        self.assertTrue(package_name)
        package_version = _query_package_version(package_name)
        self.assertIsNotNone(package_version)
        self.assertTrue(package_version)

    def test_no_system_package_found(self):
        if os.name != "posix" or shutil.which("dpkg") is None:
            self.skipTest("This test requires dpkg on a POSIX system.")
        import tempfile
        with tempfile.NamedTemporaryFile() as temp_file:
            test_file = pathlib.Path(temp_file.name)
            package_info = _find_system_package_for_file(test_file)
            self.assertIsNone(package_info, "Expected no system package to be found for a temporary file.")

    def test_query_package_version_returns_none_when_not_found(self):
        with mock.patch("subprocess.run") as run_mock:
            run_mock.side_effect = [
                subprocess.CompletedProcess(
                    args=["dpkg-query", "-W", "-f=${Version}", "pkg"],
                    returncode=1,
                    stdout="",
                    stderr="",
                ),
                subprocess.CompletedProcess(
                    args=["dpkg", "-s", "pkg"],
                    returncode=1,
                    stdout="",
                    stderr="",
                ),
            ]
            self.assertIsNone(_query_package_version("pkg"))

    def test_detect_architecture_returns_none_when_command_fails(self):
        with mock.patch("subprocess.run") as run_mock:
            run_mock.return_value = subprocess.CompletedProcess(
                args=["dpkg", "--print-architecture"],
                returncode=1,
                stdout="",
                stderr="",
            )
            self.assertIsNone(_detect_architecture())

    def test_ubuntu_defaults_when_os_release_incomplete(self):
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(
                f"{module_name}._read_os_release",
                return_value={},
            ):
                with mock.patch(
                    f"{module_name}._detect_architecture",
                    return_value=None,
                ):
                    provider = SystemPackageProvider()
        self.assertEqual(provider._resolve_distro_namespace(), "ubuntu")
        self.assertEqual(provider._resolve_distro_qualifier(), "ubuntu-unknown")

    def test_configured_fallbacks_are_used_when_distro_missing(self):
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(
                f"{module_name}._read_os_release",
                return_value={},
            ):
                with mock.patch(
                    f"{module_name}._detect_architecture",
                    return_value=None,
                ):
                    provider = SystemPackageProvider(
                        default_distro_namespace="debian",
                        default_distro_qualifier="debian-12",
                    )
        self.assertEqual(provider._resolve_distro_namespace(), "debian")
        self.assertEqual(provider._resolve_distro_qualifier(), "debian-12")

    def test_detected_distro_overrides_namespace_default(self):
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(
                f"{module_name}._read_os_release",
                return_value={
                    "ID": "debian",
                    "VERSION_ID": "12",
                    "NAME": "Debian GNU/Linux",
                },
            ):
                with mock.patch(
                    f"{module_name}._detect_architecture",
                    return_value="amd64",
                ):
                    provider = SystemPackageProvider(default_distro_namespace="ubuntu")
        self.assertEqual(provider._resolve_distro_namespace(), "debian")
        self.assertEqual(provider._resolve_distro_qualifier(), "debian-12")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
