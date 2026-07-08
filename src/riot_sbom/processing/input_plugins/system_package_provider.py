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
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple
import unittest
from unittest import mock

from riot_sbom.processing.plugin_type import Plugin
from riot_sbom.data.package_info import PackageInfo, PackageReference
from riot_sbom.data.app_info import AppInfo
from riot_sbom.util import purl_derivation


DEFAULT_DEBIAN_NAMESPACE = "ubuntu"

# Display names for known Debian-family distro ids.
_KNOWN_DISTRO_DISPLAY_NAMES: Dict[str, str] = {
    "ubuntu": "Ubuntu",
    "debian": "Debian",
    "linuxmint": "Linux Mint",
    "raspbian": "Raspbian",
    "pop": "Pop!_OS",
    "elementary": "elementary OS",
}

# Mapping from maintainer e-mail domains to distro ids.
_MAINTAINER_DOMAIN_TO_DISTRO: Dict[str, str] = {
    "ubuntu.com": "ubuntu",
    "debian.org": "debian",
}


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


def _query_package_maintainer(package_name: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Query dpkg -s for the Maintainer and Original-Maintainer fields of a package.
    Returns (maintainer, original_maintainer); either may be None.
    """
    if not package_name:
        return None, None
    dpkg_status = subprocess.run(
        ["dpkg", "-s", package_name],
        capture_output=True,
        text=True,
        check=False,
    )
    if dpkg_status.returncode != 0:
        return None, None
    maintainer: Optional[str] = None
    original_maintainer: Optional[str] = None
    for line in dpkg_status.stdout.splitlines():
        if line.startswith("Maintainer:"):
            maintainer = line.partition(":")[2].strip() or None
        elif line.startswith("Original-Maintainer:"):
            original_maintainer = line.partition(":")[2].strip() or None
    return maintainer, original_maintainer


def _detect_distro_from_maintainer(maintainer: Optional[str]) -> Optional[str]:
    """
    Attempt to identify the originating distro id from a dpkg Maintainer field.
    Checks e-mail domain first, then falls back to substring matching.
    """
    if not maintainer:
        return None
    email_match = re.search(r'<[^>]*@([^>]+)>', maintainer)
    if email_match:
        domain = email_match.group(1).lower()
        for known_domain, distro in _MAINTAINER_DOMAIN_TO_DISTRO.items():
            if domain == known_domain or domain.endswith(f".{known_domain}"):
                return distro
    maintainer_lower = maintainer.lower()
    for text, distro in [("ubuntu", "ubuntu"), ("debian", "debian")]:
        if text in maintainer_lower:
            return distro
    return None


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
        self._id_like_candidates: List[str] = []
        self._host_distro_id: str | None = None
        self._host_distro_name: str | None = None
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
        id_like_raw = os_release.get("ID_LIKE", None)
        self._id_like_candidates = (
            [s.strip().lower() for s in id_like_raw.split() if s.strip()]
            if id_like_raw else []
        )
        self._host_distro_id = self._distro_id
        self._host_distro_name = self._supplier
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

    def _resolve_origin_distro_id(self, maintainer_signal: Optional[str]) -> Optional[str]:
        """
        Resolve the origin distro id for a package using precedence:
        1. Package-level maintainer signal (parsed from dpkg -s Maintainer field)
        2. First recognised ID_LIKE candidate from /etc/os-release
        3. Host distro id (fallback)
        """
        if maintainer_signal:
            return maintainer_signal
        if self._id_like_candidates:
            return self._id_like_candidates[0]
        return self._distro_id

    def _get_origin_supplier_name(self, origin_distro_id: Optional[str]) -> Optional[str]:
        """
        Return the human-readable supplier name for an origin distro id.
        Falls back to the host supplier name when the id is unknown.
        """
        if not origin_distro_id:
            return self._supplier
        return _KNOWN_DISTRO_DISPLAY_NAMES.get(origin_distro_id, self._supplier)

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
                        maintainer, original_maintainer = _query_package_maintainer(system_package)
                        maint_signal = (
                            _detect_distro_from_maintainer(maintainer)
                            or _detect_distro_from_maintainer(original_maintainer)
                        )
                        origin_distro_id = self._resolve_origin_distro_id(maint_signal)
                        purl_namespace = (
                            origin_distro_id
                            if origin_distro_id
                            else self._resolve_distro_namespace()
                        )
                        purl_distro = (
                            f"{origin_distro_id}-{self._os_version}"
                            if origin_distro_id and self._os_version
                            else self._resolve_distro_qualifier()
                        )
                        origin_supplier = self._get_origin_supplier_name(origin_distro_id)
                        cpe_vendor = (origin_distro_id or self._resolve_distro_namespace()).replace("-", "_")
                        cpe_product = system_package.replace("-", "_")
                        cpe_version = (package_version or "*").replace(":", "\\:")
                        cpe = (
                            f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:{cpe_version}"
                            ":*:*:*:*:*:*:*"
                        ) if package_version else None
                        app_info.packages[package_ref] = PackageInfo(
                            name=system_package,
                            version=package_version,
                            supplier=origin_supplier,
                            authors=None,
                            source_dir=pathlib.Path("/"), # for relative file path representation
                            download_url=None,
                            licenses=None,
                            copyrights=None,
                            purl=purl_derivation.derive_debian_purl(
                                system_package,
                                package_version,
                                namespace=purl_namespace,
                                distro=purl_distro,
                                arch=self._architecture,
                            ),
                            cpe=cpe,
                            host_distro_id=self._host_distro_id,
                            origin_distro_id=origin_distro_id,
                            host_distro_name=self._host_distro_name,
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

    def test_detect_distro_from_maintainer_ubuntu_email(self):
        self.assertEqual(
            _detect_distro_from_maintainer("Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"),
            "ubuntu",
        )

    def test_detect_distro_from_maintainer_debian_email(self):
        self.assertEqual(
            _detect_distro_from_maintainer("Debian Kernel Team <debian-kernel@lists.debian.org>"),
            "debian",
        )

    def test_detect_distro_from_maintainer_none(self):
        self.assertIsNone(_detect_distro_from_maintainer(None))
        self.assertIsNone(_detect_distro_from_maintainer("Unknown Maintainer <unknown@example.com>"))

    def test_resolve_origin_distro_id_uses_maintainer_signal(self):
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(
                f"{module_name}._read_os_release",
                return_value={
                    "ID": "neon",
                    "VERSION_ID": "24.04",
                    "NAME": "KDE neon",
                    "ID_LIKE": "ubuntu debian",
                },
            ):
                with mock.patch(f"{module_name}._detect_architecture", return_value="amd64"):
                    provider = SystemPackageProvider()
        self.assertEqual(provider._resolve_origin_distro_id("ubuntu"), "ubuntu")
        self.assertEqual(provider._resolve_origin_distro_id("debian"), "debian")

    def test_resolve_origin_distro_id_falls_back_to_id_like(self):
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(
                f"{module_name}._read_os_release",
                return_value={
                    "ID": "neon",
                    "VERSION_ID": "24.04",
                    "NAME": "KDE neon",
                    "ID_LIKE": "ubuntu debian",
                },
            ):
                with mock.patch(f"{module_name}._detect_architecture", return_value="amd64"):
                    provider = SystemPackageProvider()
        # No maintainer signal → first ID_LIKE candidate
        self.assertEqual(provider._resolve_origin_distro_id(None), "ubuntu")

    def test_resolve_origin_distro_id_falls_back_to_host_when_no_id_like(self):
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(
                f"{module_name}._read_os_release",
                return_value={"ID": "neon", "VERSION_ID": "24.04", "NAME": "KDE neon"},
            ):
                with mock.patch(f"{module_name}._detect_architecture", return_value="amd64"):
                    provider = SystemPackageProvider()
        self.assertEqual(provider._resolve_origin_distro_id(None), "neon")

    def test_get_origin_supplier_name_known_id(self):
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(f"{module_name}._read_os_release", return_value={"NAME": "KDE neon"}):
                with mock.patch(f"{module_name}._detect_architecture", return_value="amd64"):
                    provider = SystemPackageProvider()
        self.assertEqual(provider._get_origin_supplier_name("ubuntu"), "Ubuntu")
        self.assertEqual(provider._get_origin_supplier_name("debian"), "Debian")

    def test_get_origin_supplier_name_unknown_id_falls_back_to_host(self):
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(
                f"{module_name}._read_os_release", return_value={"NAME": "KDE neon"}
            ):
                with mock.patch(f"{module_name}._detect_architecture", return_value="amd64"):
                    provider = SystemPackageProvider()
        self.assertEqual(provider._get_origin_supplier_name("neon"), "KDE neon")

    def test_neon_derivative_purl_and_supplier(self):
        """System packages on KDE Neon should resolve to Ubuntu origin."""
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(
                f"{module_name}._read_os_release",
                return_value={
                    "ID": "neon",
                    "VERSION_ID": "24.04",
                    "NAME": "KDE neon",
                    "ID_LIKE": "ubuntu debian",
                },
            ):
                with mock.patch(f"{module_name}._detect_architecture", return_value="amd64"):
                    provider = SystemPackageProvider()

        import tempfile
        from riot_sbom.data.app_info import AppInfo
        from riot_sbom.data.file_info import FileInfo
        with tempfile.TemporaryDirectory() as tmp:
            fake_file = pathlib.Path(tmp) / "libc6.so"
            fake_file.touch()
            app_pkg_ref = PackageReference("app", pathlib.Path(tmp))
            app_info = AppInfo(
                build_dir=pathlib.Path(tmp),
                app_package_ref=app_pkg_ref,
                riot_package_ref=None,
                board_package_ref=None,
                packages={app_pkg_ref: PackageInfo(
                    name="app", version="1.0", supplier=None, authors=None,
                    source_dir=pathlib.Path(tmp), download_url=None,
                    licenses=None, copyrights=None,
                )},
                files=[FileInfo(
                    path=fake_file, package=None, licenses=None, copyrights=None, authors=None,
                )],
            )
            with mock.patch(f"{module_name}._find_system_package_for_file", return_value="libc6"):
                with mock.patch(f"{module_name}._query_package_version", return_value="2.39-0ubuntu8.7"):
                    with mock.patch(f"{module_name}._query_package_maintainer", return_value=(
                        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
                        None,
                    )):
                        provider.run(app_info, None)

        pkg_ref = PackageReference("libc6", pathlib.Path("/"))
        self.assertIn(pkg_ref, app_info.packages)
        pkg = app_info.packages[pkg_ref]
        self.assertEqual(pkg.supplier, "Ubuntu")
        self.assertEqual(pkg.host_distro_id, "neon")
        self.assertEqual(pkg.origin_distro_id, "ubuntu")
        self.assertEqual(pkg.host_distro_name, "KDE neon")
        self.assertIsNotNone(pkg.purl)
        self.assertIn("pkg:deb/ubuntu/libc6@2.39-0ubuntu8.7", pkg.purl)
        self.assertIn("distro=ubuntu-24.04", pkg.purl)

    def test_missing_maintainer_falls_back_to_id_like(self):
        """When dpkg -s returns no Maintainer, ID_LIKE is used for origin."""
        module_name = __name__
        with mock.patch("shutil.which", return_value="/usr/bin/dpkg"):
            with mock.patch(
                f"{module_name}._read_os_release",
                return_value={
                    "ID": "neon",
                    "VERSION_ID": "24.04",
                    "NAME": "KDE neon",
                    "ID_LIKE": "ubuntu debian",
                },
            ):
                with mock.patch(f"{module_name}._detect_architecture", return_value="amd64"):
                    provider = SystemPackageProvider()

        import tempfile
        from riot_sbom.data.app_info import AppInfo
        from riot_sbom.data.file_info import FileInfo
        with tempfile.TemporaryDirectory() as tmp:
            fake_file = pathlib.Path(tmp) / "somefile"
            fake_file.touch()
            app_pkg_ref = PackageReference("app", pathlib.Path(tmp))
            app_info = AppInfo(
                build_dir=pathlib.Path(tmp),
                app_package_ref=app_pkg_ref,
                riot_package_ref=None,
                board_package_ref=None,
                packages={app_pkg_ref: PackageInfo(
                    name="app", version="1.0", supplier=None, authors=None,
                    source_dir=pathlib.Path(tmp), download_url=None,
                    licenses=None, copyrights=None,
                )},
                files=[FileInfo(
                    path=fake_file, package=None, licenses=None, copyrights=None, authors=None,
                )],
            )
            with mock.patch(f"{module_name}._find_system_package_for_file", return_value="somepkg"):
                with mock.patch(f"{module_name}._query_package_version", return_value="1.0"):
                    with mock.patch(f"{module_name}._query_package_maintainer", return_value=(None, None)):
                        provider.run(app_info, None)

        pkg_ref = PackageReference("somepkg", pathlib.Path("/"))
        self.assertIn(pkg_ref, app_info.packages)
        pkg = app_info.packages[pkg_ref]
        # No maintainer signal → fallback to first ID_LIKE = ubuntu
        self.assertEqual(pkg.origin_distro_id, "ubuntu")
        self.assertEqual(pkg.supplier, "Ubuntu")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
