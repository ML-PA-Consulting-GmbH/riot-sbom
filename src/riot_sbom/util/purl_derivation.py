"""
SPDX-FileCopyrightText: 2025 ML!PA Consulting GmbH
SPDX-License-Identifier: MIT
Author: Daniel Lockau <daniel.lockau@ml-pa.com>
"""

__all__ = [
    "derive_purl",
    "derive_debian_purl",
]

import logging
import unittest
import urllib.parse
from typing import Optional

logger = logging.getLogger(__name__)


def derive_purl(
    name: str,
    version: Optional[str] = None,
    download_url: Optional[str] = None,
) -> Optional[str]:
    """
    Derive a PURL for a package using the following priority:
    1. GitHub inference from download_url
    2. GitLab inference from download_url
    3. Generic fallback (pkg:generic/name@version)

    :param name: Package name
    :param version: Package version (optional)
    :param download_url: Download URL (optional)
    :return: PURL string or None
    """
    # Try VCS inference first
    if download_url:
        vcs_purl = _derive_vcs_purl(name, version, download_url)
        if vcs_purl:
            return vcs_purl

    # Fallback to generic PURL
    return _make_generic_purl(name, version)


def derive_debian_purl(
    name: str,
    version: Optional[str] = None,
    namespace: Optional[str] = "ubuntu",
    distro: Optional[str] = None,
    arch: Optional[str] = None,
) -> Optional[str]:
    """
    Derive a Debian-style PURL for system packages.
    Format: pkg:deb/<namespace>/<name>@<version>?distro=<distro>&arch=<arch>
    Qualifiers are included only when provided.

    :param name: Package name (Debian package name)
    :param version: Package version (optional)
    :param namespace: Distro namespace (defaults to ubuntu)
    :param distro: Distro qualifier value (optional)
    :param arch: Architecture qualifier value (optional)
    :return: PURL string
    """
    if not name:
        return None

    resolved_namespace = namespace or "ubuntu"
    purl = f"pkg:deb/{resolved_namespace}/{name}"
    if version:
        purl += f"@{version}"

    qualifiers = []
    if distro:
        qualifiers.append(("distro", urllib.parse.quote(distro, safe="")))
    if arch:
        qualifiers.append(("arch", urllib.parse.quote(arch, safe="")))
    if qualifiers:
        qualifier_str = "&".join(f"{key}={value}" for key, value in qualifiers)
        purl += f"?{qualifier_str}"

    return purl


def _derive_vcs_purl(
    name: str,
    version: Optional[str],
    download_url: str,
) -> Optional[str]:
    """
    Try to infer GitHub or GitLab PURL from download URL.

    :param name: Package name (used as fallback)
    :param version: Package version
    :param download_url: Download URL
    :return: PURL string or None if inference fails
    """
    try:
        parsed_url = urllib.parse.urlsplit(download_url)
    except Exception:
        return None

    host = parsed_url.hostname.lower() if parsed_url.hostname else ""
    path_parts = [part for part in parsed_url.path.split("/") if part]

    # GitHub
    if host in {"github.com", "www.github.com"} and len(path_parts) >= 2:
        namespace = path_parts[0]
        repo_name = path_parts[1]
        return _make_github_purl(namespace, _normalize_repo_name(repo_name), version)

    # GitLab
    if host in {"gitlab.com", "www.gitlab.com"}:
        repo_parts = []
        for path_part in path_parts:
            if path_part in {"-", "archive", "releases", "raw", "uploads", "repository"}:
                break
            repo_parts.append(path_part)
        if len(repo_parts) >= 2:
            return _make_gitlab_purl(
                "/".join(repo_parts[:-1]),
                _normalize_repo_name(repo_parts[-1]),
                version,
            )

    return None


def _make_generic_purl(name: str, version: Optional[str] = None) -> str:
    """
    Create a generic PURL.

    :param name: Package name
    :param version: Package version (optional)
    :return: Generic PURL string
    """
    if version:
        return f"pkg:generic/{name}@{version}"
    else:
        return f"pkg:generic/{name}"


def _make_github_purl(
    namespace: str,
    repo_name: str,
    version: Optional[str] = None,
) -> str:
    """
    Create a GitHub PURL.

    :param namespace: GitHub namespace (user or org)
    :param repo_name: Repository name
    :param version: Version (optional)
    :return: GitHub PURL string
    """
    if version:
        return f"pkg:github/{namespace}/{repo_name}@{version}"
    else:
        return f"pkg:github/{namespace}/{repo_name}"


def _make_gitlab_purl(
    namespace: str,
    repo_name: str,
    version: Optional[str] = None,
) -> str:
    """
    Create a GitLab PURL.

    :param namespace: GitLab namespace (can be hierarchical)
    :param repo_name: Repository name
    :param version: Version (optional)
    :return: GitLab PURL string
    """
    if version:
        return f"pkg:gitlab/{namespace}/{repo_name}@{version}"
    else:
        return f"pkg:gitlab/{namespace}/{repo_name}"


@staticmethod
def _normalize_repo_name(repo_name: str) -> str:
    """Remove .git suffix from repository name."""
    return repo_name.removesuffix(".git")


class TestPurlDerivation(unittest.TestCase):
    def test_derive_generic_purl_with_version(self):
        """Test generic PURL derivation with version."""
        purl = derive_purl("mypackage", "1.0.0", None)
        self.assertEqual(purl, "pkg:generic/mypackage@1.0.0")

    def test_derive_generic_purl_without_version(self):
        """Test generic PURL derivation without version."""
        purl = derive_purl("mypackage", None, None)
        self.assertEqual(purl, "pkg:generic/mypackage")

    def test_derive_github_purl(self):
        """Test GitHub PURL derivation from download URL."""
        purl = derive_purl(
            "repo",
            "1.0.0",
            "https://github.com/user/repo/archive/v1.0.0.tar.gz"
        )
        self.assertEqual(purl, "pkg:github/user/repo@1.0.0")

    def test_derive_github_purl_www(self):
        """Test GitHub PURL derivation with www subdomain."""
        purl = derive_purl(
            "repo",
            "1.0.0",
            "https://www.github.com/user/repo"
        )
        self.assertEqual(purl, "pkg:github/user/repo@1.0.0")

    def test_derive_github_purl_strips_git_suffix(self):
        """Test that .git suffix is removed from repo names."""
        purl = derive_purl(
            "repo",
            "2.0.0",
            "https://github.com/user/repo.git"
        )
        self.assertEqual(purl, "pkg:github/user/repo@2.0.0")

    def test_derive_gitlab_purl(self):
        """Test GitLab PURL derivation from download URL."""
        purl = derive_purl(
            "repo",
            "1.0.0",
            "https://gitlab.com/group/repo/archive/v1.0.0.tar.gz"
        )
        self.assertEqual(purl, "pkg:gitlab/group/repo@1.0.0")

    def test_derive_gitlab_purl_nested_namespace(self):
        """Test GitLab PURL derivation with nested namespace."""
        purl = derive_purl(
            "repo",
            "1.0.0",
            "https://gitlab.com/group/subgroup/repo/-/archive/v1.0.0/repo-1.0.0.tar.gz"
        )
        self.assertEqual(purl, "pkg:gitlab/group/subgroup/repo@1.0.0")

    def test_derive_debian_purl_with_version(self):
        """Test Debian PURL derivation with version."""
        purl = derive_debian_purl("bash", "5.1.16")
        self.assertEqual(purl, "pkg:deb/ubuntu/bash@5.1.16")

    def test_derive_debian_purl_without_version(self):
        """Test Debian PURL derivation without version."""
        purl = derive_debian_purl("bash", None)
        self.assertEqual(purl, "pkg:deb/ubuntu/bash")

    def test_derive_debian_purl_with_namespace(self):
        """Test Debian PURL derivation with explicit namespace."""
        purl = derive_debian_purl("bash", "5.1.16", namespace="debian")
        self.assertEqual(purl, "pkg:deb/debian/bash@5.1.16")

    def test_derive_debian_purl_with_distro_and_arch(self):
        """Test Debian PURL derivation with CVE-relevant qualifiers."""
        purl = derive_debian_purl(
            "bash",
            "5.1.16",
            namespace="ubuntu",
            distro="ubuntu-22.04",
            arch="amd64",
        )
        self.assertEqual(
            purl,
            "pkg:deb/ubuntu/bash@5.1.16?distro=ubuntu-22.04&arch=amd64",
        )

    def test_derive_debian_purl_with_url_encoded_qualifiers(self):
        """Test qualifier URL-encoding for Debian PURLs."""
        purl = derive_debian_purl(
            "bash",
            "5.1.16",
            distro="ubuntu 22.04",
            arch="x86/64",
        )
        self.assertEqual(
            purl,
            "pkg:deb/ubuntu/bash@5.1.16?distro=ubuntu%2022.04&arch=x86%2F64",
        )

    def test_derive_debian_purl_empty_name(self):
        """Test Debian PURL derivation with empty name returns None."""
        purl = derive_debian_purl("", None)
        self.assertIsNone(purl)

    def test_fallback_to_generic_when_url_invalid(self):
        """Test fallback to generic PURL when URL is invalid."""
        purl = derive_purl("mypackage", "1.0.0", "not-a-valid-url")
        self.assertEqual(purl, "pkg:generic/mypackage@1.0.0")

    def test_github_url_without_enough_parts(self):
        """Test that GitHub URL with insufficient path parts falls back to generic."""
        purl = derive_purl(
            "repo",
            "1.0.0",
            "https://github.com/user/"
        )
        self.assertEqual(purl, "pkg:generic/repo@1.0.0")

    def test_purl_without_version_from_url(self):
        """Test that PURL is derived even without version parameter."""
        purl = derive_purl(
            "repo",
            None,
            "https://github.com/user/repo"
        )
        self.assertEqual(purl, "pkg:github/user/repo")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()

