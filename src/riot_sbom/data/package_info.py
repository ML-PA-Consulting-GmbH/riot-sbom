"""
SPDX-FileCopyrightText: 2025 ML!PA Consulting GmbH
SPDX-License-Identifier: MIT
Author: Daniel Lockau <daniel.lockau@ml-pa.com>
"""

__all__ = ["PackageInfo"]

from dataclasses import dataclass
from pathlib import Path
from typing import List

from .author_info import AuthorInfo
from .copyright_info import CopyrightInfo
from .license_info import LicenseInfo
from .checked_url import CheckedUrl


@dataclass
class PackageInfo:
    # @TODO parent package reference?
    name: str
    supplier: str | None
    authors: List[AuthorInfo] | None
    version: str | None
    source_dir: Path | None
    download_url: CheckedUrl | None
    licenses: List[LicenseInfo] | None
    copyrights: List[CopyrightInfo] | None
    purl: str | None = None
    cpe: str | None = None
    # Provenance fields for derivative distro tracking (system packages only)
    host_distro_id: str | None = None
    origin_distro_id: str | None = None
    host_distro_name: str | None = None


class PackageReference:
    """
    A reference to a package, uniquely identified by its name and source directory.

    This has been added to avoid multiple references to the same package
    as well as weak references, as they will not serialize via pickle.
    """
    def __init__(self, pkg_name: str, source_dir: Path | None = None):
        if not pkg_name:
            raise ValueError("Package name must not be empty.")
        self.__ref = f"{pkg_name}--{source_dir.absolute().as_posix()
                                  if source_dir else ''}"

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, PackageReference):
            return False
        return self.__ref == value.__ref

    def __hash__(self) -> int:
        return hash(self.__ref)


    @classmethod
    def from_package_info(cls, pkg: PackageInfo) -> 'PackageReference':
        """
        Create a PackageReference from a PackageInfo object.
        """
        return cls(pkg.name, pkg.source_dir)
