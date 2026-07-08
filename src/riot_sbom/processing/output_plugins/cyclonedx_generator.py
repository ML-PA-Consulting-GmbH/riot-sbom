"""
SPDX-FileCopyrightText: 2025 ML!PA Consulting GmbH
SPDX-License-Identifier: MIT
Author: Daniel Lockau <daniel.lockau@ml-pa.com>
"""

__all__ = ["CycloneDxGenerator", "CycloneDxBuilder"]


if __name__ == "__main__":
    import sys
    import pathlib
    sys.path.insert(0, pathlib.Path(__file__).absolute().parents[3].as_posix())


import importlib.metadata
import json
import logging
import pathlib
import re
import tempfile
import unittest
import urllib.parse

from cyclonedx.contrib.license.factories import LicenseFactory
from cyclonedx.model import (
    ExternalReference,
    ExternalReferenceType,
    HashAlgorithm,
    HashType,
    Property,
    XsUri,
)
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.contact import OrganizationalContact, OrganizationalEntity
from cyclonedx.model.license import LicenseAcknowledgement
from cyclonedx.model.tool import Tool
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

from riot_sbom.data.app_info import AppInfo
from riot_sbom.data.author_info import AuthorInfo, AuthorDeclarationType
from riot_sbom.data.checked_url import CheckedUrl
from riot_sbom.data.copyright_info import CopyrightDeclarationType, CopyrightInfo
from riot_sbom.data.file_info import DigestType, FileInfo
from riot_sbom.data.license_info import LicenseDeclarationType, LicenseInfo
from riot_sbom.data.package_info import PackageInfo, PackageReference
from riot_sbom.processing.plugin_type import Plugin
from riot_sbom.util.file_or_stdout_resource import FileOrStdoutResource


logger = logging.getLogger(__name__)


class CycloneDxBuilder:
    def __init__(
        self,
        schema_version: str = "1.6",
        include_files: bool = False,
        expand_alternate_purls: bool = False,
        alternate_purl_name_style: str = "ecosystem-project",
    ):
        self._license_factory = LicenseFactory()
        self._package_components: dict[PackageReference, Component] = {}
        self._schema_version = schema_version
        self._include_files = include_files
        self._expand_alternate_purls = expand_alternate_purls
        self._alternate_purl_name_style = alternate_purl_name_style

    def build(self, app_info: AppInfo) -> Bom:
        app_package = app_info.packages[app_info.app_package_ref]
        root_component = self._make_package_component(
            app_info.app_package_ref,
            app_package,
            component_type=ComponentType.APPLICATION,
            role="application",
        )
        bom = Bom(
            metadata=BomMetaData(
                tools=[Tool(name="riot_sbom", version=self._get_tool_version())],
                authors=self._make_contacts(app_package.authors),
                component=root_component,
                supplier=self._make_supplier(app_package.supplier),
            )
        )

        for package_ref, package_info in app_info.packages.items():
            if package_ref == app_info.app_package_ref:
                continue
            role = None
            if package_ref == app_info.riot_package_ref:
                role = "riot"
            elif package_ref == app_info.board_package_ref:
                role = "board"
            component = self._make_package_component(
                package_ref,
                package_info,
                component_type=ComponentType.LIBRARY,
                role=role,
            )
            self._package_components[package_ref] = component
            bom.components.add(component)

        alternate_purl_components: list[Component] = []
        if self._expand_alternate_purls:
            for package_ref, package_info in app_info.packages.items():
                if package_ref == app_info.app_package_ref:
                    continue
                canonical_component = self._package_components.get(package_ref)
                if canonical_component is None:
                    continue
                alt_components = self._make_alternate_purl_components(canonical_component, package_info)
                for alt_comp in alt_components:
                    bom.components.add(alt_comp)
                    alternate_purl_components.append(alt_comp)

        root_dependencies: list[Component] = list(self._package_components.values()) + alternate_purl_components
        package_file_dependencies: dict[PackageReference, list[Component]] = {}
        for file_info in app_info.files:
            if not self._include_files:
                break
            package_info = app_info.packages.get(file_info.package) if file_info.package else None
            component = self._make_file_component(file_info, package_info)
            bom.components.add(component)
            if file_info.package is None or file_info.package == app_info.app_package_ref:
                root_dependencies.append(component)
            elif file_info.package in self._package_components:
                package_file_dependencies.setdefault(file_info.package, []).append(component)
            else:
                logger.warning(
                    "File %s references package %s that is not available as a CycloneDX component. "
                    "Attaching file to root component.",
                    file_info.path,
                    file_info.package,
                )
                root_dependencies.append(component)

        bom.register_dependency(root_component, root_dependencies)
        for package_ref, component in self._package_components.items():
            bom.register_dependency(component, package_file_dependencies.get(package_ref, []))
        bom.validate()
        return bom

    def _make_package_component(
        self,
        package_ref: PackageReference,
        package_info: PackageInfo,
        *,
        component_type: ComponentType,
        role: str | None,
    ) -> Component:
        properties = self._make_common_properties(
            authors=package_info.authors,
            licenses=package_info.licenses,
            copyrights=package_info.copyrights,
        )
        if role:
            properties.append(Property(name="riot_sbom:role", value=role))
        if package_info.source_dir:
            properties.append(
                Property(name="riot_sbom:source_dir", value=package_info.source_dir.as_posix())
            )
        if package_info.host_distro_id:
            properties.append(Property(name="riot_sbom:host_distro_id", value=package_info.host_distro_id))
        if package_info.origin_distro_id:
            properties.append(Property(name="riot_sbom:origin_distro_id", value=package_info.origin_distro_id))
        if package_info.host_distro_name:
            properties.append(Property(name="riot_sbom:host_distro_name", value=package_info.host_distro_name))
        if package_info.alternate_purls:
            for alt_purl in package_info.alternate_purls:
                properties.append(Property(name="riot_sbom:alternate-purl", value=alt_purl))
        return Component(
            name=package_info.name,
            type=component_type,
            bom_ref=self._make_bom_ref("package", package_info.name, package_info.source_dir),
            version=package_info.version,
            cpe=package_info.cpe or None,
            purl=self._derive_purl(package_info),
            supplier=self._make_supplier(package_info.supplier),
            authors=self._make_contacts(package_info.authors),
            licenses=self._make_licenses(package_info.licenses),
            copyright=self._format_copyrights(package_info.copyrights),
            external_references=self._make_package_external_references(package_info.download_url),
            properties=properties,
        )

    def _make_file_component(
        self,
        file_info: FileInfo,
        package_info: PackageInfo | None,
    ) -> Component:
        properties = self._make_common_properties(
            authors=file_info.authors,
            licenses=file_info.licenses,
            copyrights=file_info.copyrights,
        )
        properties.append(Property(name="riot_sbom:path", value=file_info.path.as_posix()))
        return Component(
            name=self._make_file_name(file_info, package_info),
            type=ComponentType.FILE,
            bom_ref=self._make_bom_ref("file", file_info.path.name, file_info.path),
            version=self._make_file_version(file_info),
            hashes=self._make_hashes(file_info),
            licenses=self._make_licenses(file_info.licenses),
            copyright=self._format_copyrights(file_info.copyrights),
            authors=self._make_contacts(file_info.authors),
            properties=properties,
        )

    def _make_contacts(self, authors: list[AuthorInfo] | None) -> list[OrganizationalContact]:
        if not authors:
            return []
        return [
            OrganizationalContact(name=author.name, email=author.email)
            for author in authors
        ]

    def _make_supplier(self, supplier: str | None) -> OrganizationalEntity | None:
        if not supplier:
            return None
        return OrganizationalEntity(name=supplier)

    def _make_licenses(self, licenses: list[LicenseInfo] | None):
        if not licenses:
            return []
        mapped_licenses = []
        for license_info in licenses:
            acknowledgement = (
                LicenseAcknowledgement.CONCLUDED
                if license_info.declaration_type == LicenseDeclarationType.DERIVED
                else LicenseAcknowledgement.DECLARED
            )
            try:
                mapped_licenses.append(
                    self._license_factory.make_from_string(
                        license_info.declaration_text,
                        license_url=self._make_xs_uri(license_info.url),
                        license_acknowledgement=acknowledgement,
                    )
                )
            except Exception:
                logger.warning(
                    "Could not map license '%s' to CycloneDX. Skipping.",
                    license_info.declaration_text,
                )
        return mapped_licenses

    def _make_package_external_references(
        self,
        download_url: CheckedUrl | None,
    ) -> list[ExternalReference]:
        url = self._make_xs_uri(download_url)
        if url is None:
            return []
        return [ExternalReference(type=ExternalReferenceType.DISTRIBUTION, url=url)]

    def _make_hashes(self, file_info: FileInfo) -> list[HashType]:
        digest_to_hash_algorithm = {
            DigestType.MD5: HashAlgorithm.MD5,
            DigestType.SHA1: HashAlgorithm.SHA_1,
            DigestType.SHA256: HashAlgorithm.SHA_256,
            DigestType.SHA512: HashAlgorithm.SHA_512,
            DigestType.SHA3_256: HashAlgorithm.SHA3_256,
            DigestType.SHA3_384: HashAlgorithm.SHA3_384,
            DigestType.SHA3_512: HashAlgorithm.SHA3_512,
        }
        return [
            HashType(alg=algorithm, content=file_info.digests[digest_type])
            for digest_type, algorithm in digest_to_hash_algorithm.items()
            if digest_type in file_info.digests
        ]

    def _make_common_properties(
        self,
        *,
        authors: list[AuthorInfo] | None,
        licenses: list[LicenseInfo] | None,
        copyrights: list[CopyrightInfo] | None,
    ) -> list[Property]:
        properties = []
        if authors == []:
            properties.append(Property(name="riot_sbom:authors", value="unknown"))
        if licenses == []:
            properties.append(Property(name="riot_sbom:licenses", value="unknown"))
        if copyrights == []:
            properties.append(Property(name="riot_sbom:copyrights", value="unknown"))
        return properties

    def _format_copyrights(self, copyrights: list[CopyrightInfo] | None) -> str | None:
        if not copyrights:
            return None
        return "\n".join(
            f"{(copyright.tag + ' ') if copyright.tag else ''}{copyright.years} {copyright.holder}".strip()
            for copyright in copyrights
        )

    def _make_file_name(self, file_info: FileInfo, package_info: PackageInfo | None) -> str:
        if package_info and package_info.source_dir:
            try:
                return file_info.path.relative_to(package_info.source_dir).as_posix()
            except ValueError:
                return file_info.path.name
        return file_info.path.as_posix()

    def _make_file_version(self, file_info: FileInfo) -> str:
        sha1_digest = file_info.digests.get(DigestType.SHA1)
        if sha1_digest:
            return f"0.0.0-{sha1_digest[:12]}"
        return "0.0.0"

    def _make_bom_ref(
        self,
        kind: str,
        name: str,
        path: pathlib.Path | None,
    ) -> str:
        raw_value = path.as_posix() if path else name
        normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", raw_value.strip("/"))
        normalized = normalized.strip("-") or name
        return f"riot-sbom-{kind}-{normalized}"

    def _make_alternate_purl_components(
        self,
        canonical_component: Component,
        package_info: PackageInfo,
    ) -> list[Component]:
        if not package_info.alternate_purls:
            return []
        primary_purl = self._derive_purl(package_info)
        primary_purl_str = str(primary_purl) if primary_purl else None
        canonical_bom_ref = (
            canonical_component.bom_ref.value
            if hasattr(canonical_component.bom_ref, "value")
            else str(canonical_component.bom_ref)
        )
        result = []
        for alt_purl_str in package_info.alternate_purls:
            if not alt_purl_str:
                continue
            try:
                alt_purl = PackageURL.from_string(alt_purl_str)
            except ValueError:
                logger.warning(
                    "Skipping malformed alternate PURL '%s' for package '%s'.",
                    alt_purl_str,
                    package_info.name,
                )
                continue
            if primary_purl_str and str(alt_purl) == primary_purl_str:
                logger.debug(
                    "Alternate PURL '%s' matches primary PURL for '%s'. Skipping duplicate.",
                    alt_purl_str,
                    package_info.name,
                )
                continue
            bom_ref_suffix = f"{alt_purl.type}-{(alt_purl.namespace or '').replace('/', '-')}"
            bom_ref_suffix = re.sub(r"[^A-Za-z0-9._-]+", "-", bom_ref_suffix).strip("-")
            alt_bom_ref = f"{canonical_bom_ref}-alt-{bom_ref_suffix}"
            alt_name = self._make_alternate_purl_component_name(package_info.name, alt_purl)
            properties = [
                Property(name="riot_sbom:canonical-bom-ref", value=canonical_bom_ref),
                Property(name="riot_sbom:alternate-purl", value=alt_purl_str),
            ]
            duplicate = Component(
                name=alt_name,
                type=ComponentType.LIBRARY,
                bom_ref=alt_bom_ref,
                version=package_info.version,
                purl=alt_purl,
                properties=properties,
            )
            result.append(duplicate)
        return result

    def _make_alternate_purl_component_name(self, base_name: str, purl: PackageURL) -> str:
        if self._alternate_purl_name_style == "ecosystem-project":
            suffix_parts = [purl.type]
            if purl.namespace:
                suffix_parts.append(purl.namespace)
            return f"{base_name} [{'/'.join(suffix_parts)}]"
        return base_name

    def _derive_purl(self, package_info: PackageInfo) -> PackageURL | None:
        if package_info.purl:
            try:
                return PackageURL.from_string(package_info.purl)
            except ValueError:
                logger.warning("Could not parse explicit PURL '%s'. Falling back to derivation.", package_info.purl)

        inferred_purl = self._derive_vcs_purl(package_info)
        if inferred_purl is not None:
            return inferred_purl

        return PackageURL(
            type="generic",
            name=package_info.name,
            version=package_info.version,
        )

    def _derive_vcs_purl(self, package_info: PackageInfo) -> PackageURL | None:
        if package_info.download_url is None:
            return None

        parsed_url = urllib.parse.urlsplit(package_info.download_url.get())
        host = parsed_url.hostname.lower() if parsed_url.hostname else ""
        path_parts = [part for part in parsed_url.path.split("/") if part]

        if host in {"github.com", "www.github.com"} and len(path_parts) >= 2:
            namespace = path_parts[0]
            repo_name = path_parts[1]
            return PackageURL(
                type="github",
                namespace=namespace,
                name=self._normalize_repo_name(repo_name),
                version=package_info.version,
            )

        if host in {"gitlab.com", "www.gitlab.com"}:
            repo_parts = []
            for path_part in path_parts:
                if path_part in {"-", "archive", "releases", "raw", "uploads", "repository"}:
                    break
                repo_parts.append(path_part)
            if len(repo_parts) >= 2:
                return PackageURL(
                    type="gitlab",
                    namespace="/".join(repo_parts[:-1]),
                    name=self._normalize_repo_name(repo_parts[-1]),
                    version=package_info.version,
                )

        return None

    @staticmethod
    def _normalize_repo_name(repo_name: str) -> str:
        return repo_name.removesuffix(".git")

    def _make_xs_uri(self, url: CheckedUrl | None) -> XsUri | None:
        if url is None:
            return None
        checked_url = url.get()
        if not checked_url:
            return None
        try:
            return XsUri(checked_url)
        except ValueError:
            logger.warning("Could not convert URL '%s' to CycloneDX URI.", checked_url)
            return None

    @staticmethod
    def _get_tool_version() -> str | None:
        try:
            return importlib.metadata.version("riot_sbom")
        except importlib.metadata.PackageNotFoundError:
            return None


class CycloneDxGenerator(Plugin):
    def __init__(self):
        self._schema_version: str = "1.6"
        self._include_files: bool = False
        self._expand_alternate_purls: bool = False
        self._alternate_purl_name_style: str = "ecosystem-project"

    def get_name(self):
        return "cyclonedx-generator"

    def get_description(self):
        return "Writes a CycloneDX SBOM in JSON format."

    def get_cli_arguments(self) -> dict:
        return {
            "schema-version": {
                "choices": ["1.6", "1.7"],
                "default": "1.6",
                "help": "CycloneDX schema version to use (default: 1.6).",
            },
            "include-files": {
                "action": "store_true",
                "default": False,
                "help": "Include file-level components in the CycloneDX BOM.",
            },
            "expand-alternate-purls": {
                "action": "store_true",
                "default": False,
                "help": (
                    "Scanner mode: emit one synthetic duplicate component per alternate PURL "
                    "for each non-root library package, linked back to the canonical component."
                ),
            },
            "alternate-purl-name-style": {
                "choices": ["ecosystem-project"],
                "default": "ecosystem-project",
                "help": (
                    "Naming style for synthetic alternate-PURL components "
                    "(default: ecosystem-project)."
                ),
            },
        }

    def configure(self, **kwargs) -> None:
        if "schema_version" in kwargs:
            self._schema_version = kwargs["schema_version"]
        if "include_files" in kwargs:
            self._include_files = bool(kwargs["include_files"])
        if "expand_alternate_purls" in kwargs:
            self._expand_alternate_purls = bool(kwargs["expand_alternate_purls"])
        if "alternate_purl_name_style" in kwargs:
            self._alternate_purl_name_style = kwargs["alternate_purl_name_style"]

    def run(self, app_info: AppInfo, output_file_prefix: pathlib.Path | None) -> AppInfo:
        logger.info("Generating CycloneDX document")
        _schema_version_map = {
            "1.6": SchemaVersion.V1_6,
            "1.7": SchemaVersion.V1_7,
        }
        schema_version_enum = _schema_version_map.get(self._schema_version, SchemaVersion.V1_6)
        builder = CycloneDxBuilder(
            schema_version=self._schema_version,
            include_files=self._include_files,
            expand_alternate_purls=self._expand_alternate_purls,
            alternate_purl_name_style=self._alternate_purl_name_style,
        )
        bom = builder.build(app_info)
        outputter = make_outputter(bom, OutputFormat.JSON, schema_version_enum)
        output_file = (
            output_file_prefix.with_suffix(".sbom.cyclonedx.json")
            if output_file_prefix
            else None
        )
        with FileOrStdoutResource(output_file) as output_stream:
            output_stream.write(outputter.output_as_string(indent=2))
        return app_info


class TestCycloneDxGenerator(unittest.TestCase):
    def test_cyclonedx_generator(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            app_source_dir = temp_dir_path / "app"
            dep_source_dir = temp_dir_path / "dep"
            app_source_dir.mkdir()
            dep_source_dir.mkdir()

            app_package = PackageInfo(
                name="example-app",
                version="1.0.0",
                licenses=[
                    LicenseInfo(
                        declaration_text="MIT",
                        declaration_type=LicenseDeclarationType.EXACT_REFERENCE,
                        license_text=None,
                        url=None,
                    )
                ],
                copyrights=[
                    CopyrightInfo(
                        holder="Example Holder",
                        years="2025",
                        declaration_type=CopyrightDeclarationType.TEXT_TAGGED,
                        tag="SPDX-FileCopyrightText:",
                        url=None,
                    )
                ],
                download_url=CheckedUrl("https://example.com/example-app.tar.gz"),
                authors=[
                    AuthorInfo(
                        name="John Doe",
                        email="john@doe.com",
                        declaration_type=AuthorDeclarationType.TEXT_TAGGED,
                    )
                ],
                source_dir=app_source_dir,
                supplier="Example Supplier",
                purl="pkg:generic/example-app@1.0.0",
            )
            riot_package = PackageInfo(
                name="riot",
                version="2026.07",
                licenses=[],
                copyrights=None,
                download_url=CheckedUrl("https://example.com/riot.tar.gz"),
                authors=None,
                source_dir=dep_source_dir,
                supplier="RIOT",
            )
            board_package = PackageInfo(
                name="native",
                version="1.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=dep_source_dir,
                supplier=None,
            )
            dependency_package = PackageInfo(
                name="example-pkg",
                version="2.0.0",
                licenses=[
                    LicenseInfo(
                        declaration_text="Apache-2.0",
                        declaration_type=LicenseDeclarationType.EXACT_REFERENCE,
                        license_text=None,
                        url=None,
                    )
                ],
                copyrights=[],
                download_url=CheckedUrl("https://github.com/example-org/example-pkg/archive/refs/tags/v2.0.0.tar.gz"),
                authors=[],
                source_dir=dep_source_dir,
                supplier="Example Supplier",
            )
            app_info = AppInfo(
                build_dir=temp_dir_path / "build",
                app_package_ref=PackageReference.from_package_info(app_package),
                riot_package_ref=PackageReference.from_package_info(riot_package),
                board_package_ref=PackageReference.from_package_info(board_package),
                packages={
                    PackageReference.from_package_info(app_package): app_package,
                    PackageReference.from_package_info(riot_package): riot_package,
                    PackageReference.from_package_info(board_package): board_package,
                    PackageReference.from_package_info(dependency_package): dependency_package,
                },
                files=[],
            )
            app_file = app_source_dir / "main.c"
            app_file.write_text("int main(void) { return 0; }\n")
            dep_file = dep_source_dir / "lib.c"
            dep_file.write_text("void example(void) {}\n")
            app_info.files.append(
                FileInfo(
                    path=app_file,
                    package=app_info.app_package_ref,
                    licenses=app_package.licenses,
                    copyrights=app_package.copyrights,
                    authors=app_package.authors,
                )
            )
            app_info.files.append(
                FileInfo(
                    path=dep_file,
                    package=PackageReference.from_package_info(dependency_package),
                    licenses=dependency_package.licenses,
                    copyrights=dependency_package.copyrights,
                    authors=dependency_package.authors,
                )
            )

            plugin = CycloneDxGenerator()
            output_file_prefix = temp_dir_path / "test_output"
            new_app_info = plugin.run(app_info, output_file_prefix)

            self.assertIs(new_app_info, app_info)
            output_file = output_file_prefix.with_suffix(".sbom.cyclonedx.json")
            self.assertTrue(output_file.exists())

            output = json.loads(output_file.read_text())
            self.assertEqual(output["bomFormat"], "CycloneDX")
            self.assertEqual(output["specVersion"], "1.6")
            self.assertEqual(output["metadata"]["component"]["type"], "application")
            self.assertEqual(output["metadata"]["component"]["name"], "example-app")
            self.assertEqual(output["metadata"]["component"]["purl"], "pkg:generic/example-app@1.0.0")

            components_by_name = {
                component["name"]: component for component in output.get("components", [])
            }
            component_names = set(components_by_name)
            self.assertIn("example-pkg", component_names)
            # File components are excluded by default
            self.assertNotIn("main.c", component_names)
            self.assertNotIn("lib.c", component_names)
            self.assertEqual(
                components_by_name["example-pkg"]["purl"],
                "pkg:github/example-org/example-pkg@2.0.0",
            )

    def test_cyclonedx_generator_with_files(self):
        """File components appear when include_files is enabled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            app_source_dir = temp_dir_path / "app"
            dep_source_dir = temp_dir_path / "dep"
            app_source_dir.mkdir()
            dep_source_dir.mkdir()

            app_package = PackageInfo(
                name="example-app",
                version="1.0.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=app_source_dir,
                supplier=None,
                purl="pkg:generic/example-app@1.0.0",
            )
            dependency_package = PackageInfo(
                name="example-pkg",
                version="2.0.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=dep_source_dir,
                supplier=None,
            )
            app_info = AppInfo(
                build_dir=temp_dir_path / "build",
                app_package_ref=PackageReference.from_package_info(app_package),
                riot_package_ref=None,
                board_package_ref=None,
                packages={
                    PackageReference.from_package_info(app_package): app_package,
                    PackageReference.from_package_info(dependency_package): dependency_package,
                },
                files=[],
            )
            app_file = app_source_dir / "main.c"
            app_file.write_text("int main(void) { return 0; }\n")
            dep_file = dep_source_dir / "lib.c"
            dep_file.write_text("void lib(void) {}\n")
            app_info.files.append(
                FileInfo(
                    path=app_file,
                    package=app_info.app_package_ref,
                    licenses=None,
                    copyrights=None,
                    authors=None,
                )
            )
            app_info.files.append(
                FileInfo(
                    path=dep_file,
                    package=PackageReference.from_package_info(dependency_package),
                    licenses=None,
                    copyrights=None,
                    authors=None,
                )
            )

            plugin = CycloneDxGenerator()
            plugin.configure(schema_version="1.6", include_files=True)
            output_file_prefix = temp_dir_path / "test_output_with_files"
            plugin.run(app_info, output_file_prefix)

            output = json.loads(
                output_file_prefix.with_suffix(".sbom.cyclonedx.json").read_text()
            )
            component_names = {c["name"] for c in output.get("components", [])}
            self.assertIn("main.c", component_names)
            self.assertIn("lib.c", component_names)

    def test_cyclonedx_schema_version_override(self):
        """Schema version can be overridden to 1.7 via configure()."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            app_source_dir = temp_dir_path / "app"
            app_source_dir.mkdir()
            app_package = PackageInfo(
                name="my-app",
                version="1.0.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=app_source_dir,
                supplier=None,
                purl="pkg:generic/my-app@1.0.0",
            )
            app_info = AppInfo(
                build_dir=temp_dir_path / "build",
                app_package_ref=PackageReference.from_package_info(app_package),
                riot_package_ref=None,
                board_package_ref=None,
                packages={PackageReference.from_package_info(app_package): app_package},
                files=[],
            )
            plugin = CycloneDxGenerator()
            plugin.configure(schema_version="1.7", include_files=False)
            output_file_prefix = temp_dir_path / "test_v17"
            plugin.run(app_info, output_file_prefix)
            output = json.loads(
                output_file_prefix.with_suffix(".sbom.cyclonedx.json").read_text()
            )
            self.assertEqual(output["specVersion"], "1.7")

    def test_cyclonedx_cpe_in_output(self):
        """Packages with a cpe field emit it in the CycloneDX component."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            app_source_dir = temp_dir_path / "app"
            sys_source_dir = pathlib.Path("/")
            app_source_dir.mkdir()
            app_package = PackageInfo(
                name="my-app",
                version="1.0.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=app_source_dir,
                supplier=None,
                purl="pkg:generic/my-app@1.0.0",
            )
            sys_package = PackageInfo(
                name="libc6",
                version="2.39",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=sys_source_dir,
                supplier="Ubuntu",
                purl="pkg:deb/ubuntu/libc6@2.39",
                cpe="cpe:2.3:a:ubuntu:libc6:2.39:*:*:*:*:*:*:*",
            )
            app_info = AppInfo(
                build_dir=temp_dir_path / "build",
                app_package_ref=PackageReference.from_package_info(app_package),
                riot_package_ref=None,
                board_package_ref=None,
                packages={
                    PackageReference.from_package_info(app_package): app_package,
                    PackageReference.from_package_info(sys_package): sys_package,
                },
                files=[],
            )
            plugin = CycloneDxGenerator()
            output_file_prefix = temp_dir_path / "test_cpe"
            plugin.run(app_info, output_file_prefix)
            output = json.loads(
                output_file_prefix.with_suffix(".sbom.cyclonedx.json").read_text()
            )
            components_by_name = {c["name"]: c for c in output.get("components", [])}
            self.assertIn("libc6", components_by_name)
            self.assertEqual(
                components_by_name["libc6"].get("cpe"),
                "cpe:2.3:a:ubuntu:libc6:2.39:*:*:*:*:*:*:*",
            )

    def test_derive_purl_prefers_github_inference(self):
        builder = CycloneDxBuilder()

        package_info = PackageInfo(
            name="example-pkg",
            version="2.0.0",
            licenses=None,
            copyrights=None,
            download_url=CheckedUrl("https://github.com/example-org/example-pkg/releases/tag/v2.0.0"),
            authors=None,
            source_dir=None,
            supplier=None,
        )

        purl = builder._derive_purl(package_info)

        self.assertIsNotNone(purl)
        self.assertEqual(str(purl), "pkg:github/example-org/example-pkg@2.0.0")

    def test_provenance_properties_serialized_in_cyclonedx(self):
        """PackageInfo provenance fields appear as properties in CycloneDX output."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            app_source_dir = temp_dir_path / "app"
            sys_source_dir = pathlib.Path("/")
            app_source_dir.mkdir()

            app_package = PackageInfo(
                name="my-app",
                version="1.0.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=app_source_dir,
                supplier="Ubuntu",
                purl="pkg:generic/my-app@1.0.0",
            )
            sys_package = PackageInfo(
                name="libc6",
                version="2.39-0ubuntu8.7",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=sys_source_dir,
                supplier="Ubuntu",
                purl="pkg:deb/ubuntu/libc6@2.39-0ubuntu8.7?distro=ubuntu-24.04&arch=amd64",
                host_distro_id="neon",
                origin_distro_id="ubuntu",
                host_distro_name="KDE neon",
            )
            app_info = AppInfo(
                build_dir=temp_dir_path / "build",
                app_package_ref=PackageReference.from_package_info(app_package),
                riot_package_ref=None,
                board_package_ref=None,
                packages={
                    PackageReference.from_package_info(app_package): app_package,
                    PackageReference.from_package_info(sys_package): sys_package,
                },
                files=[],
            )

            plugin = CycloneDxGenerator()
            output_file_prefix = temp_dir_path / "test_provenance"
            plugin.run(app_info, output_file_prefix)

            output = json.loads(
                (output_file_prefix.with_suffix(".sbom.cyclonedx.json")).read_text()
            )
            components_by_name = {c["name"]: c for c in output.get("components", [])}
            self.assertIn("libc6", components_by_name)
            props = {
                p["name"]: p["value"]
                for p in components_by_name["libc6"].get("properties", [])
            }
            self.assertEqual(props.get("riot_sbom:host_distro_id"), "neon")
            self.assertEqual(props.get("riot_sbom:origin_distro_id"), "ubuntu")
            self.assertEqual(props.get("riot_sbom:host_distro_name"), "KDE neon")

    def test_alternate_purls_canonical_properties(self):
        """Alternate PURLs appear as riot_sbom:alternate-purl properties in canonical mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            app_source_dir = temp_dir_path / "app"
            dep_source_dir = temp_dir_path / "dep"
            app_source_dir.mkdir()
            dep_source_dir.mkdir()

            app_package = PackageInfo(
                name="my-app",
                version="1.0.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=app_source_dir,
                supplier=None,
                purl="pkg:generic/my-app@1.0.0",
            )
            dep_package = PackageInfo(
                name="libfoo",
                version="3.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=dep_source_dir,
                supplier=None,
                purl="pkg:deb/ubuntu/libfoo@3.0",
                alternate_purls=["pkg:conan/libfoo@3.0", "pkg:generic/libfoo@3.0"],
            )
            app_info = AppInfo(
                build_dir=temp_dir_path / "build",
                app_package_ref=PackageReference.from_package_info(app_package),
                riot_package_ref=None,
                board_package_ref=None,
                packages={
                    PackageReference.from_package_info(app_package): app_package,
                    PackageReference.from_package_info(dep_package): dep_package,
                },
                files=[],
            )

            plugin = CycloneDxGenerator()
            output_file_prefix = temp_dir_path / "test_alt_canonical"
            plugin.run(app_info, output_file_prefix)

            output = json.loads(
                output_file_prefix.with_suffix(".sbom.cyclonedx.json").read_text()
            )
            components_by_name = {c["name"]: c for c in output.get("components", [])}
            self.assertIn("libfoo", components_by_name)
            # Canonical mode: no extra duplicate components
            self.assertEqual(len(components_by_name), 1)
            alt_purl_props = [
                p["value"]
                for p in components_by_name["libfoo"].get("properties", [])
                if p["name"] == "riot_sbom:alternate-purl"
            ]
            self.assertIn("pkg:conan/libfoo@3.0", alt_purl_props)
            self.assertIn("pkg:generic/libfoo@3.0", alt_purl_props)

    def test_alternate_purls_scanner_mode_duplicates(self):
        """Scanner mode emits one duplicate component per alternate PURL."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            app_source_dir = temp_dir_path / "app"
            dep_source_dir = temp_dir_path / "dep"
            app_source_dir.mkdir()
            dep_source_dir.mkdir()

            app_package = PackageInfo(
                name="my-app",
                version="1.0.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=app_source_dir,
                supplier=None,
                purl="pkg:generic/my-app@1.0.0",
            )
            dep_package = PackageInfo(
                name="libfoo",
                version="3.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=dep_source_dir,
                supplier=None,
                purl="pkg:deb/ubuntu/libfoo@3.0",
                alternate_purls=["pkg:conan/libfoo@3.0"],
            )
            app_info = AppInfo(
                build_dir=temp_dir_path / "build",
                app_package_ref=PackageReference.from_package_info(app_package),
                riot_package_ref=None,
                board_package_ref=None,
                packages={
                    PackageReference.from_package_info(app_package): app_package,
                    PackageReference.from_package_info(dep_package): dep_package,
                },
                files=[],
            )

            plugin = CycloneDxGenerator()
            plugin.configure(expand_alternate_purls=True)
            output_file_prefix = temp_dir_path / "test_alt_scanner"
            plugin.run(app_info, output_file_prefix)

            output = json.loads(
                output_file_prefix.with_suffix(".sbom.cyclonedx.json").read_text()
            )
            components_by_name = {c["name"]: c for c in output.get("components", [])}
            # Canonical component still present
            self.assertIn("libfoo", components_by_name)
            # Duplicate for conan alternate
            duplicate_name = "libfoo [conan]"
            self.assertIn(duplicate_name, components_by_name)
            self.assertEqual(components_by_name[duplicate_name]["purl"], "pkg:conan/libfoo@3.0")
            # Back-reference to canonical
            dup_props = {
                p["name"]: p["value"]
                for p in components_by_name[duplicate_name].get("properties", [])
            }
            canonical_bom_ref = components_by_name["libfoo"]["bom-ref"]
            self.assertEqual(dup_props.get("riot_sbom:canonical-bom-ref"), canonical_bom_ref)
            # Duplicate appears in root dependencies
            root_deps = output.get("dependencies", [])
            root_dep_refs = next(
                (d["dependsOn"] for d in root_deps if d["ref"] == output["metadata"]["component"]["bom-ref"]),
                [],
            )
            dup_bom_ref = components_by_name[duplicate_name]["bom-ref"]
            self.assertIn(dup_bom_ref, root_dep_refs)

    def test_alternate_purls_scanner_mode_suffix_naming(self):
        """ecosystem-project naming style appends type and namespace as suffix."""
        builder = CycloneDxBuilder(expand_alternate_purls=True, alternate_purl_name_style="ecosystem-project")
        purl = PackageURL.from_string("pkg:deb/debian/libssl@3.0")
        name = builder._make_alternate_purl_component_name("libssl", purl)
        self.assertEqual(name, "libssl [deb/debian]")

    def test_alternate_purls_scanner_no_root_duplicates(self):
        """Root (application) component is not expanded in scanner mode."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            app_source_dir = temp_dir_path / "app"
            app_source_dir.mkdir()

            app_package = PackageInfo(
                name="my-app",
                version="1.0.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=app_source_dir,
                supplier=None,
                purl="pkg:generic/my-app@1.0.0",
                alternate_purls=["pkg:conan/my-app@1.0.0"],
            )
            app_info = AppInfo(
                build_dir=temp_dir_path / "build",
                app_package_ref=PackageReference.from_package_info(app_package),
                riot_package_ref=None,
                board_package_ref=None,
                packages={PackageReference.from_package_info(app_package): app_package},
                files=[],
            )

            plugin = CycloneDxGenerator()
            plugin.configure(expand_alternate_purls=True)
            output_file_prefix = temp_dir_path / "test_no_root_dup"
            plugin.run(app_info, output_file_prefix)

            output = json.loads(
                output_file_prefix.with_suffix(".sbom.cyclonedx.json").read_text()
            )
            components = output.get("components", [])
            # No library duplicates for the root application
            self.assertEqual(len(components), 0)

    def test_alternate_purls_skip_malformed(self):
        """Malformed alternate PURLs are skipped with a warning, not raising."""
        builder = CycloneDxBuilder(expand_alternate_purls=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            dep_source_dir = temp_dir_path / "dep"
            dep_source_dir.mkdir()
            canonical = Component(
                name="libfoo",
                type=ComponentType.LIBRARY,
                bom_ref="riot-sbom-package-dep-dep",
                version="1.0",
            )
            package_info = PackageInfo(
                name="libfoo",
                version="1.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=dep_source_dir,
                supplier=None,
                purl="pkg:deb/ubuntu/libfoo@1.0",
                alternate_purls=["not-a-valid-purl", "pkg:conan/libfoo@1.0"],
            )
            results = builder._make_alternate_purl_components(canonical, package_info)
            # Malformed entry skipped; valid one still returned
            self.assertEqual(len(results), 1)
            self.assertEqual(str(results[0].purl), "pkg:conan/libfoo@1.0")

    def test_alternate_purls_skip_primary_duplicate(self):
        """An alternate PURL that matches the primary PURL is not emitted."""
        builder = CycloneDxBuilder(expand_alternate_purls=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = pathlib.Path(temp_dir)
            dep_source_dir = temp_dir_path / "dep"
            dep_source_dir.mkdir()
            canonical = Component(
                name="libfoo",
                type=ComponentType.LIBRARY,
                bom_ref="riot-sbom-package-dep-dep",
                version="1.0",
            )
            package_info = PackageInfo(
                name="libfoo",
                version="1.0",
                licenses=None,
                copyrights=None,
                download_url=None,
                authors=None,
                source_dir=dep_source_dir,
                supplier=None,
                purl="pkg:deb/ubuntu/libfoo@1.0",
                alternate_purls=["pkg:deb/ubuntu/libfoo@1.0"],
            )
            results = builder._make_alternate_purl_components(canonical, package_info)
            self.assertEqual(len(results), 0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()