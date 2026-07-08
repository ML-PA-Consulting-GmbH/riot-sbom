# SBOM Creation for RIOT OS Based Applications

## About

The `sbom_riot` Python package is designed to generate and manage the Software
Bill of Materials (SBOM) for RIOT OS based software projects.

## Installing

Please build & install using [uv](https://docs.astral.sh/uv/).
The project now supports both SPDX and CycloneDX output generation.

## Running

This package is intended to be mainly executed through its command line
interface. After activating your virtual environment you should have
the `riot-sbom` script installed there.

Traced builds may take a longer time. The package therefore allows to save
data in between steps. Running a traced build on an application can be achieved
with:

```console
riot-sbom --app-dir <path-to-your-application> --save-app-info <path/to/app_info.pkl>
```

Saving is in pickle format. It is not intended for storage of data.
If the save option is provided, updates to the application information
will be saved or overwritten after the build and after each plugin execution.
Loading from a file can be combined with saving after executing plugins to
create intermediates before writing to any output formats:

```console
riot-sbom --load-app-info <path/to/app_info.pkl> \
    --save-app-info <path/to/app_info2.pkl>
    --plugin-pipeline copyrights-scanner authors-scanner spdx-identifiers-scanner \
                      system-package-provider infer-file-data-from-package
```

With a valid application information object, one or several output generator
plugins can also be executed in the pipeline:

```console
riot-sbom --load-app-info <path/to/app_info.pkl> \
    --output-file-prefix <path/to/outfilebase> \
    --plugin-pipeline copyrights-scanner authors-scanner spdx-identifiers-scanner \
                      system-package-provider infer-file-data-from-package spdx-generator
```

To generate a CycloneDX SBOM in JSON format instead, use the
`cyclonedx-generator` output plugin:

```console
riot-sbom --load-app-info <path/to/app_info.pkl> \
    --output-file-prefix <path/to/outfilebase> \
    --plugin-pipeline copyrights-scanner authors-scanner spdx-identifiers-scanner \
                      system-package-provider infer-file-data-from-package cyclonedx-generator
```

This will write the output to `<path/to/outfilebase>.sbom.cyclonedx.json`.

The `cyclonedx-generator` plugin supports the following options:

| Option | Default | Description |
|---|---|---|
| `--cyclonedx-generator:schema-version` | `1.6` | CycloneDX schema version (`1.6` or `1.7`). |
| `--cyclonedx-generator:include-files` | off | Include file-level components in the BOM. |
| `--cyclonedx-generator:expand-alternate-purls` | off | Scanner mode: emit one synthetic duplicate component per alternate PURL for each non-root library package (see below). |
| `--cyclonedx-generator:alternate-purl-name-style` | `ecosystem-project` | Naming style for synthetic alternate-PURL components. |

### Canonical mode (default)

Each package appears exactly once in the BOM. If a `PackageInfo` has `alternate_purls` set, those values are serialised as `riot_sbom:alternate-purl` custom properties on the canonical component, preserving the alternate identities without duplicating the component.

### Scanner mode (`--cyclonedx-generator:expand-alternate-purls`)

In scanner mode each non-root library component with alternate PURLs also gets one synthetic duplicate component per alternate PURL. The duplicate:

- has its `purl` set to the alternate value,
- is named with a suffix derived from the PURL's ecosystem and namespace (e.g. `libfoo [conan]` or `libfoo [deb/ubuntu]` with the default `ecosystem-project` style),
- carries a `riot_sbom:canonical-bom-ref` property pointing back to the canonical component,
- is registered as an additional root dependency.

The root application component is never duplicated.

Example — emit a scanner-mode BOM:

```console
riot-sbom --load-app-info <path/to/app_info.pkl> \
    --output-file-prefix <path/to/outfilebase> \
    --plugin-pipeline system-package-provider infer-file-data-from-package cyclonedx-generator \
    --cyclonedx-generator:expand-alternate-purls
```

Example — emit a v1.7 BOM with file-level components:
riot-sbom --load-app-info <path/to/app_info.pkl> \
    --output-file-prefix <path/to/outfilebase> \
    --plugin-pipeline copyrights-scanner authors-scanner spdx-identifiers-scanner \
                      system-package-provider infer-file-data-from-package cyclonedx-generator \
    --cyclonedx-generator:schema-version 1.7 \
    --cyclonedx-generator:include-files
```

All tasks can be executed in one go of course, without saving
intermediate information to the file system:

```console
riot-sbom --app-dir <path-to-your-application> \
    --output-file-prefix <path/to/outfilebase> \
    --plugin-pipeline copyrights-scanner authors-scanner spdx-identifiers-scanner \
                      system-package-provider infer-file-data-from-package spdx-generator
```

CycloneDX generation can also be done in one go:

```console
riot-sbom --app-dir <path-to-your-application> \
    --output-file-prefix <path/to/outfilebase> \
    --plugin-pipeline copyrights-scanner authors-scanner spdx-identifiers-scanner \
                      system-package-provider infer-file-data-from-package cyclonedx-generator
```

Available default plugins can be listed via `riot-sbom --list-plugins`.

## Extending

The package supports dynamic loading of plugins.
If you have plugins implementing `riot_sbom.processing.plugin_type.Plugin`,
you can provide their directories on the command line for loading.

The following command will load and list all available plugins:

```console
riot-sbom --external-plugin-dirs <path/to/plugin/dir1> <path/to/plugin/dir2> --list-plugins
```
