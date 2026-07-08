"""
SPDX-FileCopyrightText: 2025 ML!PA Consulting GmbH
SPDX-License-Identifier: MIT
Author: Daniel Lockau <daniel.lockau@ml-pa.com>
"""

from .api import run_build
from .api import load_app_info
from .api import save_app_info
from .api import run_plugin

from pathlib import Path
import logging
logger = logging.getLogger(__name__)
from typing import List
import sys

def _make_plugin_arg_dest(plugin_name: str, arg_name: str) -> str:
    """Compute the argparse dest for a plugin-specific argument."""
    return f'{plugin_name.replace("-", "_")}__{arg_name.replace("-", "_")}'


def main() -> int:
    from .processing import plugin_registry
    import argparse

    # ── Preliminary parse: discover pipeline and external-plugin-dirs ──────────
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('--external-plugin-dirs', nargs='+', type=Path, required=False)
    pre_parser.add_argument('--plugin-pipeline', nargs='*', type=str,
                            required=False, default=[])
    pre_args, _ = pre_parser.parse_known_args()

    # Load external plugins early so plugin args can be discovered
    for ext_dir in pre_args.external_plugin_dirs or []:
        if ext_dir.is_dir():
            plugin_registry.load_plugins_from_directory(ext_dir)

    # Collect plugin instances that exist (skip unknown names here; validated below)
    pipeline_plugins: List = [
        plugin_registry.get_plugin(name)
        for name in pre_args.plugin_pipeline
        if plugin_registry.get_plugin(name) is not None
    ]

    # ── Build full parser ──────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(description = 'RIOT SBOM generator')
    parser.add_argument('--app-dir', type = Path,
                        help='Path to the directory of the application for which the SBOM should '\
                            'be built. `make -j` should build the application in that directory. '\
                            'Ignored if loading application information from a file, '\
                            'required otherwise.',
                        required=False)
    parser.add_argument('--save-app-info', type=Path,
                        help='Path to the file where application information is saved in python '\
                            'pickle format. Will be ignored if loading application information '\
                            'from a file. This step will run after the application build and '\
                            'after each successfully executed input plugin.',
                        required=False)
    parser.add_argument('--load-app-info', type=Path,
                        help='Path to the file from which application information is loaded in '\
                            'python pickle format. This will not execute an application build. '\
                            'All selected input plugins will be re-executed.',
                        required=False)
    parser.add_argument('--output-file-prefix', type=Path,
                        help='Prefix of output files, without extension. Required if output '\
                            'plugins are selected.',
                        required=False)
    parser.add_argument('--external-plugin-dirs', nargs='+', type=Path,
                        help='List of directories to search for loadable plugins.',
                        required=False)
    parser.add_argument('--list-plugins', action='store_true',
                        help='List all available plugins and exit.',
                        required=False)
    parser.add_argument('--plugin-pipeline', nargs='*', type=str,
                        help='List of input processing plugins to use for extraction of '\
                            'information or output generation. Plugins are expected to overwrite '\
                            'content created by other plugins, so highest priority should go last '\
                            'for anything altering the application information.',
                        required=False,
                        default=[])

    # Dynamically add plugin-specific arguments
    for plugin_instance in pipeline_plugins:
        cli_args = plugin_instance.get_cli_arguments()
        for arg_name, arg_config in cli_args.items():
            dest = _make_plugin_arg_dest(plugin_instance.get_name(), arg_name)
            parser.add_argument(
                f'--{plugin_instance.get_name()}:{arg_name}',
                dest=dest,
                **arg_config,
            )

    args = parser.parse_args()

    # (External plugins already loaded above; no need to reload)
    # Handle dirs that may not have existed during preliminary parse
    for ext_dir in args.external_plugin_dirs or []:
        if not ext_dir.is_dir():
            logger.error(f"Extension directory {ext_dir} does not exist. Aborting.")
            return 1

    if args.list_plugins:
        plugin_registry.print_plugin_list()
        return 0

    # Verify command line arguments
    non_existing_plugins = [x for x in args.plugin_pipeline
                            if x not in plugin_registry.get_plugin_names()]
    if non_existing_plugins:
        logger.error(f"The following selected plugins are not available: {non_existing_plugins}. "\
            f"Please run with `--list-plugins` to list available plugins.")
        return 1
    if args.load_app_info and args.app_dir:
        logger.error("Cannot specify both `--load-app-info` and `app-dir`. Please use one of them.")
        return 1
    if args.app_dir and not args.app_dir.is_dir():
        logger.error(f"Application directory {args.app_dir} does not exist. Aborting.")
        return 1
    if args.app_dir and not args.app_dir.joinpath('Makefile').is_file():
        logger.error(f"Application directory {args.app_dir} does not contain a Makefile. Aborting.")
        return 1
    if args.save_app_info and not args.save_app_info.parent.is_dir():
        logger.error(f"Cannot create output file {args.save_app_info}. "\
            f"Parent directory does not exist. Aborting.")
        return 1
    if args.load_app_info and not args.load_app_info.is_file():
        logger.error(f"Cannot load application information from {args.load_app_info}. "\
            f"File does not exist. Aborting.")
        return 1

    # Configure each plugin with its parsed CLI arguments
    for plugin_instance in pipeline_plugins:
        cli_args = plugin_instance.get_cli_arguments()
        if not cli_args:
            continue
        kwargs = {}
        for arg_name in cli_args:
            dest = _make_plugin_arg_dest(plugin_instance.get_name(), arg_name)
            kwargs[arg_name.replace('-', '_')] = getattr(args, dest)
        plugin_instance.configure(**kwargs)

    # Get application information
    if args.load_app_info:
        app_info = load_app_info(args.load_app_info)
    elif not args.app_dir:
        logger.error("No application directory specified and no application information file to "\
            "load. Please specify either `--app-dir` or `--load-app-info`.")
        parser.print_help(sys.stderr)
        return 1
    else:
        app_info = run_build(args.app_dir)
        if args.save_app_info:
            save_app_info(app_info, args.save_app_info)

    if not app_info:
        logger.error("No application information available. Aborting.")
        return 1

    # Run plugins (use already-configured instances for pipeline plugins)
    logger.info(f"Running plugins: {args.plugin_pipeline}")
    for plugin_instance in pipeline_plugins:
        new_app_info = plugin_instance.run(app_info, args.output_file_prefix)
        if not new_app_info:
            logger.warning(f"Plugin {plugin_instance.get_name()} does not conform to output spec.")
        elif args.save_app_info:
            save_app_info(app_info, args.save_app_info)

    return 0

if __name__ == '__main__':
    main()
