"""
SPDX-FileCopyrightText: 2025 ML!PA Consulting GmbH
SPDX-License-Identifier: MIT
Author: Daniel Lockau <daniel.lockau@ml-pa.com>
"""

import logging
logger = logging.getLogger(__name__)
import pathlib
import subprocess
from typing import List

def _get_command_output(cmd: List[str], cwd: pathlib.Path) -> str:
    """
    Raising wrapper to subprocess.run, capturing output.

    :param cmd: Command with arguments in subprocess.run list form.
    :type cmd: list[str]
    :param cwd: Working directory to execute the command in.
    :type cwd: pathlib.Path
    :return: Stdout buffer of the completed process as utf-8 string.
    :rtype: str
    :raises ValueError: If cwd parameter is not a directory.
    :raises RuntimeError: If command fails.
    """
    if not pathlib.Path.is_dir(cwd):
        raise ValueError(f"Parameter \"cwd\" is not a directory: {cwd}")
    subproc = subprocess.run(cmd,
                                    cwd=cwd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
    if subproc.returncode != 0:
        raise RuntimeError(f"Failed to run command {cmd} (stderr: \"{subproc.stderr.decode('utf-8')}\")")
    return subproc.stdout.decode('utf-8')

def get_git_commit(cwd: pathlib.Path) -> str:
    """
    Return the git commit SHA for the HEAD of the repository pointed to by
    the given path.

    :param cwd: Directory in which to execute the query.
    :type cwd: pathlib.Path
    :return: SHA as string.
    :rtype: str
    :raises ValueError: If cwd parameter is not a directory.
    :raises RuntimeError: If command fails.
    """
    return _get_command_output(['git', 'rev-parse', '--verify', 'HEAD'], cwd)

def get_repository_root(cwd: pathlib.Path) -> pathlib.Path:
    """
    Return the repository root for the repository pointed to by the given path.

    :param cwd: Directory in which to execute the query.
    :type cwd: pathlib.Path
    :return: Root directory of the repository which includes the given path.
    :rtype: pathlib.Path
    :raises ValueError: If cwd parameter is not a directory.
    :raises RuntimeError: If command fails.
    """
    return pathlib.PosixPath(_get_command_output(['git', 'rev-parse', '--show-toplevel'], cwd).strip())

def get_remotes_for_ref(ref: str, cwd: pathlib.Path):
    """
    Return the names of all remotes which hold a given reference.

    :param ref: Git reference.
    :type ref: str
    :param cwd: Directory in which to execute the query.
    :type cwd: pathlib.Path
    :return: List of names of the remotes which hold this reference. None if no remote was found (local ref).
    :rtype: list[str] | None
    :raises ValueError: If cwd parameter is not a directory.
    :raises RuntimeError: If command fails.
    """
    git_ref = _get_command_output(['git', 'rev-parse', '--verify', ref], cwd).strip()
    remote_names = set([x.strip().split('/')[0] for x in
        _get_command_output(['git', 'branch', '-r', '--color=never',
            '--no-column', '--no-format', '--contains', git_ref], cwd).strip().split('\n')
            if x.strip()])
    if not remote_names:
        logger.warning(f"No remote found for HEAD in repository at {get_repository_root(cwd)}.")
        return None
    return list(remote_names)

def get_url_for_remote(remote_name: str, cwd: pathlib.Path):
    """
    Return the URL for a given remote.

    :param remote_name: Name of the remote.
    :type remote_name: str
    :param cwd: Directory in which to execute the query.
    :type cwd: pathlib.Path
    :return: URL of the remote.
    :rtype: str
    :raises ValueError: If cwd parameter is not a directory.
    :raises RuntimeError: If command fails.
    """
    return _get_command_output(['git', 'remote', 'get-url', remote_name], cwd).strip()
