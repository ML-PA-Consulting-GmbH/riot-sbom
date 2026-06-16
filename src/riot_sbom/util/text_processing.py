"""
SPDX-FileCopyrightText: 2025 ML!PA Consulting GmbH
SPDX-License-Identifier: MIT
Author: Daniel Lockau <daniel.lockau@ml-pa.com>
"""

import json

def get_trailing_json_object(text: str) -> dict:
    """
    Extract the last JSON object from the given output string.

    This function searches for the last occurrence of a JSON object
    in the output string by locating the last closing brace `}` and
    searching backwards until it finds the corresponding opening brace `{`.
    It will not match braces in strings so it should work on any JSON
    object.

    :param text: The string containing at least one JSON object.
    :type text: str
    :return: The last JSON object found in the output.
    :rtype: dict
    :raises RuntimeError: If no valid JSON object is found.
    """
    end = text.rfind('}')
    if end == -1:
        raise RuntimeError('No JSON object found in output')
    start = end
    brace_count = 0
    in_string = False
    for pos in range(end, -1, -1):
        char = text[pos]
        if in_string:
            if pos == 0:
                raise RuntimeError('Unmatched quote in JSON object')
            if char == r'"' and text[pos - 1] != r"\\":
                in_string = False
        elif char == '"':
            in_string = True
        if in_string:
            continue
        # not in string
        if char == '}':
            brace_count += 1
        elif char == '{':
            brace_count -= 1
            if brace_count == 0:
                start = pos
                break
    if brace_count != 0:
        raise RuntimeError(f'Unmatched braces in JSON object. ')
    return json.loads(text[start:end + 1])
