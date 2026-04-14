"""Input validation helpers for cb toolkit."""
from __future__ import annotations

import os
import re


def validate_binary_path(path: str) -> str | None:
    """Validate that a path points to a readable file.

    Returns an error message string, or None if valid.
    """
    if not os.path.exists(path):
        return f"File not found: {path}"
    if os.path.isdir(path) and not (path.endswith(".app") or path.endswith(".framework")):
        return f"Path is a directory, not a file: {path}"
    if not os.access(path, os.R_OK):
        return f"File is not readable: {path}"
    return None


def validate_regex(pattern: str) -> str | None:
    """Validate that a string is a valid regex.

    Returns an error message string, or None if valid.
    """
    try:
        re.compile(pattern)
        return None
    except re.error as e:
        return f"Invalid regex '{pattern}': {e}"


def validate_piped_input(data: object) -> str | None:
    """Validate that pipeline input is a dict.

    Returns an error message string, or None if valid.
    """
    if not isinstance(data, dict):
        return f"Pipeline input must be a JSON object, got {type(data).__name__}"
    return None
