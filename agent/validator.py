"""
Flag Validator — scans text for flag patterns.

Supports multiple flag formats and can be configured via
CTF_FLAG_FORMAT environment variable.
"""

from __future__ import annotations

import re
from agent.config import COMPILED_FLAG_PATTERNS, DEFAULT_FLAG_PATTERN


def find_flags(text: str, pattern: str | None = None) -> list[str]:
    """
    Search *text* for all flag-like strings.

    If *pattern* is given it is used exclusively; otherwise every
    pattern in the compiled-pattern list is tried.

    Returns de-duplicated list of matches (order preserved).
    """
    if not text:
        return []

    if pattern:
        compiled = re.compile(pattern, re.DOTALL)
        return list(dict.fromkeys(compiled.findall(text)))

    seen: dict[str, None] = {}
    for regex in COMPILED_FLAG_PATTERNS:
        for match in regex.findall(text):
            seen.setdefault(match, None)
    return list(seen)


def has_flag(text: str, pattern: str | None = None) -> bool:
    """Return True if *text* contains at least one flag."""
    return len(find_flags(text, pattern)) > 0


def extract_first_flag(text: str, pattern: str | None = None) -> str | None:
    """Return the first flag found, or None."""
    flags = find_flags(text, pattern)
    return flags[0] if flags else None


def validate_format(flag: str, pattern: str | None = None) -> bool:
    """Return True if *flag* matches the expected format exactly."""
    pat = pattern or DEFAULT_FLAG_PATTERN
    return bool(re.fullmatch(pat, flag, re.DOTALL))
