#!/usr/bin/env python3
"""Sources module: defines data sources and PHP source detection."""
import re
from typing import Dict, Set, Pattern

# ============================================================================
# PHP SOURCES (requested)
# ============================================================================
PHP_SOURCE_REGEX = re.compile(
    r"""(?ix)
    (?:\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV|SESSION)\b)
    |(?:php://input\b)
    |(?:\$HTTP_RAW_POST_DATA\b)
    """
)

# PHP require/include fallback regex
PHP_REQUIRE_REGEX = re.compile(r"\b(require_once|require|include_once|include)\b", re.IGNORECASE)

# crude comment stripping for PHP (helps regex fallback)
PHP_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
PHP_LINE_COMMENT_RE = re.compile(r"(?m)//.*?$|#.*?$")


def is_php_source(text: str) -> bool:
    """Return True if the text contains PHP source indicators (superglobals, php://input)."""
    return bool(PHP_SOURCE_REGEX.search(text or ""))


def strip_php_comments(text: str) -> str:
    """Strip PHP comments from text for regex fallback."""
    text = PHP_BLOCK_COMMENT_RE.sub("", text)
    text = PHP_LINE_COMMENT_RE.sub("", text)
    return text
