#!/usr/bin/env python3
"""Sources module: defines data sources and PHP source detection."""
import re
import json
import os
from pathlib import Path
from typing import Dict, Set, Pattern, List, Optional, Any, TYPE_CHECKING
from fnmatch import fnmatch

if TYPE_CHECKING:
    from .ast_core import Node

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


# ============================================================================
# SOURCE VALIDATION (forward-validation)
# ============================================================================

# Global cache for loaded config (per repository)
_SOURCES_CONFIG_CACHE: Dict[str, Dict[str, Any]] = {}
_COMPILED_PATTERNS_CACHE: Dict[str, Dict[str, List[Pattern]]] = {}
_FILE_PATTERN_CACHE: Dict[str, bool] = {}


def _get_config_path(repo_path: Optional[Path] = None) -> Optional[Path]:
    """
    Get path to sources.json config file.
    First checks in repository root, then in core module directory.
    
    Args:
        repo_path: Optional path to repository root
    
    Returns:
        Path to sources.json or None if not found
    """
    # First, check in repository root if provided
    if repo_path:
        repo_config = Path(repo_path) / "sources.json"
        if repo_config.exists():
            return repo_config
    
    # Fallback to default location (same directory as sources.py)
    default_config = Path(__file__).parent / "sources.json"
    if default_config.exists():
        return default_config
    
    return None


def load_sources_config(repo_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """
    Load sources configuration from sources.json.
    First checks in repository root, then in core module directory.
    
    Args:
        repo_path: Optional path to repository root
    
    Returns:
        Configuration dictionary or None if file doesn't exist
    """
    global _SOURCES_CONFIG_CACHE, _COMPILED_PATTERNS_CACHE
    
    # Create cache key from repo path
    cache_key = str(repo_path) if repo_path else "default"
    
    # Check cache first
    if cache_key in _SOURCES_CONFIG_CACHE:
        return _SOURCES_CONFIG_CACHE[cache_key]
    
    config_path = _get_config_path(repo_path)
    if not config_path:
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Pre-compile regex patterns for efficiency
        compiled_patterns = {}
        if "language_specific" in config:
            for lang, lang_config in config["language_specific"].items():
                if "patterns" in lang_config:
                    compiled_patterns[lang] = [
                        re.compile(pattern, re.IGNORECASE) 
                        for pattern in lang_config["patterns"]
                    ]
        
        # Pre-compile function patterns if present
        function_patterns_compiled = []
        if "function_patterns" in config and config["function_patterns"]:
            for pattern_str in config["function_patterns"]:
                try:
                    function_patterns_compiled.append(re.compile(pattern_str, re.IGNORECASE))
                except re.error:
                    continue
        
        # Cache the config and patterns
        _SOURCES_CONFIG_CACHE[cache_key] = config
        _COMPILED_PATTERNS_CACHE[cache_key] = {
            "language_specific": compiled_patterns,
            "function_patterns": function_patterns_compiled
        }
        
        return config
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to load sources.json from {config_path}: {e}")
        return None


def is_valid_source_file(file_path: str, language: str, repo_path: Optional[Path] = None) -> bool:
    """
    Check if a file matches any of the file patterns in the config.
    Returns True if file matches, False otherwise.
    
    Args:
        file_path: Path to the file to check
        language: Language of the file
        repo_path: Optional path to repository root for repository-specific config
    """
    config = load_sources_config(repo_path)
    if not config:
        return False
    
    # If no file_patterns specified, file validation is not required
    if "file_patterns" not in config or not config["file_patterns"]:
        return True  # No file patterns means files are not filtered
    
    # Check cache first
    cache_key = f"{file_path}:{language}"
    if cache_key in _FILE_PATTERN_CACHE:
        return _FILE_PATTERN_CACHE[cache_key]
    
    path_obj = Path(file_path)
    result = False
    
    for pattern_config in config["file_patterns"]:
        pattern = pattern_config.get("pattern", "")
        pattern_lang = pattern_config.get("language", "")
        
        # Check language match
        if pattern_lang and pattern_lang != language:
            continue
        
        # Convert glob pattern to path matching
        # Handle **/ prefix for recursive matching
        if pattern.startswith("**/"):
            pattern_suffix = pattern[3:]  # Remove "**/"
            # Normalize pattern suffix to use OS-specific path separator
            pattern_suffix_normalized = pattern_suffix.replace("/", os.sep)
            # Check if file ends with the pattern suffix
            if str(path_obj).endswith(pattern_suffix_normalized):
                result = True
                break
            # Also check if any parent directory matches
            for parent in path_obj.parents:
                if fnmatch(str(parent / path_obj.name), pattern):
                    result = True
                    break
            if result:
                break
        else:
            # Simple pattern matching
            if fnmatch(str(path_obj), pattern) or fnmatch(path_obj.name, pattern):
                result = True
                break
    
    _FILE_PATTERN_CACHE[cache_key] = result
    return result


def is_valid_source_node(node, file_content: str, language: str, repo_path: Optional[Path] = None) -> bool:
    """
    Check if a node matches source indicators and language-specific patterns.
    
    Args:
        node: Node object from ast_core
        file_content: Full content of the file containing the node
        language: Language identifier (python, javascript, etc.)
        repo_path: Optional path to repository root for repository-specific config
    
    Returns:
        True if node matches source criteria, False otherwise
    """
    config = load_sources_config(repo_path)
    if not config:
        # Fallback to PHP source detection for backward compatibility
        if language == "php":
            return is_php_source(file_content)
        # If node is already marked as source, allow it
        return node.is_source
    
    # If node is already marked as source (e.g., by PHP detection), allow it
    if node.is_source and language == "php":
        return True
    
    # Check if we have file_patterns or function_patterns/function_names
    has_file_patterns = "file_patterns" in config and config["file_patterns"]
    has_function_patterns = "function_patterns" in config and config["function_patterns"]
    has_function_names = "function_names" in config and config["function_names"]
    
    # If neither file_patterns nor function patterns/names are specified, use old logic
    if not has_file_patterns and not has_function_patterns and not has_function_names:
        # Fallback to old behavior: check file and content patterns
        file_matches = is_valid_source_file(node.file, language, repo_path)
        
        # Get compiled patterns for this repository
        cache_key = str(repo_path) if repo_path else "default"
        patterns_cache = _COMPILED_PATTERNS_CACHE.get(cache_key, {})
        compiled_patterns = patterns_cache.get("language_specific", {})
            
        # Extract node-specific code if it's a function (not <global>)
        node_code = ""
        if node.name != "<global>" and node.line:
            try:
                lines = file_content.splitlines()
                start_line = max(0, node.line - 1)
                end_line = min(len(lines), node.end_line if node.end_line else node.line)
                if end_line > start_line:
                    node_code = "\n".join(lines[start_line:end_line])
            except Exception:
                pass
        
        content_to_check = node_code if node_code else file_content
        content_lower = content_to_check.lower()
        
        # Check general source indicators
        if "source_indicators" in config and config["source_indicators"]:
            for indicator in config["source_indicators"]:
                if indicator.lower() in content_lower:
                    return True
        
        # Check language-specific patterns
        if language in compiled_patterns:
            for pattern in compiled_patterns[language]:
                if pattern.search(content_to_check):
                    return True
        
        if file_matches:
            return True
        
        if language == "php":
            return is_php_source(content_to_check)
        
        return False
    
    # New logic: check functions OR files (not both required)
    function_matches = False
    file_matches = False
    
    # Check function patterns/names if specified
    if has_function_patterns or has_function_names:
        # Check function name patterns (regex) - use cached compiled patterns
        if has_function_patterns:
            cache_key = str(repo_path) if repo_path else "default"
            patterns_cache = _COMPILED_PATTERNS_CACHE.get(cache_key, {})
            function_patterns_compiled = patterns_cache.get("function_patterns", [])
            
            # Check if function name matches any pattern
            for pattern in function_patterns_compiled:
                if pattern.search(node.name):
                    function_matches = True
                    break
        
        # Check exact function names
        if has_function_names and not function_matches:
            node_name_lower = node.name.lower()
            for func_name in config["function_names"]:
                if func_name.lower() == node_name_lower or node_name_lower.endswith("." + func_name.lower()):
                    function_matches = True
                    break
    
    # Check file patterns if specified
    if has_file_patterns:
        file_matches = is_valid_source_file(node.file, language, repo_path)
    
    # Logic:
    # - If only file patterns: require file match
    # - If only function patterns/names: require function match
    # - If both: either can match (OR logic)
    if has_file_patterns and not (has_function_patterns or has_function_names):
        return file_matches
    elif (has_function_patterns or has_function_names) and not has_file_patterns:
        return function_matches
    elif has_file_patterns and (has_function_patterns or has_function_names):
        # Both specified: OR logic
        return file_matches or function_matches
    
    return False


def validate_source(path: List[str], nodes: Dict[str, 'Node'], repo_path: Optional[Path] = None) -> bool:  # type: ignore
    """
    Validate that the first node in a trace path is a valid source.
    
    Args:
        path: List of node UIDs representing the trace path (from source to sink)
        nodes: Dictionary of all nodes in the graph
        repo_path: Optional path to repository root for repository-specific config
    
    Returns:
        True if the first node is a valid source, False otherwise
    """
    if not path:
        return False
    
    # Get the first node (source) from the path
    source_uid = path[0]
    if source_uid not in nodes:
        return False
    
    source_node = nodes[source_uid]
    
    # Skip builtin/external nodes
    if source_node.is_builtin or source_node.file in {"<external>", "unknown", "<builtin>"}:
        return False
    
    # Check if config exists
    config = load_sources_config(repo_path)
    if not config:
        # Backward compatibility: if no config, allow traces with nodes already marked as source
        return source_node.is_source
    
    # Determine language from file extension
    from .ast_core import EXT_TO_LANG
    file_ext = Path(source_node.file).suffix
    language = EXT_TO_LANG.get(file_ext, "python")  # Default to python
    
    # Read file content (will be cached by trace_processor)
    try:
        file_content = Path(source_node.file).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    
    # Validate the source node
    return is_valid_source_node(source_node, file_content, language, repo_path)
