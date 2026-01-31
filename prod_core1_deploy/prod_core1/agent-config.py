#!/usr/bin/env python3
"""
SAST sources.json agent: builds sources.json (forward validation config) via LLM with tools.
Before scanning, the model receives ls (depth 2) of the repo and instructions;
it uses tools (list_dir, read_file, read_lines, grep, get_languages, file_info, submit_sources_config)
to produce a valid sources.json. Config is validated; on failure the agent is asked to retry (1-2 times).
LLM/scan connection config is created by the user manually; this agent outputs only sources.json.
"""
import os
import sys
import re
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Run from project root: python core4-agent-config/agent-config.py
_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import openai

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# Supported extensions for SAST (same as core2/ast_core)
EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "c_sharp",
}

MAX_READ_LINES = 200
MAX_GREP_RESULTS = 50
MAX_AGENT_STEPS = 15
MAX_SUBMIT_CONFIG_RETRIES = 2


def ls_depth(repo_path: Path, depth: int = 2) -> str:
    """List repo with given depth; return compact string (dir: file1, file2)."""
    repo_path = repo_path.resolve()
    if not repo_path.is_dir():
        return f"(not a directory: {repo_path})"
    lines: List[str] = []
    for root, dirs, files in os.walk(repo_path):
        rel = Path(root).relative_to(repo_path)
        parts = rel.parts
        if len(parts) >= depth:
            dirs.clear()
            continue
        # Skip hidden and common noise
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "__pycache__", "venv", ".git")]
        names = [d + "/" for d in dirs] + [f for f in files if not f.startswith(".")]
        if not names:
            continue
        prefix = str(rel) + ":" if parts else ".:"
        lines.append(prefix + " " + ", ".join(sorted(names)[:80]))  # cap entries per line
        if len(names) > 80:
            lines[-1] += f" ... (+{len(names)-80} more)"
    return "\n".join(lines) if lines else "(empty)"


def _safe_path(repo_root: Path, path: str) -> Path:
    """Resolve path relative to repo_root; ensure it stays under repo_root. Returns relative Path."""
    p = Path(path)
    if not p.is_absolute():
        p = (repo_root / path).resolve()
    else:
        p = p.resolve()
    try:
        return p.relative_to(repo_root.resolve())
    except ValueError:
        raise PermissionError(f"Path outside repo: {path}")


def _safe_path_abs(repo_root: Path, path: str) -> Path:
    """Return absolute path under repo_root."""
    rel = _safe_path(repo_root, path)
    return repo_root / rel


def tool_list_dir(repo_root: Path, path: str, depth: int = 1) -> str:
    path = path.strip() or "."
    try:
        abs_p = _safe_path_abs(repo_root, path)
        if not abs_p.is_dir():
            return f"Not a directory: {path}"
        out: List[str] = []
        max_depth = max(1, depth)
        for root, dirs, files in os.walk(abs_p):
            rel = Path(root).relative_to(repo_root)
            if len(rel.parts) >= max_depth and rel != Path("."):
                dirs.clear()
                continue
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            names = [d + "/" for d in dirs] + files
            prefix = str(rel) + ":" if rel.parts else ".:"
            out.append(prefix + " " + ", ".join(sorted(names)[:60]))
            if len(names) > 60:
                out[-1] += " ..."
        return "\n".join(out) if out else "(empty)"
    except Exception as e:
        return f"Error: {e}"


def tool_read_file(repo_root: Path, path: str, max_lines: Optional[int] = None) -> str:
    max_lines = max_lines or MAX_READ_LINES
    try:
        abs_p = _safe_path_abs(repo_root, path)
        if not abs_p.is_file():
            return f"Not a file: {path}"
        if abs_p.stat().st_size > 1024 * 1024:
            return "File too large (>1MB)"
        raw = abs_p.read_bytes()
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return "Binary or invalid encoding"
        lines = text.splitlines()
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            return "\n".join(lines) + f"\n... (truncated, total {len(text.splitlines())} lines)"
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


def tool_read_lines(repo_root: Path, path: str, start_line: int, end_line: int) -> str:
    try:
        abs_p = _safe_path_abs(repo_root, path)
        if not abs_p.is_file():
            return f"Not a file: {path}"
        lines = abs_p.read_text(encoding="utf-8", errors="replace").splitlines()
        if start_line < 1:
            start_line = 1
        if end_line > len(lines):
            end_line = len(lines)
        if start_line > end_line:
            return "(invalid range)"
        return "\n".join(lines[start_line - 1 : end_line])
    except Exception as e:
        return f"Error: {e}"


def tool_grep(
    repo_root: Path,
    pattern: str,
    path: str,
    type_: str = "content",
    max_results: int = MAX_GREP_RESULTS,
) -> str:
    try:
        abs_p = _safe_path_abs(repo_root, path)
        if type_ == "filename":
            if not abs_p.is_dir():
                return "Path must be directory for filename grep"
            try:
                pat = re.compile(pattern, re.IGNORECASE)
            except re.error:
                return f"Invalid regex: {pattern}"
            out = []
            for root, _, files in os.walk(abs_p):
                for f in files:
                    if pat.search(f):
                        out.append(str((Path(root) / f).relative_to(repo_root)))
                        if len(out) >= max_results:
                            return "\n".join(out) + f"\n... (max {max_results} results)"
            return "\n".join(out) if out else "(no matches)"
        else:
            if abs_p.is_file():
                files = [abs_p]
            elif abs_p.is_dir():
                files = [p for p in abs_p.rglob("*") if p.is_file() and p.suffix.lower() in EXT_TO_LANG]
            else:
                return "Not file or directory"
            try:
                pat = re.compile(pattern, re.IGNORECASE)
            except re.error:
                return f"Invalid regex: {pattern}"
            out = []
            for f in files:
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    for i, line in enumerate(text.splitlines(), 1):
                        if pat.search(line):
                            rel = f.relative_to(repo_root)
                            out.append(f"{rel}:{i}: {line.strip()[:120]}")
                            if len(out) >= max_results:
                                return "\n".join(out) + f"\n... (max {max_results} results)"
                except Exception:
                    continue
            return "\n".join(out) if out else "(no matches)"
    except Exception as e:
        return f"Error: {e}"


def tool_get_languages() -> str:
    return "Supported extensions: " + ", ".join(sorted(EXT_TO_LANG.keys()))


def tool_file_info(repo_root: Path, path: str) -> str:
    try:
        abs_p = _safe_path_abs(repo_root, path)
        if not abs_p.is_file():
            return f"Not a file: {path}"
        st = abs_p.stat()
        ext = abs_p.suffix.lower()
        lang = EXT_TO_LANG.get(ext, "?")
        return f"path={path} size_bytes={st.st_size} ext={ext} language={lang}"
    except Exception as e:
        return f"Error: {e}"


def build_tools_schema() -> List[Dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": "list_dir",
                "description": "List directory contents. Path relative to repo root.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path (e.g. . or src)"},
                        "depth": {"type": "integer", "description": "Depth (default 1)", "default": 1},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read file contents. Path relative to repo root. Truncated by max_lines.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "max_lines": {"type": "integer", "description": "Max lines to return (default 200)"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_lines",
                "description": "Read lines from start_line to end_line (1-based).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                    },
                    "required": ["path", "start_line", "end_line"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep",
                "description": "Search by pattern. path: file or dir. type: content or filename.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "path": {"type": "string"},
                        "type": {"type": "string", "enum": ["content", "filename"], "default": "content"},
                        "max_results": {"type": "integer", "default": 50},
                    },
                    "required": ["pattern", "path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_languages",
                "description": "List supported file extensions for scanning.",
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "file_info",
                "description": "Get file size and extension/language.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_sources_config",
                "description": "Submit the final sources.json for forward validation. Call when config is ready. At least one of file_patterns, function_patterns, function_names, or language_specific recommended.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_patterns": {
                            "type": "array",
                            "description": "Glob file patterns. Each item: { pattern: string, language?: string }",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "pattern": {"type": "string"},
                                    "language": {"type": "string"},
                                },
                                "required": ["pattern"],
                            },
                        },
                        "function_patterns": {
                            "type": "array",
                            "description": "Regex patterns for full function name",
                            "items": {"type": "string"},
                        },
                        "function_names": {
                            "type": "array",
                            "description": "Exact function names or suffixes",
                            "items": {"type": "string"},
                        },
                        "source_indicators": {
                            "type": "array",
                            "description": "Substrings that must appear in code",
                            "items": {"type": "string"},
                        },
                        "language_specific": {
                            "type": "object",
                            "description": "Keys: language (python, javascript, etc). Values: { patterns: string[] } regex on code",
                        },
                    },
                },
            },
        },
    ]


def validate_sources_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate sources.json structure. Returns (ok, list of error strings)."""
    errors: List[str] = []
    file_patterns = config.get("file_patterns")
    if file_patterns is not None:
        if not isinstance(file_patterns, list):
            errors.append("file_patterns must be an array")
        else:
            for i, item in enumerate(file_patterns):
                if not isinstance(item, dict):
                    errors.append(f"file_patterns[{i}] must be an object")
                elif not (item.get("pattern") and isinstance(item.get("pattern"), str) and item["pattern"].strip()):
                    errors.append(f"file_patterns[{i}] must have non-empty 'pattern' string")

    function_patterns = config.get("function_patterns")
    if function_patterns is not None:
        if not isinstance(function_patterns, list):
            errors.append("function_patterns must be an array")
        else:
            for i, pat in enumerate(function_patterns):
                if not isinstance(pat, str) or not pat.strip():
                    errors.append(f"function_patterns[{i}] must be non-empty string")
                else:
                    try:
                        re.compile(pat)
                    except re.error as e:
                        errors.append(f"function_patterns[{i}] invalid regex: {e}")

    function_names = config.get("function_names")
    if function_names is not None and not isinstance(function_names, list):
        errors.append("function_names must be an array")

    source_indicators = config.get("source_indicators")
    if source_indicators is not None and not isinstance(source_indicators, list):
        errors.append("source_indicators must be an array")

    language_specific = config.get("language_specific")
    if language_specific is not None:
        if not isinstance(language_specific, dict):
            errors.append("language_specific must be an object")
        else:
            for lang, val in language_specific.items():
                if not isinstance(val, dict):
                    errors.append(f"language_specific.{lang} must be an object")
                elif "patterns" not in val or not isinstance(val["patterns"], list):
                    errors.append(f"language_specific.{lang} must have 'patterns' array")
                else:
                    for j, pat in enumerate(val["patterns"]):
                        if not isinstance(pat, str) or not pat.strip():
                            errors.append(f"language_specific.{lang}.patterns[{j}] must be non-empty string")
                        else:
                            try:
                                re.compile(pat)
                            except re.error as e:
                                errors.append(f"language_specific.{lang}.patterns[{j}] invalid regex: {e}")

    # Optional: recommend at least one block for precision (non-blocking warning only)
    has_any = (
        (file_patterns and len(file_patterns) > 0)
        or (function_patterns and len(function_patterns) > 0)
        or (function_names and len(function_names) > 0)
        or (language_specific and len(language_specific) > 0)
    )
    if not has_any and not errors:
        logger.warning("No file_patterns/function_patterns/function_names/language_specific set; forward validation may be permissive")
    return (len(errors) == 0, errors)


def run_agent(
    repo_path: Path,
    prompt_text: str,
    base_url: str,
    api_key: str,
    folder_id: Optional[str] = None,
    model: str = "yandexgpt-lite",
) -> Optional[Dict[str, Any]]:
    repo_path = repo_path.resolve()
    ls_text = ls_depth(repo_path, 2)
    system = (
        "You build sources.json for forward validation: only web entrypoints (routes, handlers, API). "
        "Use only the tools. End by calling submit_sources_config with the config. Do not output JSON in chat."
    )
    user_content = (
        f"Repo (ls depth 2):\n{ls_text}\n\nInstructions:\n{prompt_text}\n\n"
        "Find routes/handlers/API, then call submit_sources_config with file_patterns, function_patterns, function_names, source_indicators, or language_specific."
    )
    messages: List[Dict] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content},
    ]
    tools = build_tools_schema()
    client = openai.OpenAI(base_url=base_url, api_key=api_key)
    if folder_id:
        client.default_headers["x-folder-id"] = folder_id

    submit_retries = 0
    for step in range(MAX_AGENT_STEPS):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0.0,
        )
        choice = response.choices[0]
        msg = choice.message
        tool_calls = getattr(msg, "tool_calls", None)
        if not tool_calls:
            if msg.content:
                messages.append({"role": "assistant", "content": msg.content or ""})
            if step == 0:
                messages.append(
                    {"role": "user", "content": "You must use tools and then call submit_sources_config to submit the sources.json config."}
                )
                continue
            break

        messages.append(
            {
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in msg.tool_calls
                ],
            }
        )
        for tc in msg.tool_calls:
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
            except json.JSONDecodeError:
                args = {}
            result: str
            if name == "list_dir":
                result = tool_list_dir(repo_path, args.get("path", "."), args.get("depth", 1))
            elif name == "read_file":
                result = tool_read_file(repo_path, args.get("path", ""), args.get("max_lines"))
            elif name == "read_lines":
                result = tool_read_lines(
                    repo_path,
                    args.get("path", ""),
                    int(args.get("start_line", 1)),
                    int(args.get("end_line", 1)),
                )
            elif name == "grep":
                result = tool_grep(
                    repo_path,
                    args.get("pattern", ""),
                    args.get("path", "."),
                    args.get("type", "content"),
                    args.get("max_results", MAX_GREP_RESULTS),
                )
            elif name == "get_languages":
                result = tool_get_languages()
            elif name == "file_info":
                result = tool_file_info(repo_path, args.get("path", ""))
            elif name == "submit_sources_config":
                known = {"file_patterns", "function_patterns", "function_names", "source_indicators", "language_specific"}
                config = {k: v for k, v in args.items() if k in known and v is not None}
                ok, errs = validate_sources_config(config)
                if ok:
                    return config
                submit_retries += 1
                result = "Validation failed: " + "; ".join(errs)
                if submit_retries >= MAX_SUBMIT_CONFIG_RETRIES:
                    result += ". Max retries reached; fix the errors and call submit_sources_config again."
                else:
                    result += ". Fix and call submit_sources_config again."
            else:
                result = f"Unknown tool: {name}"
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                }
            )
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Build sources.json (forward validation config) via LLM agent")
    parser.add_argument("--repo", required=True, help="Path to repository (or dir containing repos)")
    parser.add_argument("--output", required=True, help="Output path for sources.json")
    parser.add_argument("--config-prompt", default=None, help="Path to config prompt (default: prompts/config.md)")
    parser.add_argument("--base-url", default=os.environ.get("YANDEX_LLM_BASE_URL"), help="LLM API base URL (or YANDEX_LLM_BASE_URL)")
    parser.add_argument("--api-key", default=os.environ.get("YANDEX_CLOUD_API_KEY"), help="LLM API key (or YANDEX_CLOUD_API_KEY)")
    parser.add_argument("--folder-id", default=os.environ.get("YANDEX_CLOUD_FOLDER"), help="Yandex folder ID (or YANDEX_CLOUD_FOLDER)")
    parser.add_argument("--model", default="yandexgpt-lite", help="Model name for agent")
    args = parser.parse_args()
    if not args.base_url or not args.api_key:
        parser.error("--base-url and --api-key required (or set YANDEX_LLM_BASE_URL and YANDEX_CLOUD_API_KEY)")

    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        logger.error("Repo path does not exist: %s", repo_path)
        return 1
    if not repo_path.is_dir():
        logger.error("Repo path is not a directory: %s", repo_path)
        return 1

    prompt_path = Path(args.config_prompt) if args.config_prompt else _REPO_ROOT / "prompts" / "config.md"
    if not prompt_path.exists():
        logger.error("Config prompt not found: %s", prompt_path)
        return 1
    prompt_text = prompt_path.read_text(encoding="utf-8", errors="ignore").strip()

    config = run_agent(
        repo_path=repo_path,
        prompt_text=prompt_text,
        base_url=args.base_url,
        api_key=args.api_key,
        folder_id=args.folder_id,
        model=args.model,
    )
    if not config:
        logger.error("Agent did not produce a valid sources.json config")
        return 1

    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    logger.info("sources.json written to %s", out_path)
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
