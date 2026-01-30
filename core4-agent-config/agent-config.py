#!/usr/bin/env python3
"""
SAST config agent: builds a JSON config for llm_aditor via LLM with tools.
Before scanning, the model receives ls (depth 2) of the repo and instructions;
it uses tools (list_dir, read_file, read_lines, grep, get_languages, file_info, submit_config)
to produce a valid config. Config is validated; on failure the agent is asked to retry (1-2 times).
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
                "name": "submit_config",
                "description": "Submit the final scan config. Call this when config is ready. All required fields must be set.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repos_path": {"type": "string", "description": "Path to dir containing repos (required)"},
                        "base_url": {"type": "string", "description": "LLM API base URL (required)"},
                        "api_key": {"type": "string", "description": "LLM API key (required)"},
                        "reports_dir": {"type": "string"},
                        "folder_id": {"type": "string"},
                        "model": {"type": "string"},
                        "debug": {"type": "boolean"},
                        "enable_js": {"type": "boolean"},
                        "temperature": {"type": "number"},
                        "streams": {"type": "integer"},
                        "max_concurrent": {"type": "integer"},
                        "save_no_vuln_traces": {"type": "boolean"},
                        "prompt_path": {"type": "string"},
                        "exclude_dirs": {"type": "array", "items": {"type": "string"}},
                        "include_extensions": {"type": "array", "items": {"type": "string"}},
                        "max_file_size_kb": {"type": "integer"},
                        "sources_config_path": {"type": "string"},
                    },
                    "required": ["repos_path", "base_url", "api_key"],
                },
            },
        },
    ]


def validate_config(config: Dict[str, Any], repo_path: Path) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    for key in ("repos_path", "base_url", "api_key"):
        val = config.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            errors.append(f"Missing or empty required: {key}")
    if config.get("repos_path"):
        rp = Path(config["repos_path"]).resolve()
        if not rp.exists():
            errors.append(f"repos_path does not exist: {rp}")
        elif not rp.is_dir():
            errors.append(f"repos_path is not a directory: {rp}")
    if config.get("base_url") is not None and not str(config["base_url"]).strip():
        errors.append("base_url must be non-empty")
    t = config.get("temperature")
    if t is not None:
        try:
            v = float(t)
            if v < 0 or v > 2:
                errors.append("temperature must be between 0 and 2")
        except (TypeError, ValueError):
            errors.append("temperature must be a number")
    mc = config.get("max_concurrent") or config.get("streams")
    if mc is not None:
        try:
            v = int(mc)
            if v < 1:
                errors.append("max_concurrent/streams must be >= 1")
        except (TypeError, ValueError):
            errors.append("max_concurrent/streams must be an integer")
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
        "You build a config for the SAST scanner. Use only the tools. "
        "End by calling submit_config with the complete config. Do not output JSON in chat."
    )
    user_content = (
        f"Repo (ls depth 2):\n{ls_text}\n\nInstructions:\n{prompt_text}\n\n"
        "Explore if needed, then call submit_config with the config (required: repos_path, base_url, api_key)."
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
                    {"role": "user", "content": "You must use tools and then call submit_config to submit the config."}
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
            elif name == "submit_config":
                known = {
                    "repos_path", "base_url", "api_key", "reports_dir", "folder_id", "model",
                    "debug", "enable_js", "temperature", "streams", "max_concurrent",
                    "save_no_vuln_traces", "prompt_path", "exclude_dirs", "include_extensions",
                    "max_file_size_kb", "sources_config_path",
                }
                config = {k: v for k, v in args.items() if k in known}
                ok, errs = validate_config(config, repo_path)
                if ok:
                    return config
                submit_retries += 1
                result = "Validation failed: " + "; ".join(errs)
                if submit_retries >= MAX_SUBMIT_CONFIG_RETRIES:
                    result += ". Max retries reached; fix the errors and call submit_config again."
                else:
                    result += ". Fix and call submit_config again."
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
    parser = argparse.ArgumentParser(description="Build SAST scan config via LLM agent")
    parser.add_argument("--repo", required=True, help="Path to repository (or dir containing repos)")
    parser.add_argument("--output", required=True, help="Output JSON config path")
    parser.add_argument("--config-prompt", default=None, help="Path to config prompt (default: prompts/config.md)")
    parser.add_argument("--base-url", required=True, help="LLM API base URL (for agent)")
    parser.add_argument("--api-key", required=True, help="LLM API key (for agent)")
    parser.add_argument("--folder-id", default=None, help="Yandex folder ID (optional)")
    parser.add_argument("--model", default="yandexgpt-lite", help="Model name for agent")
    args = parser.parse_args()

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
        logger.error("Agent did not produce a valid config")
        return 1

    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    logger.info("Config written to %s", out_path)
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
