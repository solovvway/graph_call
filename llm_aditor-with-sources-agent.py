#!/usr/bin/env python3
"""
LLM auditor with sources.json agent: only core4-agent-config.
Optionally generates sources.json via LLM agent before scanning (--gen-sources).
Config (repos_path, base_url, api_key, etc.) is read from JSON; sources.json is generated per repo or used if present.
"""
import os
import sys
import json
import logging
import argparse
import asyncio
import random
import importlib.util
import types
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

# Resolve project root
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from auditor import TraceSaver
import openai

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# Core4-agent-config package name (hyphen -> underscore)
CORE4_PACKAGE = "core4_agent_config"
CORE4_DIR = _SCRIPT_DIR / "core4-agent-config"

# Will be set by load_core4()
CodeParser = None
EXT_TO_LANG = None
Node = None
Edge = None
SecurityGraph = None
KNOWN_SINKS = None
run_sources_agent = None


def load_core4():
    """Load only core4-agent-config: ast_core, graph_builder, sinks, sources, trace_processor, and agent run_agent."""
    global CodeParser, EXT_TO_LANG, Node, Edge, SecurityGraph, KNOWN_SINKS, run_sources_agent

    if not CORE4_DIR.is_dir():
        raise FileNotFoundError(f"core4-agent-config not found: {CORE4_DIR}")

    if CORE4_PACKAGE not in sys.modules:
        fake_package = types.ModuleType(CORE4_PACKAGE)
        fake_package.__path__ = [str(CORE4_DIR)]
        fake_package.__file__ = str(CORE4_DIR / "__init__.py")
        sys.modules[CORE4_PACKAGE] = fake_package

    def load_module(module_name: str, file_path: Path):
        full_name = f"{CORE4_PACKAGE}.{module_name}"
        spec = importlib.util.spec_from_file_location(full_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load {module_name} from {file_path}")
        mod = importlib.util.module_from_spec(spec)
        mod.__package__ = CORE4_PACKAGE
        mod.__name__ = full_name
        sys.modules[full_name] = mod
        spec.loader.exec_module(mod)
        return mod

    ast_core = load_module("ast_core", CORE4_DIR / "ast_core.py")
    sinks_mod = load_module("sinks", CORE4_DIR / "sinks.py")
    load_module("sources", CORE4_DIR / "sources.py")
    trace_processor = load_module("trace_processor", CORE4_DIR / "trace_processor.py")
    graph_builder = load_module("graph_builder", CORE4_DIR / "graph_builder.py")

    # Agent module: file is agent-config.py, import as agent_config
    agent_mod = load_module("agent_config", CORE4_DIR / "agent-config.py")

    CodeParser = ast_core.CodeParser
    EXT_TO_LANG = ast_core.EXT_TO_LANG
    Node = ast_core.Node
    Edge = ast_core.Edge
    SecurityGraph = graph_builder.SecurityGraph
    KNOWN_SINKS = sinks_mod.KNOWN_SINKS
    run_sources_agent = getattr(agent_mod, "run_agent", None)
    if run_sources_agent is None:
        logger.warning("core4-agent-config agent run_agent not found; --gen-sources will be no-op")

    logger.info("Loaded core4-agent-config")


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_prompt(prompt_path: Path) -> Tuple[str, str]:
    if not prompt_path.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
    content = prompt_path.read_text(encoding="utf-8", errors="ignore")
    if "Trace: TRACE" in content:
        parts = content.split("Trace: TRACE", 1)
        system_prompt = parts[0].strip()
        user_template = "Trace: TRACE" + (parts[1].strip() if len(parts) > 1 else "")
    else:
        system_prompt = content.strip()
        user_template = "Trace: TRACE"
    return system_prompt, user_template


class LLMClient:
    DEFAULT_MAX_CONCURRENT = 8
    MAX_RETRIES = 5
    BASE_DELAY = 1.0
    MAX_DELAY = 60.0

    def __init__(self, base_url: str, api_key: str, folder_id: str = None, model: str = "yandexgpt-lite",
                 temperature: float = 0.0, debug: bool = False, max_concurrent: int = None,
                 system_prompt: str = "", user_template: str = ""):
        self.client = openai.OpenAI(base_url=base_url, api_key=api_key)
        if folder_id:
            self.client.default_headers["x-folder-id"] = folder_id
        self.folder_id = folder_id
        self.model = model
        self.temperature = temperature
        self.debug = debug
        self.system_prompt = system_prompt
        self.user_template = user_template
        self._max_concurrent = max_concurrent or self.DEFAULT_MAX_CONCURRENT
        self._semaphore = asyncio.Semaphore(self._max_concurrent)

    def _chat_sync(self, system_prompt: str, user_prompt: str) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        response = self.client.chat.completions.create(
            model=self.model, messages=messages, temperature=self.temperature
        )
        if not response.choices or not response.choices[0].message or not response.choices[0].message.content:
            raise ValueError("Empty response from LLM")
        return response.choices[0].message.content.strip()

    async def _chat_with_retry(self, system_prompt: str, user_prompt: str) -> str:
        for attempt in range(self.MAX_RETRIES):
            try:
                return await asyncio.to_thread(self._chat_sync, system_prompt, user_prompt)
            except Exception as e:
                err = str(e)
                if "429" in err or "rate limit" in err.lower() or "too many requests" in err.lower():
                    delay = min(self.BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), self.MAX_DELAY)
                    logger.warning(f"Rate limit (attempt {attempt + 1}/{self.MAX_RETRIES}), waiting {delay:.2f}s")
                    await asyncio.sleep(delay)
                else:
                    delay = min(self.BASE_DELAY * (2 ** attempt), self.MAX_DELAY)
                    logger.warning(f"Request failed (attempt {attempt + 1}/{self.MAX_RETRIES}), retry in {delay:.2f}s")
                    await asyncio.sleep(delay)
        return json.dumps({"vulnerability": False, "error": "Max retries exceeded"})

    async def _chat(self, system_prompt: str, user_prompt: str) -> str:
        async with self._semaphore:
            return await self._chat_with_retry(system_prompt, user_prompt)

    async def ask_vuln_analysis(self, trace: str) -> dict:
        system = self.system_prompt or (
            "You are a security researcher. Analyse the call-trace to a dangerous function. "
            "Return JSON: vulnerability (boolean), confidence, reasoning, exploit."
        )
        user = self.user_template.replace("TRACE", trace) if self.user_template else f"Trace:\n{trace}"
        for attempt in range(3):
            response_str = await self._chat(system, user)
            try:
                return json.loads(response_str)
            except json.JSONDecodeError:
                if attempt < 2:
                    user += "\n\nYour response was not valid JSON. Provide a valid JSON object."
                else:
                    return {"vulnerability": False, "reasoning": "Failed to parse LLM response"}
        return {"vulnerability": False, "reasoning": "Failed to parse LLM response"}


def ensure_sources_json(repo_path: Path, config: dict, config_prompt_path: Path) -> bool:
    """Generate sources.json for repo if missing or --gen-sources. Returns True if sources.json is present (existing or generated)."""
    sources_file = repo_path / "sources.json"
    if sources_file.exists():
        return True

    if not run_sources_agent:
        logger.warning("Sources agent not available; run without --gen-sources or add sources.json manually")
        return False

    base_url = config.get("base_url")
    api_key = config.get("api_key")
    if not base_url or not api_key:
        logger.warning("base_url and api_key required in config for --gen-sources")
        return False

    prompt_text = ""
    if config_prompt_path.exists():
        prompt_text = config_prompt_path.read_text(encoding="utf-8", errors="ignore").strip()

    logger.info("Generating sources.json for %s via agent...", repo_path.name)
    result = run_sources_agent(
        repo_path=repo_path,
        prompt_text=prompt_text,
        base_url=base_url,
        api_key=api_key,
        folder_id=config.get("folder_id"),
        model=config.get("model", "yandexgpt-lite"),
    )
    if not result:
        logger.warning("Agent did not produce sources.json for %s", repo_path.name)
        return False
    with open(sources_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    logger.info("Wrote %s", sources_file)
    return True


async def analyze_repository(
    repo_path: Path,
    config: dict,
    llm_client: LLMClient,
    trace_saver: TraceSaver,
    enable_js: bool = False,
):
    repo_path = repo_path.resolve()
    logger.info("Analyzing repository: %s", repo_path.name)

    graph = SecurityGraph(repo_path=repo_path)
    files_map: Dict[str, List[Path]] = defaultdict(list)

    for root, _, files in os.walk(repo_path):
        for f in files:
            ext = Path(f).suffix.lower()
            if ext in EXT_TO_LANG:
                lang = EXT_TO_LANG[ext]
                if lang in ("javascript", "typescript", "tsx") and not enable_js:
                    continue
                files_map[lang].append(Path(root) / f)

    all_raw_edges: List[Tuple[Edge, str]] = []
    for lang, paths in files_map.items():
        logger.info("Parsing %d %s files...", len(paths), lang)
        parser_eng = CodeParser(lang, repo_root=repo_path)
        for p in paths:
            try:
                content = p.read_bytes()
                nodes, edges = parser_eng.parse_file(p, content)
                for n in nodes:
                    graph.add_node(n)
                for e in edges:
                    all_raw_edges.append((e, lang))
            except Exception as e:
                logger.debug("Failed parsing %s: %s", p, e)

    logger.info("Linking %d calls...", len(all_raw_edges))
    for e, lang in all_raw_edges:
        graph.add_edge(e.src, e.dst, lang, e.file, e.line)

    graph.trace_all(show_code=True, out_dir=None)

    if not graph.trace_processor:
        logger.warning("No trace processor, skip LLM analysis")
        return

    trace_ids = graph.trace_processor.get_all_trace_ids()
    logger.info("Found %d traces, analyzing with LLM...", len(trace_ids))
    save_no_vuln = config.get("save_no_vuln_traces", False)

    async def analyze_one(tid):
        return await _analyze_trace_async(tid, graph, llm_client, trace_saver, save_no_vuln)

    results = await asyncio.gather(*[analyze_one(tid) for tid in trace_ids], return_exceptions=True)
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            logger.error("Trace %s failed: %s", trace_ids[i], r)
    logger.info("Completed %d traces for %s", len(trace_ids), repo_path.name)


async def _analyze_trace_async(
    trace_id: int, graph, llm_client: LLMClient, trace_saver: TraceSaver, save_no_vuln: bool
):
    if not graph.trace_processor:
        return
    trace_text = graph.trace_processor.get_trace_text(
        trace_id, graph.nodes, graph.edge_sites, show_code=True
    )
    trace_text_no_code = graph.trace_processor.get_trace_text(
        trace_id, graph.nodes, graph.edge_sites, show_code=False
    )
    if not trace_text:
        return
    result = await llm_client.ask_vuln_analysis(trace_text)
    is_vuln = result.get("vulnerability", False)
    if is_vuln or save_no_vuln:
        if is_vuln:
            logger.info("Trace %s: Vulnerability DETECTED", trace_id)
        trace_saver.save_trace(trace_id, trace_text_no_code, trace_text)
        trace_saver.save_report(trace_id, result)


async def async_main():
    parser = argparse.ArgumentParser(description="LLM SAST with core4-agent-config; optional --gen-sources")
    parser.add_argument("--config", required=True, help="Path to JSON config (repos_path, base_url, api_key, ...)")
    parser.add_argument("--gen-sources", action="store_true", help="Generate sources.json per repo via agent if missing")
    args = parser.parse_args()

    load_core4()

    config_path = Path(args.config).resolve()
    try:
        config = load_config(config_path)
    except Exception as e:
        logger.error("Load config failed: %s", e)
        sys.exit(1)

    repos_path = Path(config.get("repos_path", ".")).resolve()
    if not repos_path.exists() or not repos_path.is_dir():
        logger.error("repos_path not found or not a directory: %s", repos_path)
        sys.exit(1)

    reports_dir = Path(config.get("reports_dir", "reports")).resolve()
    base_url = config.get("base_url")
    api_key = config.get("api_key")
    if not base_url or not api_key:
        logger.error("base_url and api_key required in config")
        sys.exit(1)

    prompt_path = Path("prompts/prompt.md").resolve()
    if not prompt_path.exists():
        prompt_path = config_path.parent / "prompts" / "prompt.md"
    config_prompt_path = Path("prompts/config.md").resolve()
    if not config_prompt_path.exists():
        config_prompt_path = config_path.parent / "prompts" / "config.md"

    try:
        system_prompt, user_template = load_prompt(prompt_path)
    except FileNotFoundError:
        system_prompt, user_template = "", ""

    streams = config.get("streams")
    max_concurrent = streams if streams is not None else config.get("max_concurrent", LLMClient.DEFAULT_MAX_CONCURRENT)
    llm_client = LLMClient(
        base_url=base_url,
        api_key=api_key,
        folder_id=config.get("folder_id"),
        model=config.get("model", "yandexgpt-lite"),
        temperature=config.get("temperature", 0.0),
        debug=config.get("debug", False),
        max_concurrent=max_concurrent,
        system_prompt=system_prompt,
        user_template=user_template,
    )

    repositories = [
        repos_path / item
        for item in os.listdir(repos_path)
        if (repos_path / item).is_dir() and not item.startswith(".")
    ]
    if not repositories:
        logger.error("No repositories in %s", repos_path)
        sys.exit(1)
    logger.info("Repositories: %d", len(repositories))

    for repo_path in repositories:
        if not repo_path.exists():
            continue
        if args.gen_sources:
            ensure_sources_json(repo_path, config, config_prompt_path)
        repo_name = repo_path.name
        trace_saver = TraceSaver(reports_dir, repo_name)
        try:
            await analyze_repository(repo_path, config, llm_client, trace_saver, config.get("enable_js", False))
        except Exception as e:
            logger.error("Error analyzing %s: %s", repo_name, e, exc_info=True)

    logger.info("Analysis complete")


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
