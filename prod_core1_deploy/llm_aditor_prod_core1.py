#!/usr/bin/env python3
"""
LLM auditor for prod_core1: sync sources.json via agent, async trace evaluation.
Optionally generates sources.json via LLM agent (--gen-sources). After saving reports,
optionally uploads to MinIO (--upload-minio or when MINIO_ENDPOINT is set).
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

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from auditor import TraceSaver

try:
    from yandex_ai_studio_sdk import AsyncAIStudio
except ImportError:
    AsyncAIStudio = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

PROD_CORE1_PACKAGE = "prod_core1"
PROD_CORE1_DIR = _SCRIPT_DIR / "prod_core1"

CodeParser = None
EXT_TO_LANG = None
Node = None
Edge = None
SecurityGraph = None
KNOWN_SINKS = None
run_sources_agent = None


def load_prod_core1():
    """Load prod_core1: ast_core, graph_builder, sinks, sources, trace_processor, agent run_agent."""
    global CodeParser, EXT_TO_LANG, Node, Edge, SecurityGraph, KNOWN_SINKS, run_sources_agent

    if not PROD_CORE1_DIR.is_dir():
        raise FileNotFoundError(f"prod_core1 not found: {PROD_CORE1_DIR}")

    if PROD_CORE1_PACKAGE not in sys.modules:
        fake_package = types.ModuleType(PROD_CORE1_PACKAGE)
        fake_package.__path__ = [str(PROD_CORE1_DIR)]
        fake_package.__file__ = str(PROD_CORE1_DIR / "__init__.py")
        sys.modules[PROD_CORE1_PACKAGE] = fake_package

    def load_module(module_name: str, file_path: Path):
        full_name = f"{PROD_CORE1_PACKAGE}.{module_name}"
        spec = importlib.util.spec_from_file_location(full_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load {module_name} from {file_path}")
        mod = importlib.util.module_from_spec(spec)
        mod.__package__ = PROD_CORE1_PACKAGE
        mod.__name__ = full_name
        sys.modules[full_name] = mod
        spec.loader.exec_module(mod)
        return mod

    ast_core = load_module("ast_core", PROD_CORE1_DIR / "ast_core.py")
    sinks_mod = load_module("sinks", PROD_CORE1_DIR / "sinks.py")
    load_module("sources", PROD_CORE1_DIR / "sources.py")
    load_module("trace_processor", PROD_CORE1_DIR / "trace_processor.py")
    graph_builder = load_module("graph_builder", PROD_CORE1_DIR / "graph_builder.py")
    agent_mod = load_module("agent_config", PROD_CORE1_DIR / "agent-config.py")

    CodeParser = ast_core.CodeParser
    EXT_TO_LANG = ast_core.EXT_TO_LANG
    Node = ast_core.Node
    Edge = ast_core.Edge
    SecurityGraph = graph_builder.SecurityGraph
    KNOWN_SINKS = sinks_mod.KNOWN_SINKS
    run_sources_agent = getattr(agent_mod, "run_agent", None)
    if run_sources_agent is None:
        logger.warning("prod_core1 run_agent not found; --gen-sources will be no-op")
    logger.info("Loaded prod_core1")


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


def _model_name_and_version(model_cfg: str) -> Tuple[str, Optional[str]]:
    """Parse config model to (model_name, model_version) for AsyncAIStudio. E.g. gpt://folder/gpt-oss-120b/latest -> ('gpt-oss-120b', 'latest')."""
    if not model_cfg:
        return "yandexgpt", "rc"
    if model_cfg.startswith("gpt://"):
        parts = model_cfg.rstrip("/").replace("gpt://", "").split("/")
        if len(parts) >= 2:
            return parts[-2], parts[-1]  # e.g. gpt-oss-120b, latest
        if len(parts) == 1:
            return parts[0], "rc"
    return model_cfg if model_cfg != "yandexgpt-lite" else "yandexgpt", "rc"


class LLMClient:
    """Client for trace vulnerability analysis: Yandex AI Studio SDK (AsyncAIStudio), native async model.run()."""
    DEFAULT_MAX_CONCURRENT = 8
    MAX_RETRIES = 5
    BASE_DELAY = 1.0
    MAX_DELAY = 60.0

    def __init__(self, api_key: str, folder_id: str, model: str = "yandexgpt",
                 temperature: float = 0.0, debug: bool = False, max_concurrent: int = None,
                 system_prompt: str = "", user_template: str = "", model_version: Optional[str] = None):
        if AsyncAIStudio is None:
            raise ImportError("yandex-ai-studio-sdk required: pip install yandex-ai-studio-sdk")
        if not folder_id or not api_key:
            raise ValueError("folder_id and api_key required for Yandex AI Studio SDK")
        self.folder_id = folder_id
        self.api_key = api_key
        self.temperature = temperature
        self.debug = debug
        self.system_prompt = system_prompt
        self.user_template = user_template
        self._max_concurrent = max_concurrent or self.DEFAULT_MAX_CONCURRENT
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        model_name, default_version = _model_name_and_version(model)
        self._model_name = model_name
        self._model_version = model_version or default_version
        self._sdk: Optional[AsyncAIStudio] = None

    async def _get_sdk(self) -> "AsyncAIStudio":
        if self._sdk is None:
            self._sdk = AsyncAIStudio(folder_id=self.folder_id, auth=self.api_key)
            if self.debug:
                self._sdk.setup_default_logging()
        return self._sdk

    def _messages_for_sdk(self, system_prompt: str, user_prompt: str) -> List[Dict[str, str]]:
        """Messages in SDK format: list of {role, text}."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "text": system_prompt})
        messages.append({"role": "user", "text": user_prompt})
        return messages

    async def _run_async(self, system_prompt: str, user_prompt: str) -> str:
        """Native async: await model.run(messages). Result is sequence, result[0].text."""
        sdk = await self._get_sdk()
        model = sdk.models.completions(self._model_name, model_version=self._model_version)
        model = model.configure(temperature=self.temperature)
        messages = self._messages_for_sdk(system_prompt, user_prompt)
        result = await model.run(messages)
        first = result[0] if result and hasattr(result, "__getitem__") else result
        text = getattr(first, "text", None) if first is not None else None
        if text is None and first is not None:
            text = str(first)
        return (text or "").strip()

    async def _chat_with_retry(self, system_prompt: str, user_prompt: str) -> str:
        for attempt in range(self.MAX_RETRIES):
            try:
                return await self._run_async(system_prompt, user_prompt)
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
    """Generate sources.json for repo if missing or --gen-sources. Sync OpenAI. Returns True if present."""
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
    logger.info("Generating sources.json for %s via agent (sync)...", repo_path.name)
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
    status_callback: Optional[callable] = None,
):
    repo_path = repo_path.resolve()
    logger.info("Analyzing repository: %s", repo_path.name)
    if status_callback:
        status_callback(f"Analyzing repository: {repo_path.name}")

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
        if status_callback:
            status_callback(f"Analyzing {len(paths)} {lang} files")
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
    if status_callback:
        status_callback(f"Linking {len(all_raw_edges)} calls")
    for e, lang in all_raw_edges:
        graph.add_edge(e.src, e.dst, lang, e.file, e.line)

    graph.trace_all(show_code=True, out_dir=None)

    if not graph.trace_processor:
        logger.warning("No trace processor, skip LLM analysis")
        return

    trace_ids = graph.trace_processor.get_all_trace_ids()
    logger.info("Found %d traces, analyzing with LLM (async)...", len(trace_ids))
    if status_callback:
        status_callback(f"Check {len(trace_ids)} potential vulns")
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


def upload_repo_reports_to_minio(reports_dir: Path, repo_name: str) -> int:
    """Upload reports_dir/repo_name to MinIO bucket named after repo. Returns count uploaded."""
    try:
        from tools.minio_upload import upload_reports_to_minio
        return upload_reports_to_minio(reports_dir, repo_name)
    except Exception as e:
        logger.error("MinIO upload failed for %s: %s", repo_name, e)
        return 0


async def async_main():
    parser = argparse.ArgumentParser(description="LLM SAST with prod_core1; optional --gen-sources, --upload-minio")
    parser.add_argument("--config", required=True, help="Path to JSON config (repos_path, base_url, api_key, ...)")
    parser.add_argument("--gen-sources", action="store_true", help="Generate sources.json per repo via agent if missing")
    parser.add_argument("--upload-minio", action="store_true", help="Upload reports to MinIO after each repo (or set MINIO_ENDPOINT)")
    args = parser.parse_args()

    load_prod_core1()

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
    api_key = config.get("api_key")
    folder_id = config.get("folder_id")
    if not folder_id or not api_key:
        logger.error("folder_id and api_key required in config (Yandex Cloud ML SDK)")
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

    max_concurrent = config.get("max_concurrent", LLMClient.DEFAULT_MAX_CONCURRENT)
    llm_client = LLMClient(
        api_key=api_key,
        folder_id=folder_id,
        model=config.get("model", "yandexgpt"),
        model_version=config.get("model_version"),
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

    do_minio = args.upload_minio or bool(os.environ.get("MINIO_ENDPOINT"))

    for repo_path in repositories:
        if not repo_path.exists():
            continue
        if args.gen_sources:
            ensure_sources_json(repo_path, config, config_prompt_path)
        repo_name = repo_path.name
        trace_saver = TraceSaver(reports_dir, repo_name)
        try:
            await analyze_repository(repo_path, config, llm_client, trace_saver, config.get("enable_js", False), status_callback=status_callback)
        except Exception as e:
            logger.error("Error analyzing %s: %s", repo_name, e, exc_info=True)
        if do_minio:
            upload_repo_reports_to_minio(reports_dir, repo_name)

    logger.info("Analysis complete")


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
