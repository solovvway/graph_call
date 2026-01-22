#!/usr/bin/env python3
import os
import sys
import logging
import argparse
import asyncio
import json
import random
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict

# Import from core2 and auditor
from core2.ast_core import CodeParser, EXT_TO_LANG, Node, Edge
from core2.graph_builder import SecurityGraph
from core2.sinks import KNOWN_SINKS
from auditor import TraceSaver

import openai

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


def load_config(config_path: Path) -> dict:
    """Load configuration from JSON file."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        return config
    except Exception as e:
        raise ValueError(f"Error loading config file: {e}")


def load_prompt(prompt_path: Path) -> Tuple[str, str]:
    """
    Load prompt from file and split into system and user parts.
    
    Returns:
        (system_prompt, user_template) where user_template contains "TRACE" placeholder
    """
    if not prompt_path.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
    
    content = prompt_path.read_text(encoding="utf-8", errors="ignore")
    
    # Split by "Trace: TRACE" - everything before is system prompt
    if "Trace: TRACE" in content:
        parts = content.split("Trace: TRACE", 1)
        system_prompt = parts[0].strip()
        user_template = "Trace: TRACE" + (parts[1].strip() if len(parts) > 1 else "")
    else:
        # If no "Trace: TRACE" found, use entire content as system prompt
        system_prompt = content.strip()
        user_template = "Trace: TRACE"
    
    return system_prompt, user_template


class LLMClient:
    """Thin wrapper around the Yandex LLM endpoint (Async version) with rate limiting."""

    # Default concurrency limit
    DEFAULT_MAX_CONCURRENT = 8
    # Retry settings for rate limiting
    MAX_RETRIES = 5
    BASE_DELAY = 1.0  # Base delay in seconds for exponential backoff
    MAX_DELAY = 60.0  # Maximum delay between retries

    def __init__(self, base_url: str, api_key: str, folder_id: str = None, model: str = "yandexgpt-lite",
                 temperature: float = 0.0, debug: bool = False, max_concurrent: int = None,
                 system_prompt: str = "", user_template: str = ""):
        """
        Initialize the LLM client.

        Parameters
        ----------
        base_url: URL of the LLM server.
        api_key: Authentication key for the LLM server.
        folder_id: Yandex Cloud folder ID (optional, can be passed in headers).
        model: Model name to use (default: yandexgpt-lite).
        temperature: Sampling temperature (default: 0.0).
        debug: Enable debug logging.
        max_concurrent: Maximum number of concurrent requests (default: 8).
        system_prompt: System prompt for LLM.
        user_template: User prompt template with "TRACE" placeholder.
        """
        if debug:
            print(f"[DEBUG] Initializing LLMClient: base_url={base_url}, folder_id={folder_id}, model={model}, temperature={temperature}")
        # Use synchronous client for Yandex Cloud API (will run in executor)
        self.client = openai.OpenAI(base_url=base_url, api_key=api_key)
        
        # If folder_id is provided, add it to default headers
        if folder_id:
            self.client.default_headers["x-folder-id"] = folder_id
        
        self.folder_id = folder_id
        self.model = model
        self.temperature = temperature
        self.debug = debug
        self.system_prompt = system_prompt
        self.user_template = user_template
        
        # Semaphore for rate limiting concurrent requests
        self._max_concurrent = max_concurrent or self.DEFAULT_MAX_CONCURRENT
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        logger.info(f"LLM rate limiter initialized: max {self._max_concurrent} concurrent requests")

    def _chat_sync(self, system_prompt: str, user_prompt: str) -> str:
        """Send a synchronous chat request to Yandex Cloud API using OpenAI-compatible format."""
        try:
            # Build messages array for chat completions API
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": user_prompt})
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature
            )
            
            # Extract content from OpenAI-compatible response format
            # Format: response.choices[0].message.content
            if not response.choices or len(response.choices) == 0:
                raise ValueError("Empty response from Yandex Cloud API")
            
            if not response.choices[0].message or not response.choices[0].message.content:
                raise ValueError("Empty content in Yandex Cloud API response")
            
            content = response.choices[0].message.content.strip()
            
            if self.debug:
                print(f"\n[DEBUG] LLM Response:\n{content}")
                
            return content
        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            raise

    async def _chat_with_retry(self, system_prompt: str, user_prompt: str) -> str:
        """Send a chat request with exponential backoff retry on rate limit errors."""
        
        for attempt in range(self.MAX_RETRIES):
            try:
                # Run synchronous Yandex Cloud API call in executor to avoid blocking
                content = await asyncio.to_thread(self._chat_sync, system_prompt, user_prompt)
                return content
                
            except Exception as e:
                error_str = str(e)
                # Check if it's a rate limit error (429)
                if "429" in error_str or "rate limit" in error_str.lower() or "too many requests" in error_str.lower():
                    if attempt < self.MAX_RETRIES - 1:
                        # Calculate delay with exponential backoff and jitter
                        delay = min(self.BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), self.MAX_DELAY)
                        logger.warning(f"Rate limit hit (attempt {attempt + 1}/{self.MAX_RETRIES}), waiting {delay:.2f}s...")
                        await asyncio.sleep(delay)
                    else:
                        logger.error(f"Rate limit exceeded after {self.MAX_RETRIES} retries: {e}")
                        return json.dumps({"vulnerability": False, "error": f"Rate limit exceeded: {e}"})
                else:
                    if attempt < self.MAX_RETRIES - 1:
                        # Retry on other errors with shorter delay
                        delay = min(self.BASE_DELAY * (2 ** attempt), self.MAX_DELAY)
                        logger.warning(f"Request failed (attempt {attempt + 1}/{self.MAX_RETRIES}), retrying in {delay:.2f}s...")
                        await asyncio.sleep(delay)
                    else:
                        logger.error(f"LLM request failed after {self.MAX_RETRIES} retries: {e}")
                        return json.dumps({"vulnerability": False, "error": str(e)})
        
        return json.dumps({"vulnerability": False, "error": "Max retries exceeded"})

    async def _chat(self, system_prompt: str, user_prompt: str) -> str:
        """Send a single?turn chat request with rate limiting and return the assistant's content."""
        
        if self.debug:
            print(f"\n[DEBUG] System Prompt:\n{system_prompt}")
            print(f"\n[DEBUG] User Prompt:\n{user_prompt}")

        # Use semaphore to limit concurrent requests
        async with self._semaphore:
            if self.debug:
                logger.debug(f"Acquired semaphore, making request...")
            return await self._chat_with_retry(system_prompt, user_prompt)

    async def ask_vuln_analysis(self, trace: str) -> dict:
        """
        Ask the model to assess the vulnerability represented by the trace.
        
        Args:
            trace: Trace text to analyze
            
        Returns:
            Dictionary with vulnerability analysis result
        """
        # Use system prompt from config/file
        system = self.system_prompt if self.system_prompt else (
            "You are a security researcher. Analyse the provided call?trace that "
            "leads to a dangerous function. Identify if there is a real vulnerability. "
            "Return a JSON object with the following keys:\n"
            "- \"vulnerability\": boolean (true if vulnerable, false otherwise)\n"
            "- \"confidence\": string (e.g., \"High\", \"Medium\", \"Low\")\n"
            "- \"reasoning\": string (explanation)\n"
            "- \"exploit\": string (vulnerability exploitation method, request, or sequence of actions)\n"
        )
        
        # Replace TRACE placeholder in user template
        user = self.user_template.replace("TRACE", trace) if self.user_template else f"Trace:\n{trace}"
        
        max_retries = 3
        for attempt in range(max_retries):
            response_str = await self._chat(system, user)
            try:
                return json.loads(response_str)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse JSON response (attempt {attempt + 1}/{max_retries}): {response_str}")
                if attempt < max_retries - 1:
                    user += f"\n\nYour previous response was not valid JSON. Please provide a valid JSON object."
                else:
                    return {"vulnerability": False, "reasoning": "Failed to parse LLM response after retries"}
        return {"vulnerability": False, "reasoning": "Failed to parse LLM response"}


async def analyze_repository(repo_path: Path, config: dict, llm_client: LLMClient, 
                             trace_saver: TraceSaver, enable_js: bool = False):
    """
    Analyze a single repository.
    
    Args:
        repo_path: Path to repository
        config: Configuration dictionary
        llm_client: LLM client instance
        trace_saver: TraceSaver instance for saving results
        enable_js: Whether to analyze JavaScript/TypeScript files
    """
    logger.info(f"Analyzing repository: {repo_path}")
    
    graph = SecurityGraph()
    files_map: Dict[str, List[Path]] = defaultdict(list)
    
    # Collect files
    for root, _, files in os.walk(repo_path):
        for f in files:
            ext = Path(f).suffix.lower()
            if ext in EXT_TO_LANG:
                lang = EXT_TO_LANG[ext]
                if lang in ("javascript", "typescript", "tsx") and not enable_js:
                    continue
                files_map[lang].append(Path(root) / f)
    
    all_raw_edges: List[Tuple[Edge, str]] = []
    
    # Parse files
    for lang, paths in files_map.items():
        logger.info(f"Analyzing {len(paths)} {lang} files...")
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
                logger.debug(f"Failed reading/parsing {p}: {e}")
    
    logger.info(f"Linking {len(all_raw_edges)} calls...")
    for e, lang in all_raw_edges:
        graph.add_edge(e.src, e.dst, lang, e.file, e.line)
    
    # Run trace analysis
    graph.trace_all(show_code=True, out_dir=None)
    
    # Get all traces
    if not graph.trace_processor:
        logger.warning("No trace processor found, no traces to analyze")
        return
    
    trace_ids = graph.trace_processor.get_all_trace_ids()
    logger.info(f"Found {len(trace_ids)} traces, analyzing with LLM...")
    
    # Process traces with LLM
    save_no_vuln = config.get("save_no_vuln_traces", False)
    
    tasks = []
    for trace_id in trace_ids:
        tasks.append(_analyze_trace_async(
            trace_id, graph, llm_client, trace_saver, save_no_vuln
        ))
    
    # Process all tasks
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Log any exceptions
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            trace_id = trace_ids[i]
            logger.error(f"Trace {trace_id} analysis failed with exception: {result}")
    
    logger.info(f"Completed analysis of {len(trace_ids)} traces for {repo_path.name}")


async def _analyze_trace_async(trace_id: int, graph: SecurityGraph, llm_client: LLMClient,
                               trace_saver: TraceSaver, save_no_vuln: bool):
    """Analyze a single trace with LLM and save if needed."""
    if not graph.trace_processor:
        return
    
    # Get trace text
    trace_text = graph.trace_processor.get_trace_text(
        trace_id, graph.nodes, graph.edge_sites, show_code=True
    )
    trace_text_no_code = graph.trace_processor.get_trace_text(
        trace_id, graph.nodes, graph.edge_sites, show_code=False
    )
    
    if not trace_text:
        logger.warning(f"Trace {trace_id} has no text")
        return
    
    # Ask LLM
    result = await llm_client.ask_vuln_analysis(trace_text)
    
    is_vuln = result.get("vulnerability", False)
    
    # Save only if vulnerability found OR save_no_vuln is enabled
    if is_vuln or save_no_vuln:
        if is_vuln:
            logger.info(f"Trace {trace_id}: Vulnerability DETECTED")
        else:
            logger.debug(f"Trace {trace_id}: No vulnerability (saving because save_no_vuln_traces=true)")
        
        # Save trace files
        trace_saver.save_trace(trace_id, trace_text_no_code, trace_text)
        
        # Save LLM report
        trace_saver.save_report(trace_id, result)
    else:
        logger.debug(f"Trace {trace_id}: No vulnerability detected (not saving)")


async def async_main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    args = parser.parse_args()
    
    # Load config
    config_path = Path(args.config).resolve()
    try:
        config = load_config(config_path)
    except Exception as e:
        print(f"Error loading config: {e}")
        sys.exit(1)
    
    # Extract config values
    repos_path = Path(config.get("repos_path", ".")).resolve()
    if not repos_path.exists():
        print(f"Repositories path not found: {repos_path}")
        sys.exit(1)
    
    reports_dir = Path(config.get("reports_dir", "reports")).resolve()
    base_url = config.get("base_url")
    folder_id = config.get("folder_id")  # Optional, can be in headers
    api_key = config.get("api_key")
    model = config.get("model", "yandexgpt-lite")
    debug = config.get("debug", False)
    enable_js = config.get("enable_js", False)
    temperature = config.get("temperature", 0.0)
    # Use streams if specified, otherwise use max_concurrent, otherwise default
    streams = config.get("streams")
    max_concurrent = streams if streams is not None else config.get("max_concurrent", LLMClient.DEFAULT_MAX_CONCURRENT)
    
    if not base_url or not api_key:
        print("Error: base_url and api_key are required in config")
        sys.exit(1)
    
    # Load prompt
    prompt_path = Path("prompts/prompt.md").resolve()
    if not prompt_path.exists():
        # Try relative to config file
        prompt_path = config_path.parent / "prompts" / "prompt.md"
    
    try:
        system_prompt, user_template = load_prompt(prompt_path)
        logger.info(f"Loaded prompt from {prompt_path}")
    except FileNotFoundError:
        logger.warning(f"Prompt file not found at {prompt_path}, using default prompt")
        system_prompt = ""
        user_template = ""
    
    # Initialize LLM client
    logger.info(f"Initializing LLM client with {max_concurrent} parallel streams")
    llm_client = LLMClient(
        base_url=base_url,
        api_key=api_key,
        folder_id=folder_id,
        model=model,
        temperature=temperature,
        debug=debug,
        max_concurrent=max_concurrent,
        system_prompt=system_prompt,
        user_template=user_template
    )
    
    # Find repositories - repos_path should always point to directory containing repositories
    if not repos_path.is_dir():
        print(f"Repositories path is not a directory: {repos_path}")
        sys.exit(1)
    
    repositories = []
    for item in os.listdir(repos_path):
        item_path = repos_path / item
        if item_path.is_dir() and not item.startswith('.'):
            repositories.append(item_path)
    
    if not repositories:
        print(f"No repositories found in {repos_path}")
        sys.exit(1)
    
    logger.info(f"Found {len(repositories)} repository(ies) to analyze")
    
    # Analyze each repository
    for repo_path in repositories:
        if not repo_path.exists():
            logger.warning(f"Repository path does not exist: {repo_path}, skipping")
            continue
        
        repo_name = repo_path.name
        trace_saver = TraceSaver(reports_dir, repo_name)
        
        try:
            await analyze_repository(repo_path, config, llm_client, trace_saver, enable_js)
        except Exception as e:
            logger.error(f"Error analyzing repository {repo_name}: {e}", exc_info=True)
    
    logger.info("Analysis complete")


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
