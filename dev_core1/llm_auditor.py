#!/usr/bin/env python3
import os
import sys
import logging
import argparse
import asyncio
import json
import re
import pathlib
import shutil
import random
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict

# Import from auditor.py
try:
    from auditor import SecurityGraph, CodeParser, Node, Edge, EXT_TO_LANG, KNOWN_SINKS
except ImportError:
    print("Error: auditor.py not found or cannot import.")
    sys.exit(1)

import openai

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

class LLMClient:
    """Thin wrapper around the Yandex LLM endpoint (Async version) with rate limiting."""

    # Default concurrency limit (Yandex allows 10 concurrent sessions, we use 5 to be safe)
    DEFAULT_MAX_CONCURRENT = 8
    # Retry settings for rate limiting
    MAX_RETRIES = 5
    BASE_DELAY = 1.0  # Base delay in seconds for exponential backoff
    MAX_DELAY = 60.0  # Maximum delay between retries

    def __init__(self, base_url: str, api_key: str, model: str = "gpt-4o-mini",
                 temperature: float = 0.0, debug: bool = False, max_concurrent: int = None):
        """
        Initialise the LLM client.

        Parameters
        ----------
        base_url: URL of the LLM server.
        api_key: Authentication key for the LLM server.
        model: Model name to use (default: gpt-4o-mini).
        temperature: Sampling temperature (default: 0.0).
        debug: Enable debug logging.
        max_concurrent: Maximum number of concurrent requests (default: 5).
        """
        print(f"[DEBUG] Initializing LLMClient: base_url={base_url}, model={model}, temperature={temperature}")
        self.client = openai.AsyncOpenAI(base_url=base_url, api_key=api_key)
        self.model = model
        self.temperature = temperature
        self.debug = debug
        
        # Semaphore for rate limiting concurrent requests
        self._max_concurrent = max_concurrent or self.DEFAULT_MAX_CONCURRENT
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        logger.info(f"LLM rate limiter initialized: max {self._max_concurrent} concurrent requests")

    async def _chat_with_retry(self, system_prompt: str, user_prompt: str) -> str:
        """Send a chat request with exponential backoff retry on rate limit errors."""
        
        for attempt in range(self.MAX_RETRIES):
            try:
                # Build the request payload.
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": self.temperature,
                    "response_format": {"type": "json_object"}
                }

                # The OpenAI client expects the request parameters as keyword arguments.
                response = await self.client.chat.completions.create(**payload)
                content = response.choices[0].message.content.strip()
                
                if self.debug:
                    print(f"\n[DEBUG] LLM Response:\n{content}")
                    
                return content
                
            except openai.RateLimitError as e:
                # Handle 429 Too Many Requests with exponential backoff
                if attempt < self.MAX_RETRIES - 1:
                    # Calculate delay with exponential backoff and jitter
                    delay = min(self.BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), self.MAX_DELAY)
                    logger.warning(f"Rate limit hit (attempt {attempt + 1}/{self.MAX_RETRIES}), waiting {delay:.2f}s...")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"Rate limit exceeded after {self.MAX_RETRIES} retries: {e}")
                    return json.dumps({"vulnerability": False, "error": f"Rate limit exceeded: {e}"})
                    
            except openai.APIStatusError as e:
                if e.status_code == 429:
                    # Handle 429 from APIStatusError as well
                    if attempt < self.MAX_RETRIES - 1:
                        delay = min(self.BASE_DELAY * (2 ** attempt) + random.uniform(0, 1), self.MAX_DELAY)
                        logger.warning(f"Rate limit hit (attempt {attempt + 1}/{self.MAX_RETRIES}), waiting {delay:.2f}s...")
                        await asyncio.sleep(delay)
                    else:
                        logger.error(f"Rate limit exceeded after {self.MAX_RETRIES} retries: {e}")
                        return json.dumps({"vulnerability": False, "error": f"Rate limit exceeded: {e}"})
                else:
                    logger.error(f"API error: {e}")
                    return json.dumps({"vulnerability": False, "error": str(e)})
                    
            except Exception as e:
                logger.error(f"LLM request failed: {e}")
                return json.dumps({"vulnerability": False, "error": str(e)})
        
        return json.dumps({"vulnerability": False, "error": "Max retries exceeded"})

    async def _chat(self, system_prompt: str, user_prompt: str) -> str:
        """Send a single‑turn chat request with rate limiting and return the assistant's content."""
        
        if self.debug:
            print(f"\n[DEBUG] System Prompt:\n{system_prompt}")
            print(f"\n[DEBUG] User Prompt:\n{user_prompt}")

        # Use semaphore to limit concurrent requests
        async with self._semaphore:
            if self.debug:
                logger.debug(f"Acquired semaphore, making request...")
            return await self._chat_with_retry(system_prompt, user_prompt)

    def _extract_context(self, match: dict, radius: int = 5) -> str:
        """
        Return a small code context window around the matched line.
        Reads the file and returns up to ``radius`` lines before and after the match.
        """
        try:
            path = pathlib.Path(match["file"])
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            start = max(match["line"] - radius - 1, 0)
            end = min(match["line"] + radius, len(lines))
            snippet = "".join(lines[start:end])
            return snippet.rstrip("\n")
        except Exception:
            return match["code"]

    async def ask_vuln_analysis(self, trace: str, match: dict) -> dict:
        """
        Ask the model to assess the vulnerability represented by the trace.
        """
        system = (
            "You are a security researcher. Analyse the provided call‑trace that "
            "leads to a dangerous function. Identify if there is a real vulnerability. "
            "Return a JSON object with the following keys:\n"
            "- \"vulnerability\": boolean (true if vulnerable, false otherwise)\n"
            "- \"confidence\": string (e.g., \"High\", \"Medium\", \"Low\")\n"
            "- \"reasoning\": string (explanation)\n"
            "- \"exploit\": string (vulnerability exploitation method, request, or sequence of actions)\n"

        )
        context = self._extract_context(match, radius=10)
        user = (
            f"Trace:\n{trace}\n\n"
            f"Original snippet (line {match['line']} of {match['file']}):\n{match['code']}\n"
            f"--- Context (±10 lines) ---\n{context}"
        )
        
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


async def async_main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="Path to repository")
    parser.add_argument("--out", help="Output directory to save traces")
    parser.add_argument("--reports", default="reports", help="Directory to save LLM reports")
    parser.add_argument("--config", help="Path to JSON config file for LLM settings")
    parser.add_argument("--base-url", default="https://api.openai.com/v1", help="LLM Base URL")
    parser.add_argument("--api-key", help="LLM API Key")
    parser.add_argument("--model", default="gpt-4o-mini", help="LLM Model")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging for LLM requests")
    parser.add_argument("--enable-js", action="store_true", help="Enable analysis of JavaScript/TypeScript files")
    
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    if not repo.exists():
        print(f"Repo not found: {repo}")
        sys.exit(2)

    out_dir = (Path(args.out).resolve() / repo.name) if args.out else None
    reports_dir = Path(args.reports).resolve() / repo.name

    # Load config from JSON if provided
    base_url = args.base_url
    api_key = args.api_key
    model = args.model
    temperature = 0.0
    max_concurrent = LLMClient.DEFAULT_MAX_CONCURRENT  # Default concurrency limit

    if args.config:
        config_path = Path(args.config).resolve()
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    base_url = config.get("base_url", base_url)
                    api_key = config.get("api_key", api_key)
                    model = config.get("model", model)
                    temperature = config.get("temperature", temperature)
                    max_concurrent = config.get("max_concurrent", max_concurrent)
            except Exception as e:
                print(f"Error loading config file: {e}")
                sys.exit(1)
        else:
            print(f"Config file not found: {config_path}")
            sys.exit(1)

    if not api_key:
        print("Error: API Key is required (via --api-key or --config)")
        sys.exit(1)

    client = LLMClient(base_url=base_url, api_key=api_key, model=model, temperature=temperature,
                       debug=args.debug, max_concurrent=max_concurrent)
    graph = LLMSecurityGraph(client, reports_dir)
    
    # --- Graph Building (Copied from auditor.py) ---
    files_map: Dict[str, List[Path]] = defaultdict(list)
    for root, _, files in os.walk(repo):
        for f in files:
            ext = Path(f).suffix.lower()
            if ext in EXT_TO_LANG:
                lang = EXT_TO_LANG[ext]
                if lang in ("javascript", "typescript", "tsx") and not args.enable_js:
                    continue
                files_map[lang].append(Path(root) / f)

    all_raw_edges: List[Tuple[Edge, str]] = []

    for lang, paths in files_map.items():
        logger.info(f"Analyzing {len(paths)} {lang} files...")
        parser_eng = CodeParser(lang, repo_root=repo)
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
    # -----------------------------------------------

    # Run trace_all (synchronous part to find traces)
    # We pass show_code=True to ensure code is available if needed, 
    # though _emit_trace in LLMSecurityGraph ignores printing.
    # We pass out_dir to LLMSecurityGraph via constructor or setter, 
    # but trace_all takes it as arg.
    
    graph.trace_all(show_code=True, out_dir=out_dir)
    
    # Now process found traces asynchronously
    await graph.process_traces()

def main():
    asyncio.run(async_main())

if __name__ == "__main__":
    main()