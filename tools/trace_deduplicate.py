#!/usr/bin/env python3
"""Trace deduplication module: parses YAML traces and merges traces with same function code but different sinks."""

import hashlib
import re
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


class TraceDeduplicator:
    """Deduplicates traces by merging those with same function code but different sinks."""
    
    def __init__(self, reports_dir: Path, repo_name: str, output_dir: Optional[Path] = None):
        """
        Initialize TraceDeduplicator.
        
        Args:
            reports_dir: Base directory for reports (e.g., "reports")
            repo_name: Name of the repository
            output_dir: Optional output directory for deduplicated traces. If None, saves to repo_dir/deduplicated
        """
        self.reports_dir = Path(reports_dir).resolve()
        self.repo_dir = self.reports_dir / repo_name
        if not self.repo_dir.exists():
            raise ValueError(f"Reports directory not found: {self.repo_dir}")
        
        # Set output directory - default to deduplicated subfolder
        if output_dir:
            self.output_dir = Path(output_dir).resolve()
        else:
            self.output_dir = self.repo_dir / "deduplicated"
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"TraceDeduplicator initialized for {repo_name}, output: {self.output_dir}")
    
    def parse_yaml_trace(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse a YAML trace file.
        
        Args:
            file_path: Path to the YAML trace file
            
        Returns:
            Parsed YAML as dictionary, or None if parsing fails
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            # Parse YAML - it's a list starting with "- function:"
            # We need to handle the YAML structure properly
            parsed = yaml.safe_load(content)
            return parsed
        except Exception as e:
            logger.debug(f"Failed to parse {file_path}: {e}")
            return None
    
    def extract_function_path(self, trace_dict: List[Dict]) -> List[str]:
        """
        Extract function path from trace (excluding sink).
        
        Args:
            trace_dict: Parsed YAML trace (list of function dictionaries)
            
        Returns:
            List of function names/labels in the path
        """
        path = []
        
        def traverse(node: Dict, current_path: List[str]):
            if not isinstance(node, dict):
                return
            
            func_name = node.get("function", "")
            if func_name:
                # Check if it's a sink
                tags = node.get("tags", [])
                is_sink = "SINK" in tags
                
                if not is_sink:
                    current_path.append(func_name)
                
                # Recursively traverse calls
                calls = node.get("calls", [])
                if calls:
                    for call in calls:
                        traverse(call, current_path.copy())
            
        if isinstance(trace_dict, list) and trace_dict:
            traverse(trace_dict[0], path)
        
        return path
    
    def extract_sink(self, trace_dict: List[Dict]) -> Optional[Dict[str, Any]]:
        """
        Extract sink from trace.
        
        Args:
            trace_dict: Parsed YAML trace
            
        Returns:
            Sink dictionary or None
        """
        def find_sink(node: Dict) -> Optional[Dict]:
            if not isinstance(node, dict):
                return None
            
            tags = node.get("tags", [])
            if "SINK" in tags:
                return node
            
            calls = node.get("calls", [])
            if calls:
                for call in calls:
                    sink = find_sink(call)
                    if sink:
                        return sink
            
            return None
        
        if isinstance(trace_dict, list) and trace_dict:
            return find_sink(trace_dict[0])
        return None
    
    def extract_code_from_trace(self, trace_dict: List[Dict]) -> str:
        """
        Extract code from trace (excluding sink code).
        
        Args:
            trace_dict: Parsed YAML trace
            
        Returns:
            Combined code string
        """
        codes = []
        
        def extract_code(node: Dict):
            if not isinstance(node, dict):
                return
            
            # Check if it's a sink - skip sink code
            tags = node.get("tags", [])
            if "SINK" in tags:
                return
            
            code = node.get("code", "")
            if code:
                # Remove line number comments
                code_lines = code.split('\n')
                filtered_lines = [line for line in code_lines if not line.strip().startswith('# Lines')]
                code_clean = '\n'.join(filtered_lines)
                if code_clean.strip():
                    func_name = node.get("function", "")
                    codes.append(f"{func_name}:{code_clean}")
            
            # Recursively extract from calls
            calls = node.get("calls", [])
            if calls:
                for call in calls:
                    extract_code(call)
        
        if isinstance(trace_dict, list) and trace_dict:
            extract_code(trace_dict[0])
        
        return "\n---\n".join(sorted(codes))
    
    def extract_function_code_hash(self, trace_dict: List[Dict]) -> str:
        """
        Extract function code hash from trace (excluding sink).
        
        Args:
            trace_dict: Parsed YAML trace
            
        Returns:
            MD5 hash of function code
        """
        code = self.extract_code_from_trace(trace_dict)
        if not code:
            return ""
        return hashlib.md5(code.encode('utf-8')).hexdigest()
    
    def merge_traces(self, traces: List[Tuple[int, List[Dict]]]) -> Dict[str, Any]:
        """
        Merge multiple traces with same function code into one.
        
        Args:
            traces: List of (trace_id, trace_dict) tuples
            
        Returns:
            Merged trace dictionary
        """
        if not traces:
            return None
        
        # Use first trace as base
        base_trace_id, base_trace = traces[0]
        base_trace_dict = base_trace.copy()
        
        # Collect all sinks from all traces
        all_sinks = []
        for trace_id, trace_dict in traces:
            sink = self.extract_sink(trace_dict)
            if sink:
                all_sinks.append(sink)
        
        # If we have multiple sinks, merge them
        if len(all_sinks) > 1:
            # Find the last function before sinks in base trace
            def find_last_function_before_sink(node: Dict, parent: Optional[Dict] = None) -> Optional[Dict]:
                if not isinstance(node, dict):
                    return None
                
                tags = node.get("tags", [])
                if "SINK" in tags:
                    return parent
                
                calls = node.get("calls", [])
                if calls:
                    for call in calls:
                        result = find_last_function_before_sink(call, node)
                        if result:
                            return result
                
                return None
            
            last_func = None
            if isinstance(base_trace_dict, list) and base_trace_dict:
                last_func = find_last_function_before_sink(base_trace_dict[0])
            
            if last_func:
                # Replace single sink with multiple sinks
                if "calls" in last_func:
                    # Remove existing sink calls
                    last_func["calls"] = [c for c in last_func["calls"] if "SINK" not in c.get("tags", [])]
                
                # Add all sinks
                if "calls" not in last_func:
                    last_func["calls"] = []
                last_func["calls"].extend(all_sinks)
        
        return base_trace_dict
    
    def deduplicate(self) -> None:
        """
        Main deduplication method: loads all traces, groups by code hash, and merges them.
        """
        # Find all *_code.txt files
        trace_files = list(self.repo_dir.glob("*_code.txt"))
        
        if not trace_files:
            logger.warning(f"No trace files found in {self.repo_dir}")
            return
        
        logger.info(f"Found {len(trace_files)} trace files to process")
        
        # Parse all traces and group by code hash
        traces_by_hash: Dict[str, List[Tuple[int, List[Dict]]]] = defaultdict(list)
        
        for trace_file in trace_files:
            # Extract trace_id from filename (e.g., "1103_code.txt" -> 1103)
            match = re.match(r"(\d+)_code\.txt", trace_file.name)
            if not match:
                continue
            
            trace_id = int(match.group(1))
            trace_dict = self.parse_yaml_trace(trace_file)
            
            if not trace_dict:
                continue
            
            code_hash = self.extract_function_code_hash(trace_dict)
            if code_hash:
                traces_by_hash[code_hash].append((trace_id, trace_dict))
        
        logger.info(f"Grouped traces into {len(traces_by_hash)} unique code hashes")
        
        # Merge traces with same hash and save unique traces
        merged_count = 0
        saved_count = 0
        
        for code_hash, traces in traces_by_hash.items():
            if len(traces) > 1:
                # Multiple traces with same code - merge them
                merged_trace = self.merge_traces(traces)
                
                if merged_trace:
                    # Use the first trace_id for the merged trace
                    base_trace_id, _ = traces[0]
                    
                    # Save merged trace to output directory
                    output_file = self.output_dir / f"{base_trace_id}_code.txt"
                    yaml_content = yaml.dump(merged_trace, default_flow_style=False, allow_unicode=True, sort_keys=False)
                    output_file.write_text(yaml_content, encoding="utf-8")
                    
                    merged_count += len(traces) - 1
                    saved_count += 1
                    logger.debug(f"Merged {len(traces)} traces into {base_trace_id}_code.txt")
            else:
                # Single trace - just copy it to output directory
                trace_id, trace_dict = traces[0]
                output_file = self.output_dir / f"{trace_id}_code.txt"
                yaml_content = yaml.dump(trace_dict, default_flow_style=False, allow_unicode=True, sort_keys=False)
                output_file.write_text(yaml_content, encoding="utf-8")
                saved_count += 1
        
        logger.info(f"Deduplication complete: merged {merged_count} duplicate traces, saved {saved_count} unique traces to {self.output_dir}")


def main():
    """Main entry point for trace deduplication."""
    import argparse
    
    ap = argparse.ArgumentParser(description="Deduplicate trace files by merging traces with same function code")
    ap.add_argument("--reports", required=True, help="Path to reports directory")
    ap.add_argument("--repo", required=True, help="Repository name")
    args = ap.parse_args()
    
    reports_dir = Path(args.reports)
    repo_name = args.repo
    
    if not reports_dir.exists():
        print(f"Reports directory not found: {reports_dir}")
        sys.exit(1)
    
    deduplicator = TraceDeduplicator(reports_dir, repo_name)
    deduplicator.deduplicate()
    
    logger.info("Deduplication complete")


if __name__ == "__main__":
    main()
