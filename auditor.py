#!/usr/bin/env python3

import os, sys, logging, argparse, warnings, json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, DefaultDict
from collections import defaultdict

warnings.simplefilter(action="ignore", category=FutureWarning)

try:
    from tree_sitter_languages import get_language, get_parser
except ImportError:
    print("CRITICAL: Missing libraries. Run: pip install tree-sitter tree-sitter-languages graphviz")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# Import modular components
from core2.ast_core import CodeParser, EXT_TO_LANG, Node
from core2.graph_builder import SecurityGraph
from core2.sinks import KNOWN_SINKS
from core2.sources import is_php_source
from core2.trace_processor import TraceProcessor


class TraceSaver:
    """Class for saving traces and reports to repository-specific folders."""
    
    def __init__(self, reports_dir: Path, repo_name: str):
        """
        Initialize TraceSaver.
        
        Args:
            reports_dir: Base directory for reports (e.g., "reports")
            repo_name: Name of the repository (will create reports_dir/repo_name/)
        """
        self.reports_dir = Path(reports_dir).resolve()
        self.repo_dir = self.reports_dir / repo_name
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"TraceSaver initialized: reports will be saved to {self.repo_dir}")
    
    def save_trace(self, trace_id: int, trace_text: str, trace_text_with_code: str):
        """
        Save trace files.
        
        Args:
            trace_id: Unique trace identifier
            trace_text: Trace text without code
            trace_text_with_code: Trace text with code
        """
        (self.repo_dir / f"{trace_id}.txt").write_text(
            trace_text, encoding="utf-8", errors="ignore"
        )
        (self.repo_dir / f"{trace_id}_code.txt").write_text(
            trace_text_with_code, encoding="utf-8", errors="ignore"
        )
        logger.debug(f"Saved trace {trace_id} to {self.repo_dir}")
    
    def save_report(self, trace_id: int, report: dict):
        """
        Save LLM report.
        
        Args:
            trace_id: Unique trace identifier
            report: LLM response as dictionary
        """
        report_file = self.repo_dir / f"{trace_id}_report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.debug(f"Saved report {trace_id} to {report_file}")


def analyze_repository(repo_path: Path, out_dir: Optional[Path], show_code: bool, visualize: bool):
    """
    Analyze a single repository.
    
    Args:
        repo_path: Path to the repository
        out_dir: Base output directory (will create out_dir/repo_name/)
        show_code: Whether to include code in traces
        visualize: Whether to generate visualization
    """
    repo_name = repo_path.name
    logger.info(f"Analyzing repository: {repo_name} ({repo_path})")
    
    graph = SecurityGraph()
    files_map: Dict[str, List[Path]] = defaultdict(list)

    for root, _, files in os.walk(repo_path):
        for f in files:
            ext = Path(f).suffix.lower()
            if ext in EXT_TO_LANG:
                files_map[EXT_TO_LANG[ext]].append(Path(root) / f)

    all_raw_edges: List[Tuple] = []

    # Подсчитываем общее количество файлов для прогресс-бара
    total_files = sum(len(paths) for paths in files_map.values())
    files_processed = 0

    for lang, paths in files_map.items():
        logger.info(f"Analyzing {len(paths)} {lang} files...")
        parser_eng = CodeParser(lang, repo_root=repo_path)
        
        # Инициализируем прогресс-бар для текущего языка
        if total_files > 0:
            sys.stdout.write(f"\r[AST PROGRESS] [{'░' * 50}] Files parsed: {files_processed}/{total_files} ({lang})")
            sys.stdout.flush()
        
        for idx, p in enumerate(paths):
            try:
                content = p.read_bytes()
                nodes, edges = parser_eng.parse_file(p, content)
                for n in nodes:
                    graph.add_node(n)
                for e in edges:
                    all_raw_edges.append((e, lang))
                
                files_processed += 1
                
                # Обновляем прогресс-бар
                if total_files > 0:
                    bar_length = 50
                    filled = int((files_processed / total_files) * bar_length)
                    filled = min(bar_length, filled)
                    bar = "█" * filled + "░" * (bar_length - filled)
                    percentage = int((files_processed / total_files) * 100)
                    progress_text = f"\r[AST PROGRESS] [{bar}] Files parsed: {files_processed}/{total_files} ({percentage}%) - {lang}"
                    sys.stdout.write(progress_text)
                    sys.stdout.flush()
            except Exception as e:
                logger.debug(f"Failed reading/parsing {p}: {e}")
                files_processed += 1
                # Обновляем прогресс-бар даже при ошибке
                if total_files > 0:
                    bar_length = 50
                    filled = int((files_processed / total_files) * bar_length)
                    filled = min(bar_length, filled)
                    bar = "█" * filled + "░" * (bar_length - filled)
                    percentage = int((files_processed / total_files) * 100)
                    progress_text = f"\r[AST PROGRESS] [{bar}] Files parsed: {files_processed}/{total_files} ({percentage}%) - {lang}"
                    sys.stdout.write(progress_text)
                    sys.stdout.flush()
    
    # Завершаем прогресс-бар AST парсинга
    if total_files > 0:
        print()  # Новая строка после завершения прогресс-бара

    logger.info(f"Linking {len(all_raw_edges)} calls...")
    for e, lang in all_raw_edges:
        graph.add_edge(e.src, e.dst, lang, e.file, e.line)

    # Run trace analysis
    graph.trace_all(show_code=show_code, out_dir=None)
    
    # Save traces if out_dir is specified
    if out_dir and graph.trace_processor:
        trace_saver = TraceSaver(out_dir, repo_name)
        trace_ids = graph.trace_processor.get_all_trace_ids()
        
        logger.info(f"Saving {len(trace_ids)} traces to {out_dir}/{repo_name}/...")
        for trace_id in trace_ids:
            trace_text = graph.trace_processor.get_trace_text(
                trace_id, graph.nodes, graph.edge_sites, show_code=False
            )
            trace_text_with_code = graph.trace_processor.get_trace_text(
                trace_id, graph.nodes, graph.edge_sites, show_code=True
            )
            trace_saver.save_trace(trace_id, trace_text, trace_text_with_code)
        
        logger.info(f"Saved {len(trace_ids)} traces")

    if visualize:
        graph.visualize()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="Path to directory containing repositories")
    ap.add_argument("--visualize", action="store_true", help="Generate PNG")
    ap.add_argument("--code", action="store_true", help="Show code for each function in every trace")
    ap.add_argument("--out", help="Output directory to save traces: N.txt and N_code.txt")
    args = ap.parse_args()

    repos_dir = Path(args.repo).resolve()
    if not repos_dir.exists():
        print(f"Repositories directory not found: {repos_dir}")
        sys.exit(2)
    
    if not repos_dir.is_dir():
        print(f"Path is not a directory: {repos_dir}")
        sys.exit(2)

    out_dir = Path(args.out).resolve() if args.out else None

    # Find all repositories in the directory
    repositories = []
    for item in os.listdir(repos_dir):
        item_path = repos_dir / item
        if item_path.is_dir() and not item.startswith('.'):
            repositories.append(item_path)
    
    if not repositories:
        print(f"No repositories found in {repos_dir}")
        sys.exit(1)
    
    logger.info(f"Found {len(repositories)} repository(ies) to analyze")
    
    # Analyze each repository
    for repo_path in repositories:
        try:
            analyze_repository(repo_path, out_dir, args.code, args.visualize)
        except Exception as e:
            logger.error(f"Error analyzing repository {repo_path.name}: {e}", exc_info=True)
    
    logger.info("Analysis complete")

if __name__ == "__main__":
    main()
