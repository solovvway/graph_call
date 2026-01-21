#!/usr/bin/env python3

import os, sys, logging, argparse, warnings
from pathlib import Path
from typing import Dict, List
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
from ast_core import CodeParser, EXT_TO_LANG
from graph_builder import SecurityGraph
from sinks import KNOWN_SINKS
from sources import is_php_source

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="Path to repository")
    ap.add_argument("--visualize", action="store_true", help="Generate PNG")
    ap.add_argument("--code", action="store_true", help="Show code for each function in every trace")
    ap.add_argument("--out", help="Output directory to save traces: N.txt and N_code.txt")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    if not repo.exists():
        print(f"Repo not found: {repo}")
        sys.exit(2)

    out_dir = Path(args.out).resolve() if args.out else None

    graph = SecurityGraph()
    files_map: Dict[str, List[Path]] = defaultdict(list)

    for root, _, files in os.walk(repo):
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
        parser_eng = CodeParser(lang, repo_root=repo)
        
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

    graph.trace_all(show_code=args.code, out_dir=out_dir)

    if args.visualize:
        graph.visualize()

if __name__ == "__main__":
    main()
