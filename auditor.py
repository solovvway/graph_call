#!/usr/bin/env python3

import os, sys, logging, argparse, warnings, json
import importlib
import importlib.util
import types
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

# Import modular components - will be set dynamically based on --core parameter
CodeParser = None
EXT_TO_LANG = None
Node = None
SecurityGraph = None
KNOWN_SINKS = None
is_php_source = None
TraceProcessor = None
from tools.trace_deduplicate import TraceDeduplicator


def load_core_module(core_name: str):
    """
    Dynamically load modules from the specified core (core1, core2, or core3-fast).
    
    Args:
        core_name: Name of the core module to load (core1, core2, or core3-fast)
    
    Returns:
        Tuple of (CodeParser, EXT_TO_LANG, Node, SecurityGraph, KNOWN_SINKS, is_php_source, TraceProcessor)
    """
    global CodeParser, EXT_TO_LANG, Node, SecurityGraph, KNOWN_SINKS, is_php_source, TraceProcessor
    
    if core_name not in ["core1", "core2", "core3-fast"]:
        raise ValueError(f"Invalid core name: {core_name}. Must be one of: core1, core2, core3-fast")
    
    try:
        if core_name == "core1":
            # core1 might have different structure, try to import
            # If core1 doesn't have modular structure, we'll need to handle it differently
            try:
                from core1.ast_core import CodeParser, EXT_TO_LANG, Node
                from core1.graph_builder import SecurityGraph
                from core1.sinks import KNOWN_SINKS
                from core1.sources import is_php_source
                from core1.trace_processor import TraceProcessor
            except ImportError:
                # core1 might use a different structure - use core2 as fallback or raise error
                logger.warning(f"core1 doesn't have modular structure, falling back to core2")
                from core2.ast_core import CodeParser, EXT_TO_LANG, Node
                from core2.graph_builder import SecurityGraph
                from core2.sinks import KNOWN_SINKS
                from core2.sources import is_php_source
                from core2.trace_processor import TraceProcessor
        elif core_name == "core2":
            from core2.ast_core import CodeParser, EXT_TO_LANG, Node
            from core2.graph_builder import SecurityGraph
            from core2.sinks import KNOWN_SINKS
            from core2.sources import is_php_source
            from core2.trace_processor import TraceProcessor
        elif core_name == "core3-fast":
            # core3-fast has a hyphen, so we need special handling for imports
            # Get the directory of this script
            script_dir = Path(__file__).parent
            core3_fast_dir = script_dir / "core3-fast"
            
            # Create a fake package in sys.modules to handle relative imports
            package_name = "core3_fast"  # Use underscore for Python compatibility
            if package_name not in sys.modules:
                # Create a fake package module using types.ModuleType
                fake_package = types.ModuleType(package_name)
                fake_package.__path__ = [str(core3_fast_dir)]
                fake_package.__file__ = str(core3_fast_dir / "__init__.py")
                sys.modules[package_name] = fake_package
            
            def load_module_from_file(module_name: str, file_path: Path):
                """Load a module from a file path, handling relative imports."""
                full_module_name = f"{package_name}.{module_name}"
                spec = importlib.util.spec_from_file_location(full_module_name, file_path)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Could not load module {module_name} from {file_path}")
                module = importlib.util.module_from_spec(spec)
                module.__package__ = package_name
                module.__name__ = full_module_name
                # Register in sys.modules before execution to allow relative imports
                sys.modules[full_module_name] = module
                spec.loader.exec_module(module)
                return module
            
            # Load modules in dependency order (ast_core first, then others that depend on it)
            ast_core_module = load_module_from_file("ast_core", core3_fast_dir / "ast_core.py")
            sinks_module = load_module_from_file("sinks", core3_fast_dir / "sinks.py")
            sources_module = load_module_from_file("sources", core3_fast_dir / "sources.py")
            trace_processor_module = load_module_from_file("trace_processor", core3_fast_dir / "trace_processor.py")
            graph_builder_module = load_module_from_file("graph_builder", core3_fast_dir / "graph_builder.py")
            
            CodeParser = ast_core_module.CodeParser
            EXT_TO_LANG = ast_core_module.EXT_TO_LANG
            Node = ast_core_module.Node
            SecurityGraph = graph_builder_module.SecurityGraph
            KNOWN_SINKS = sinks_module.KNOWN_SINKS
            is_php_source = sources_module.is_php_source
            TraceProcessor = trace_processor_module.TraceProcessor
        else:
            raise ValueError(f"Unknown core: {core_name}")
        
        return CodeParser, EXT_TO_LANG, Node, SecurityGraph, KNOWN_SINKS, is_php_source, TraceProcessor
    except ImportError as e:
        logger.error(f"Failed to import modules from {core_name}: {e}")
        raise


def analyze_repository(repo_path: Path, out_dir: Optional[Path], show_code: bool, visualize: bool, core_name: str = "core2"):
    """
    Analyze a single repository.
    
    Args:
        repo_path: Path to the repository
        out_dir: Base output directory (will create out_dir/repo_name/)
        show_code: Whether to include code in traces
        visualize: Whether to generate visualization
        core_name: Name of the core module to use (core1, core2, or core3-fast)
    """
    # Load core modules
    load_core_module(core_name)
    
    repo_name = repo_path.name
    logger.info(f"Analyzing repository: {repo_name} ({repo_path})")
    
    # Check if repository has its own sources.json
    repo_sources = repo_path / "sources.json"
    if repo_sources.exists():
        logger.info(f"Found repository-specific sources.json in {repo_path}")
    
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
    
    # Save traces if out_dir is specified (simple YAML format, deduplication will be done later)
    if out_dir and graph.trace_processor:
        reports_dir = Path(out_dir).resolve()
        repo_dir = reports_dir / repo_name
        repo_dir.mkdir(parents=True, exist_ok=True)
        
        trace_ids = graph.trace_processor.get_all_trace_ids()
        
        logger.info(f"Saving {len(trace_ids)} traces to {repo_dir}/...")
        for trace_id in trace_ids:
            trace_text_with_code = graph.trace_processor.get_trace_text(
                trace_id, graph.nodes, graph.edge_sites, show_code=True
            )
            (repo_dir / f"{trace_id}_code.txt").write_text(
                trace_text_with_code, encoding="utf-8", errors="ignore"
            )
        
        logger.info(f"Saved {len(trace_ids)} traces to {repo_dir}")
        
        # Run deduplication and save to deduplicated subfolder
        try:
            logger.info("Starting trace deduplication...")
            deduplicator = TraceDeduplicator(reports_dir, repo_name)
            deduplicator.deduplicate()
            logger.info("Trace deduplication complete")
        except Exception as e:
            logger.warning(f"Failed to deduplicate traces: {e}", exc_info=True)

    if visualize:
        graph.visualize()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="Path to directory containing repositories")
    ap.add_argument("--core", default="core2", choices=["core1", "core2", "core3-fast"], 
                    help="Core module to use for analysis (default: core2)")
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
            analyze_repository(repo_path, out_dir, args.code, args.visualize, args.core)
        except Exception as e:
            logger.error(f"Error analyzing repository {repo_path.name}: {e}", exc_info=True)
    
    logger.info("Analysis complete")

if __name__ == "__main__":
    main()
