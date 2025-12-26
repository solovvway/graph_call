#!/usr/bin/env python3
"""
Multi-Language Security Call Graph Builder (IPCG)
Построение графа вызовов с отслеживанием путей от Entry Points (роутов) до Sinks (опасных функций).
Поддерживает: Python, JavaScript/TypeScript, Java, Go, PHP, Ruby, C#.
"""
import os, json, sys, logging, argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict, field
from collections import defaultdict

try:
    from tree_sitter_languages import get_language, get_parser
except ImportError:
    print("Error: Missing libraries. Run: pip install tree-sitter tree-sitter-languages")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# LANGUAGE CONFIGURATION & VULNERABILITY SINKS
# ============================================================================
# Списки опасных функций (Sinks), аналогичные тем, что ищут Regex'ы
KNOWN_SINKS = {
    "python": {"exec", "eval", "compile", "open", "os.system", "os.popen", "subprocess.Popen", "subprocess.call", "pickle.loads", "yaml.load", "cursor.execute"},
    "javascript": {"eval", "setTimeout", "setInterval", "child_process.exec", "child_process.spawn", "document.write", "innerHTML", "dangerouslySetInnerHTML"},
    "java": {"Runtime.exec", "ProcessBuilder.start", "Statement.execute", "Statement.executeQuery", "Class.forName"},
    "php": {"exec", "system", "passthru", "shell_exec", "eval", "popen", "proc_open", "mysqli_query", "query"},
    "go": {"os.StartProcess", "exec.Command", "sql.Query", "template.Execute"},
    "ruby": {"eval", "system", "exec", "syscall", "open", "send"},
    "c_sharp": {"Process.Start", "SqlCommand", "ExecuteNonQuery", "ExecuteReader"}
}

LANG_QUERIES = {
    "python": {
        "funcs": """(function_definition name: (identifier) @name) @def""",
        "calls": """(call function: [(identifier) @callee (attribute object: (_) @obj attribute: (identifier) @attr)])""",
        "routes": ["app.route", "bp.route", "router.get", "router.post"]
    },
    "javascript": {
        "funcs": """
            (function_declaration name: (identifier) @name) @def
            (method_definition name: (property_identifier) @name) @def
            (arrow_function) @def
        """,
        "calls": """(call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @attr)])""",
        "routes": ["router.get", "app.get", "app.post", "router.post"]
    },
    "java": {
        "funcs": """(method_declaration name: (identifier) @name) @def""",
        "calls": """(method_invocation name: (identifier) @callee)""",
        "routes": ["@GetMapping", "@PostMapping", "@RequestMapping"]
    },
    "php": {
        "funcs": """(function_definition name: (name) @name) @def""",
        "calls": """(function_call_expression function: (qualified_name) @callee) (member_call_expression name: (name) @attr)""",
        "routes": ["Route::get", "Route::post"]
    },
    "go": {
        "funcs": """(function_declaration name: (identifier) @name) @def""",
        "calls": """(call_expression function: [(identifier) @callee (selector_expression field: (field_identifier) @attr)])""",
        "routes": ["router.GET", "http.HandleFunc"]
    },
     "ruby": {
        "funcs": """(method name: (identifier) @name) @def""",
        "calls": """(call method: (identifier) @callee)""",
        "routes": ["get", "post", "match"]
    },
}

FILE_EXTENSIONS = {
    ".py": "python", ".js": "javascript", ".ts": "javascript", 
    ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby", ".cs": "c_sharp"
}

# ============================================================================
# DATA MODELS
# ============================================================================
@dataclass
class FunctionNode:
    name: str
    full_name: str
    file: str
    line: int
    is_external: bool = False  # True для builtins/libs
    is_sink: bool = False      # True для опасных функций
    is_entry: bool = False     # True для роутов

@dataclass
class CallEdge:
    caller: str
    callee: str
    file: str
    line: int

# ============================================================================
# ANALYZER CORE
# ============================================================================
class MultiLangParser:
    def __init__(self, language: str):
        self.lang_name = language
        self.query_config = LANG_QUERIES.get(language, {})
        try:
            self.parser = get_parser(language)
            self.lang_lib = get_language(language)
        except Exception as e:
            logger.error(f"Language {language} not supported: {e}")
            self.parser = None

    def parse(self, file_path: str, content: bytes) -> Tuple[List[FunctionNode], List[CallEdge]]:
        if not self.parser or not self.query_config: return [], []
        
        tree = self.parser.parse(content)
        funcs = self._extract_funcs(tree, file_path, content)
        calls = self._extract_calls(tree, file_path, content, funcs)
        return funcs, calls

    def _get_text(self, node, content):
        return content[node.start_byte:node.end_byte].decode('utf-8', 'ignore')

    def _extract_funcs(self, tree, file_path, content):
        nodes = []
        q = self.lang_lib.query(self.query_config['funcs'])
        captures = q.captures(tree.root_node)
        
        # Simple module naming: filename without ext
        module = Path(file_path).stem

        for node, tag in captures:
            if tag == 'name':
                func_name = self._get_text(node, content)
                full_name = f"{module}.{func_name}"
                
                # Heuristic for Entry Points (scan for decorators or usage of "route" in file)
                is_entry = False
                parent_text = self._get_text(node.parent, content)
                for route_sig in self.query_config.get('routes', []):
                    if route_sig in parent_text or "Controller" in str(file_path):
                        is_entry = True
                        break

                nodes.append(FunctionNode(
                    name=func_name, full_name=full_name, file=str(file_path),
                    line=node.start_point[0] + 1, is_entry=is_entry
                ))
        return nodes

    def _extract_calls(self, tree, file_path, content, defined_funcs):
        edges = []
        q = self.lang_lib.query(self.query_config['calls'])
        captures = q.captures(tree.root_node)
        
        module = Path(file_path).stem
        
        # Map ranges to functions to find "caller"
        def find_caller(node_start):
            for f in defined_funcs:
                # This assumes simple sequential functions. 
                # Better approach: check node range containment.
                pass 
            return f"{module}.<script_scope>" # Default

        for node, tag in captures:
            callee_name = None
            if tag == 'callee':
                callee_name = self._get_text(node, content)
            elif tag == 'attr':
                # Handle obj.method() -> method
                callee_name = self._get_text(node, content)
            
            if callee_name:
                # Find enclosing function (caller)
                curr = node
                caller_name = f"{module}.<global>"
                while curr:
                    if curr.type in ['function_definition', 'function_declaration', 'method_definition', 'method_declaration']:
                        # Try to find name child
                        child_name = curr.child_by_field_name('name')
                        if child_name:
                            caller_name = f"{module}.{self._get_text(child_name, content)}"
                        break
                    curr = curr.parent

                edges.append(CallEdge(caller=caller_name, callee=callee_name, file=str(file_path), line=node.start_point[0]+1))
        return edges

# ============================================================================
# GRAPH BUILDER
# ============================================================================
class CallGraph:
    def __init__(self):
        self.nodes: Dict[str, FunctionNode] = {}
        self.forward: Dict[str, Set[str]] = defaultdict(set)
        self.backward: Dict[str, Set[str]] = defaultdict(set)
        self.sinks: Set[str] = set()
        self.entries: Set[str] = set()

    def add_node(self, node: FunctionNode):
        self.nodes[node.full_name] = node
        if node.is_sink: self.sinks.add(node.full_name)
        if node.is_entry: self.entries.add(node.full_name)

    def resolve_and_add_edge(self, edge: CallEdge, lang: str):
        # 1. Try exact match (local function)
        # We need to find the callee in our nodes.
        # Since we only captured "short names" in calls (e.g., "exec"), we need heuristics.
        
        target_full_name = None
        
        # Check against known Sinks first (Implicit Global)
        sinks = KNOWN_SINKS.get(lang, set())
        
        # Heuristic 1: Is it a dangerous sink?
        # Check simple name (exec) or dot name (os.system)
        if edge.callee in sinks or any(edge.callee.endswith(f".{s}") for s in sinks):
            target_full_name = f"builtin.{edge.callee}"
            if target_full_name not in self.nodes:
                self.add_node(FunctionNode(
                    name=edge.callee, full_name=target_full_name, file="<builtin>", 
                    line=0, is_external=True, is_sink=True
                ))
        
        # Heuristic 2: Match against defined functions (Module.func)
        if not target_full_name:
            # Try to find a function named 'callee' in the same module or others
            candidates = [k for k, v in self.nodes.items() if v.name == edge.callee]
            if candidates:
                # Pick best match (same file/module priority)
                # Simplified: pick first
                target_full_name = candidates[0]
        
        # Heuristic 3: External/Lib call (Unknown)
        if not target_full_name:
            target_full_name = f"external.{edge.callee}"
            if target_full_name not in self.nodes:
                 self.add_node(FunctionNode(
                    name=edge.callee, full_name=target_full_name, file="<external>", 
                    line=0, is_external=True, is_sink=False
                ))

        # Add Edge
        if edge.caller not in self.nodes:
            # Ensure caller exists (e.g. global scope)
            self.add_node(FunctionNode(edge.caller, edge.caller, edge.file, 0))
            
        self.forward[edge.caller].add(target_full_name)
        self.backward[target_full_name].add(edge.caller)

    def trace_routes_to_sinks(self):
        """Finds paths from Entry Points to Sinks"""
        results = []
        if not self.entries:
            logger.warning("No explicit entry points found. Analyzing ALL functions as potential starts.")
            starts = [n for n in self.nodes if not self.nodes[n].is_external]
        else:
            starts = list(self.entries)

        logger.info(f"Tracing from {len(starts)} start points to {len(self.sinks)} sinks...")
        
        memo = {}

        def get_paths(curr, path_stack):
            if curr in self.sinks:
                return [[curr]]
            if len(path_stack) > 15: return [] # Depth limit
            
            paths = []
            for neighbor in self.forward.get(curr, []):
                if neighbor in path_stack: continue # Cycle
                
                suffixes = get_paths(neighbor, path_stack + [neighbor])
                for suf in suffixes:
                    paths.append([curr] + suf)
            return paths

        found_any = False
        for start in starts:
            paths = get_paths(start, [start])
            if paths:
                found_any = True
                print(f"\n[VULNERABILITY TRACE] From {start}:")
                for p in paths[:5]: # Limit output
                    chain = " -> ".join([self.nodes[n].name for n in p])
                    print(f"  🔴 Path: {chain}")
                    print(f"     (Sink: {p[-1]} in {self.nodes[p[-1]].file})")

        if not found_any:
            print("\nNo paths from Routes to Sinks found.")

    def visualize(self, output="graph"):
        try:
            from graphviz import Digraph
            dot = Digraph(comment='Security Call Graph', format='png')
            dot.attr(rankdir='LR')
            
            for uid, node in self.nodes.items():
                color = 'lightgrey'
                shape = 'box'
                if node.is_sink: 
                    color = 'red'; shape='ellipse'
                elif node.is_entry:
                    color = 'green'
                elif node.is_external:
                    color = 'lightblue'
                
                label = f"{node.name}\n{Path(node.file).name}:{node.line}"
                dot.node(uid, label=label, style='filled', fillcolor=color, shape=shape)
            
            for src, dests in self.forward.items():
                for dst in dests:
                    dot.edge(src, dst)
            
            dot.render(output, view=False)
            logger.info(f"Graph saved to {output}.png")
        except Exception as e:
            logger.error(f"Visualization failed: {e}")

# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="Security Call Graph Auditor")
    parser.add_argument("--repo", required=True, help="Path to repository")
    parser.add_argument("--visualize", action="store_true", help="Generate PNG")
    args = parser.parse_args()

    repo_path = Path(args.repo).resolve()
    graph = CallGraph()
    
    # 1. Identify Files
    files_by_lang = defaultdict(list)
    for root, _, files in os.walk(repo_path):
        for f in files:
            ext = Path(f).suffix
            if ext in FILE_EXTENSIONS:
                files_by_lang[FILE_EXTENSIONS[ext]].append(Path(root) / f)

    # 2. Parse & Build Nodes
    all_edges = []
    
    for lang, files in files_by_lang.items():
        logger.info(f"Parsing {len(files)} {lang} files...")
        parser_inst = MultiLangParser(lang)
        
        for fpath in files:
            try:
                with open(fpath, 'rb') as f: content = f.read()
                funcs, calls = parser_inst.parse(str(fpath), content)
                
                for fn in funcs: 
                    graph.add_node(fn)
                
                # Store edges to link after all nodes are known
                for edge in calls:
                    all_edges.append((edge, lang))
                    
            except Exception as e:
                logger.warning(f"Failed to parse {fpath}: {e}")

    # 3. Resolve Edges (Link Phase)
    logger.info(f"Resolving {len(all_edges)} calls...")
    for edge, lang in all_edges:
        graph.resolve_and_add_edge(edge, lang)

    # 4. Analyze Paths
    print(f"\n{'='*60}")
    print(f"ANALYSIS REPORT: {repo_path}")
    print(f"Nodes: {len(graph.nodes)} | Edges: {sum(len(x) for x in graph.forward.values())}")
    print(f"Detected Sinks (Builtins/Libs): {len(graph.sinks)}")
    print(f"Detected Entry Points (Routes): {len(graph.entries)}")
    print(f"{'='*60}")

    graph.trace_routes_to_sinks()

    if args.visualize:
        graph.visualize("security_trace")

if __name__ == "__main__":
    main()
