#!/usr/bin/env python3
"""
Advanced Security Call Graph Auditor (ASCG) - FORMAT FIXED FINAL
Унифицированный инструмент для трассировки путей от Entry Points до уязвимых Sinks.
"""
import os, sys, logging, argparse, shutil, warnings
from pathlib import Path
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict

# Suppress library warnings
warnings.simplefilter(action='ignore', category=FutureWarning)

try:
    from tree_sitter_languages import get_language, get_parser
except ImportError:
    print("CRITICAL: Missing libraries. Run: pip install tree-sitter tree-sitter-languages graphviz")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
KNOWN_SINKS = {
    "python": {
        "exec", "eval", "compile", "open", "execfile", "input", "__import__",
        "os.system", "os.popen", "os.spawn", "subprocess.Popen", "subprocess.call", "subprocess.run",
        "pickle.loads", "yaml.load", "marshal.load", "shelve.open",
        "sqlite3.connect", "cursor.execute", "flask.render_template_string"
    },
    "javascript": {
        "eval", "setTimeout", "setInterval", "Function",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln", "innerHTML", "outerHTML", "dangerouslySetInnerHTML"
    },
    "java": {"Runtime.exec", "ProcessBuilder.start", "Statement.execute", "Statement.executeQuery"},
    "php": {"exec", "system", "passthru", "shell_exec", "eval", "popen", "proc_open", "mysqli_query"},
    "go": {"os.StartProcess", "exec.Command", "sql.Query", "sql.Exec", "template.Execute"},
    "ruby": {"eval", "system", "exec", "syscall", "open", "send", "public_send"}
}

LANG_CONFIG = {
    "python": {
        "funcs": """(function_definition name: (identifier) @name) @def""",
        "calls": """
            (call function: (identifier) @callee) 
            (call function: (attribute attribute: (identifier) @callee))
        """,
        "entry_heuristics": ["test_", "handler", "view", "controller", "route", "api", "endpoint", "app"]
    },
    "javascript": {
        "funcs": """
            (function_declaration name: (identifier) @name) @def
            (method_definition name: (property_identifier) @name) @def
            (variable_declarator name: (identifier) @name value: [(arrow_function) (function_expression)]) @def
        """,
        "calls": """
            (call_expression function: (identifier) @callee)
            (call_expression function: (member_expression property: (property_identifier) @callee))
        """,
        "entry_heuristics": ["router", "app", "handle", "controller", "test"]
    }
}

EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "javascript", ".jsx": "javascript",
    ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby", ".cs": "c_sharp"
}

# ============================================================================
# MODELS
# ============================================================================
@dataclass
class Node:
    uid: str
    name: str
    file: str
    line: int
    is_sink: bool = False
    is_entry: bool = False
    is_builtin: bool = False

@dataclass
class Edge:
    src: str
    dst: str
    file: str
    line: int

# ============================================================================
# PARSER ENGINE
# ============================================================================
class CodeParser:
    def __init__(self, lang: str):
        self.lang = lang
        self.config = LANG_CONFIG.get(lang, LANG_CONFIG.get("python")) 
        
        # Fallbacks
        if lang not in LANG_CONFIG:
             if lang == "java": self.config = {"funcs": "(method_declaration name: (identifier) @name) @def", "calls": "(method_invocation name: (identifier) @callee)", "entry_heuristics": ["Controller", "Mapping"]}
             elif lang == "go": self.config = {"funcs": "(function_declaration name: (identifier) @name) @def", "calls": "(call_expression function: (identifier) @callee)", "entry_heuristics": ["Handler", "Func"]}
             elif lang == "php": self.config = {"funcs": "(function_definition name: (name) @name) @def", "calls": "(function_call_expression function: (qualified_name) @callee)", "entry_heuristics": ["Action", "Controller"]}
             
        try:
            self.parser = get_parser(lang)
            self.lib = get_language(lang)
        except Exception:
            self.parser = None

    def parse_file(self, path: str, content: bytes) -> Tuple[List[Node], List[Edge]]:
        if not self.parser: return [], []
        try:
            tree = self.parser.parse(content)
        except Exception as e:
            logger.warning(f"Parse error {path}: {e}")
            return [], []
        
        module_name = Path(path).stem
        nodes = self._extract_functions(tree, path, content, module_name)
        edges = self._extract_calls(tree, path, content, module_name)
        return nodes, edges

    def _get_text(self, node, content) -> str:
        return content[node.start_byte:node.end_byte].decode('utf-8', 'ignore')

    def _extract_functions(self, tree, path, content, module) -> List[Node]:
        nodes = []
        try:
            query = self.lib.query(self.config['funcs'])
            captures = query.captures(tree.root_node)
        except Exception:
            return []
        
        for node, tag in captures:
            if tag == 'name':
                name = self._get_text(node, content)
                uid = f"{module}.{name}"
                is_entry = False
                
                # Check decorators
                parent = node.parent
                if parent:
                    parent_text = self._get_text(parent, content)
                    if "@" in parent_text or "#[" in parent_text: 
                        if any(x in parent_text for x in ["route", "get", "post", "mapping"]): is_entry = True
                
                # Check naming
                if any(h in name.lower() for h in self.config.get('entry_heuristics', [])):
                    is_entry = True

                nodes.append(Node(uid, name, str(path), node.start_point[0]+1, is_entry=is_entry))
        return nodes

    def _extract_calls(self, tree, path, content, module) -> List[Edge]:
        edges = []
        try:
            query = self.lib.query(self.config['calls'])
            captures = query.captures(tree.root_node)
        except Exception:
            return []
        
        def find_scope(n):
            curr = n.parent
            while curr:
                if curr.type.endswith('definition') or curr.type.endswith('declaration') or 'function' in curr.type:
                    child = curr.child_by_field_name('name')
                    if child: return f"{module}.{self._get_text(child, content)}"
                curr = curr.parent
            return f"{module}.<global>"

        for node, tag in captures:
            if tag == 'callee':
                callee_raw = self._get_text(node, content)
                caller_uid = find_scope(node)
                edges.append(Edge(caller_uid, callee_raw, str(path), node.start_point[0]+1))
                
        return edges

# ============================================================================
# GRAPH LOGIC
# ============================================================================
class SecurityGraph:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.adj: Dict[str, Set[str]] = defaultdict(set)
        self.rev_adj: Dict[str, Set[str]] = defaultdict(set)
        self.sinks_found: Set[str] = set()

    def add_node(self, n: Node):
        self.nodes[n.uid] = n
        if n.is_sink: self.sinks_found.add(n.uid)

    def add_edge(self, caller_uid: str, callee_name: str, lang: str):
        if caller_uid not in self.nodes:
            self.nodes[caller_uid] = Node(caller_uid, caller_uid.split('.')[-1], "unknown", 0)

        target_uid = None
        sinks = KNOWN_SINKS.get(lang, set())
        
        is_sink = (callee_name in sinks) or any(callee_name.endswith("." + s) for s in sinks)
        if is_sink:
            target_uid = f"builtin.{callee_name}"
            if target_uid not in self.nodes:
                self.nodes[target_uid] = Node(target_uid, callee_name, "<builtin>", 0, is_sink=True, is_builtin=True)
                self.sinks_found.add(target_uid)
        
        if not target_uid:
            caller_mod = caller_uid.rsplit('.', 1)[0]
            candidate_local = f"{caller_mod}.{callee_name}"
            if candidate_local in self.nodes:
                target_uid = candidate_local
            else:
                matches = [uid for uid, n in self.nodes.items() if n.name == callee_name]
                if matches: target_uid = matches[0]

        if not target_uid:
            target_uid = f"ext.{callee_name}"
            if target_uid not in self.nodes:
                self.nodes[target_uid] = Node(target_uid, callee_name, "<external>", 0, is_builtin=True)

        self.adj[caller_uid].add(target_uid)
        self.rev_adj[target_uid].add(caller_uid)

    def _print_formatted_path(self, path: List[str]):
        """Helper to print path in A -> B -> C format with details below."""
        # 1. Names Chain
        names = [self.nodes[uid].name for uid in path]
        arrow_str = " -> ".join(names)
        print(f"\n[🔴 PATH] {arrow_str}")
        
        # 2. Details for each function (file path and line)
        for uid in path:
            n = self.nodes[uid]
            if n.is_builtin:
                loc = "<builtin>"
            elif n.file == "unknown":
                loc = "<unknown source>"
            elif n.file == "<external>":
                loc = "<external lib>"
            else:
                try:
                    loc = f"{Path(n.file).relative_to(os.getcwd())}:{n.line}"
                except ValueError:
                    loc = f"{n.file}:{n.line}"
            print(f"   {n.name} ({loc})")

    def trace_all(self):
        print(f"\n{'='*30} VULNERABILITY REPORT {'='*30}")
        print(f"Total Nodes: {len(self.nodes)} | Sinks Found: {len(self.sinks_found)}")
        
        entries = [uid for uid, n in self.nodes.items() if n.is_entry]
        print(f"Entry Points: {len(entries)}")

        if not self.sinks_found:
            print("No dangerous sinks detected.")
            return

        paths_found = 0
        def dfs(curr, path, visited_local):
            nonlocal paths_found
            if self.nodes[curr].is_sink:
                paths_found += 1
                self._print_formatted_path(path)
                return

            if len(path) > 12: return

            for neighbor in self.adj.get(curr, []):
                if neighbor not in visited_local:
                    dfs(neighbor, path + [neighbor], visited_local | {neighbor})

        # 1. Forward Trace
        for entry in entries:
            dfs(entry, [entry], {entry})

        # 2. Backward Trace (if needed or for extra info)
        if paths_found == 0:
            print("\n[INFO] No direct paths from Entry Points found.")
            print("Showing immediate callers of Sinks (Backward Trace):")
            for sink in self.sinks_found:
                callers = self.rev_adj.get(sink, [])
                if callers:
                    # Form little paths: Caller -> Sink
                    for c in list(callers)[:5]: # Limit to 5 per sink
                        # Construct a mini-path for display
                        path = [c, sink]
                        self._print_formatted_path(path)

    def visualize(self, filename="vuln_graph"):
        if not shutil.which("dot"):
            logger.warning("Graphviz 'dot' not found. Visualization skipped. (Install 'graphviz' pkg)")
            return

        try:
            from graphviz import Digraph
            dot = Digraph(comment='Security Graph', format='png')
            dot.attr(rankdir='LR', overlap='false')
            
            for uid, n in self.nodes.items():
                if n.is_sink:
                    dot.node(uid, label=f"{n.name}\n(SINK)", style='filled', fillcolor='#ffcccc', color='red')
                elif n.is_entry:
                    dot.node(uid, label=f"{n.name}", style='filled', fillcolor='#ccffcc')
                elif not n.is_builtin:
                     dot.node(uid, label=f"{n.name}\n{Path(n.file).name}")

            for src, dests in self.adj.items():
                for dst in dests:
                    color = 'red' if dst in self.sinks_found else '#666666'
                    dot.edge(src, dst, color=color)

            dot.render(filename, view=False)
            logger.info(f"Graph saved to {filename}.png")
        except Exception as e:
            logger.error(f"Visualization error: {e}")

# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="Path to repository")
    parser.add_argument("--visualize", action="store_true", help="Generate PNG")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    graph = SecurityGraph()
    files_map = defaultdict(list)

    for root, _, files in os.walk(repo):
        for f in files:
            ext = Path(f).suffix
            if ext in EXT_TO_LANG:
                files_map[EXT_TO_LANG[ext]].append(Path(root)/f)

    all_raw_edges = []
    for lang, paths in files_map.items():
        logger.info(f"Analyzing {len(paths)} {lang} files...")
        parser_eng = CodeParser(lang)
        for p in paths:
            try:
                with open(p, 'rb') as f: content = f.read()
                nodes, edges = parser_eng.parse_file(str(p), content)
                for n in nodes: graph.add_node(n)
                for e in edges: all_raw_edges.append((e, lang))
            except Exception:
                pass

    logger.info(f"Linking {len(all_raw_edges)} calls...")
    for e, lang in all_raw_edges:
        graph.add_edge(e.src, e.dst, lang)

    graph.trace_all()
    if args.visualize:
        graph.visualize()

if __name__ == "__main__":
    main()
