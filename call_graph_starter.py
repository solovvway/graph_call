#!/usr/bin/env python3
"""
Финальная, рабочая реализация для построения межпроцедурного графа вызовов (IPCG)
Language-agnostic, с парсингом импортов для Python.
"""
import os, json, sys, logging, argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict, field
from collections import defaultdict

try:
    from tree_sitter import Language, Parser, Node
    from tree_sitter_languages import get_language
except ImportError:
    print("Install required packages: pip install tree-sitter tree-sitter-languages"); sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# DATA MODELS
# ============================================================================
@dataclass
class FunctionDefinition:
    name: str
    file: str
    line: int
    column: int
    full_name: str = ""
    decorators: List[str] = field(default_factory=list)

@dataclass
class FunctionCall: caller_full_name: str; callee_name: str; file: str; line: int; column: int
@dataclass
class ModuleImports:
    direct_imports: Dict[str, str] = field(default_factory=dict)
    aliased_imports: Dict[str, str] = field(default_factory=dict)
    from_imports: Dict[str, str] = field(default_factory=dict)

# ============================================================================
# TREE-SITTER PARSER
# ============================================================================
class UniversalCodeParser:
    QUERIES = {
        "python": {
            "functions": """
                (function_definition
                    name: (identifier) @func_name
                ) @func_def
                (decorator) @decorator
            """,
            "calls": """(call function: [(identifier) @callee (attribute object: (_) @callee_obj attribute: (identifier) @callee_attr)])""",
            "imports": """
                (import_statement name: (dotted_name) @import)
                (import_statement (aliased_import name: (dotted_name) @import alias: (identifier) @alias))
                (import_from_statement
                    module_name: (dotted_name) @from_module
                    name: (dotted_name) @from_import)
                (import_from_statement
                    module_name: (dotted_name) @from_module
                    (aliased_import name: (dotted_name) @from_import alias: (identifier) @alias))
            """
        }
    }

    def __init__(self, language: str, repo_path: str):
        self.language, self.repo_root = language, Path(repo_path).resolve()
        self.parser = Parser()
        try:
            lang_lib = get_language(language)
            self.parser.set_language(lang_lib)
            self.queries = self.QUERIES.get(language, {})
            self.func_query = lang_lib.query(self.queries.get("functions", ""))
            self.call_query = lang_lib.query(self.queries.get("calls", ""))
            self.import_query = lang_lib.query(self.queries.get("imports", ""))
            self.func_types = self.queries.get("func_types", {"function_definition"})
        except Exception as e:
            logger.error(f"Failed to initialize parser for {language}: {e}"); sys.exit(1)

    def parse_file(self, file_path: str) -> Tuple[List[FunctionDefinition], List[FunctionCall], Optional[ModuleImports]]:
        file_path_obj = Path(file_path).resolve()
        try:
            with open(file_path_obj, 'rb') as f: content = f.read()
        except Exception as e: logger.warning(f"Could not read {file_path_obj}: {e}"); return [], [], None
        tree = self.parser.parse(content)
        module_name = self._get_module_name(file_path_obj)
        functions = self._extract_functions(tree, file_path_obj, content, module_name)
        calls = self._extract_calls(tree, file_path_obj, content, module_name)
        imports = self._extract_imports(tree, content, module_name)
        return functions, calls, imports

    def _get_node_text(self, n: Node, c: bytes) -> str: return c[n.start_byte:n.end_byte].decode('utf-8', 'ignore')
    def _get_module_name(self, p: Path) -> str:
        try: rp = p.relative_to(self.repo_root)
        except ValueError: return p.stem
        parts = list(rp.parts)
        if parts and parts[-1] == '__init__.py': parts.pop()
        elif parts: parts[-1] = parts[-1].replace('.py', '')
        
        # Handle src layout
        if parts and parts[0] == 'src':
            parts.pop(0)
            
        return '.'.join(parts)

    def _extract_functions(self, tree, file_path, content, module_name):
        functions = []
        captures = self.func_query.captures(tree.root_node)
        
        # Map function definition nodes to their decorators
        func_decorators = defaultdict(list)
        
        # First pass: collect decorators
        # In tree-sitter python grammar, decorators are siblings preceding the function_definition
        # OR they are part of the decorated_definition which wraps the function_definition
        # Let's try a simpler approach: iterate over function definitions and look at their previous siblings
        
        for node, name in captures:
            if name == 'func_def':
                decorators = []
                # Check for decorated_definition parent
                parent = node.parent
                if parent.type == 'decorated_definition':
                    for child in parent.children:
                        if child.type == 'decorator':
                            decorators.append(self._get_node_text(child, content).strip())
                
                func_decorators[node.id] = decorators

        for node, name in captures:
            if name == 'func_name':
                func_def_node = node.parent
                func_name = self._get_node_text(node, content)
                full_name = f"{module_name}.{func_name}"
                
                # Check if function is inside a class
                parent = func_def_node.parent
                while parent:
                    if parent.type == 'class_definition':
                        class_name_node = parent.child_by_field_name('name')
                        if class_name_node:
                            class_name = self._get_node_text(class_name_node, content)
                            full_name = f"{module_name}.{class_name}.{func_name}"
                        break
                    parent = parent.parent

                functions.append(FunctionDefinition(
                    name=func_name, file=str(file_path),
                    line=func_def_node.start_point[0], column=func_def_node.start_point[1],
                    full_name=full_name,
                    decorators=func_decorators.get(func_def_node.id, [])
                ))
        return functions

    def _extract_calls(self, tree, file_path, content, module_name):
        calls, captures = [], self.call_query.captures(tree.root_node)
        obj_map = {node.parent.id: self._get_node_text(node, content) for node, name in captures if name == 'callee_obj'}
        for node, name in captures:
            calee, cnode = None, None
            if name == 'callee': calee, cnode = self._get_node_text(node, content), node.parent
            elif name == 'callee_attr':
                ot = obj_map.get(node.parent.id, "unknown")
                calee, cnode = f"{ot}.{self._get_node_text(node, content)}", node.parent.parent
            if not calee or not cnode: continue
            caller_node = self._find_enclosing_function_node(node)
            caller_name = f"{module_name}.<module_level>"
            if caller_node and (cn_node := caller_node.child_by_field_name('name')):
                caller_name = f"{module_name}.{self._get_node_text(cn_node, content)}"
            calls.append(FunctionCall(caller_name, calee, str(file_path), cnode.start_point[0], cnode.start_point[1]))
        return calls

    def _extract_imports(self, tree, content, module_name):
        if not self.import_query: return None
        imports = ModuleImports()
        captures_by_parent = defaultdict(list)
        for node, name in self.import_query.captures(tree.root_node):
            captures_by_parent[node.parent.id].append((name, self._get_node_text(node, content)))
        for _, values_list in captures_by_parent.items():
            vals = dict(values_list)
            if 'import' in vals and 'alias' in vals: imports.aliased_imports[vals['alias']] = vals['import']
            elif 'import' in vals: imports.direct_imports[vals['import']] = vals['import']
            elif 'from_module' in vals and 'from_import' in vals:
                alias = vals.get('alias', vals['from_import'])
                if alias == '*': continue
                fp, fib = vals['from_module'], vals['from_module']
                if fp.startswith('.'):
                    nd = len(fp) - len(fp.lstrip('.')); bp = module_name.split('.')[:-(nd - 1)] if nd > 1 else module_name.split('.')[:-1]; sfx = fp.lstrip('.')
                    fib = '.'.join(bp + ([sfx] if sfx else []))
                imports.from_imports[alias] = f"{fib}.{vals['from_import']}"
        return imports

    def _find_enclosing_function_node(self, node: Node) -> Optional[Node]:
        c = node.parent
        while c:
            if c.type in self.func_types: return c
            c = c.parent
        return None

# ============================================================================
# LINKER, GRAPH, ANALYZER & MAIN (Без изменений, они уже были корректны)
# ============================================================================
class InterProceduralLinker:
    def __init__(self): self.functions, self.imports_map = {}, {}
    def register_definitions(self, funcs, imps):
        for f in funcs: self.functions[f.full_name] = f
        self.imports_map = imps
    def resolve_calls(self, calls):
        resolved, unresolved = [], defaultdict(int)
        for call in calls:
            if res := self._resolve_one_call(call): resolved.append((call.caller_full_name, res))
            else: unresolved[call.callee_name] += 1
        if unresolved:
            logger.info(f"Could not resolve {sum(unresolved.values())} calls. Sample:")
            for name, count in sorted(unresolved.items(), key=lambda i: i[1], reverse=True)[:5]:
                logger.info(f"  - '{name}' (called {count} times)")
        return resolved
    def _resolve_one_call(self, call):
        parts = call.callee_name.split('.')
        base_name = parts[0]
        
        # Extract module name from caller's full name
        # Assuming caller_full_name is like "module.class.method" or "module.function"
        # We need to find the module part. Since we don't know the depth, we try to match with imports map keys.
        mname = None
        caller_parts = call.caller_full_name.split('.')
        for i in range(len(caller_parts), 0, -1):
            potential_mname = ".".join(caller_parts[:i])
            if potential_mname in self.imports_map:
                mname = potential_mname
                break
        
        if not mname:
             # Fallback: try stripping last part
             mname = ".".join(call.caller_full_name.split('.')[:-1])

        imps = self.imports_map.get(mname)
        
        # 1. Check local definition (in same module)
        local_name = f"{mname}.{call.callee_name}"
        if local_name in self.functions: return local_name
        
        # Check if it's a method call on self (e.g. self.method())
        if base_name == 'self' and len(parts) > 1:
             # This is a heuristic. We assume the method is in the same class/module.
             # A proper resolution would require type inference.
             # Try to find the class name from caller
             # caller: module.Class.method
             # callee: self.other_method -> module.Class.other_method
             caller_parts = call.caller_full_name.split('.')
             if len(caller_parts) >= 3: # module.Class.method
                 class_name = caller_parts[-2]
                 method_name = parts[1]
                 potential_full = f"{mname}.{class_name}.{method_name}"
                 if potential_full in self.functions: return potential_full

        if not imps: return None

        # 2. Check from imports (from X import Y)
        if base_name in imps.from_imports:
            imported_full = imps.from_imports[base_name]
            # If callee is just Y, then imported_full is the candidate
            # If callee is Y.Z, then imported_full.Z is the candidate
            full = ".".join([imported_full] + parts[1:])
            if full in self.functions: return full
            
            # Handle class static methods/attributes: from models.user_model import User -> User.decode_auth_token
            # imported_full is models.user_model.User
            # callee is User.decode_auth_token
            # parts[1:] is ['decode_auth_token']
            # full becomes models.user_model.User.decode_auth_token
            
            # Also check if imported_full itself is a function (e.g. from module import func)
            if imported_full in self.functions and len(parts) == 1:
                return imported_full
            
        # 3. Check aliased imports (import X as Y)
        if base_name in imps.aliased_imports:
            imported_full = imps.aliased_imports[base_name]
            full = ".".join([imported_full] + parts[1:])
            if full in self.functions: return full

        # 4. Check direct imports (import X)
        if base_name in imps.direct_imports:
             # callee X.Y -> X.Y
             if call.callee_name in self.functions: return call.callee_name
             
        return None
@dataclass
class CallGraph:
    functions: Dict[str, FunctionDefinition]; forward_edges: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list)); backward_edges: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    def add_edge(self, c, e):
        if e not in self.forward_edges[c]: self.forward_edges[c].append(e)
        if c not in self.backward_edges[e]: self.backward_edges[e].append(c)
    def to_json(self): return {"functions": {n: asdict(f) for n, f in self.functions.items()},"edges": {"forward": dict(self.forward_edges), "backward": dict(self.backward_edges)},"statistics": {"total_functions": len(self.functions),"total_edges": sum(len(v) for v in self.forward_edges.values()),"entry_points": [n for n in self.functions if n not in self.backward_edges]}}
    
    @classmethod
    def from_json(cls, json_path: str):
        with open(json_path, 'r') as f: data = json.load(f)
        functions = {}
        for n, d in data['functions'].items():
            # Handle backward compatibility if 'decorators' is missing
            if 'decorators' not in d:
                d['decorators'] = []
            functions[n] = FunctionDefinition(**d)
        graph = cls(functions=functions)
        graph.forward_edges = defaultdict(list, data['edges']['forward'])
        graph.backward_edges = defaultdict(list, data['edges']['backward'])
        return graph

    def get_function_info(self, func_name: str) -> Optional[FunctionDefinition]:
        return self.functions.get(func_name)

    def print_trace(self, start_node: str, direction: str = 'forward', max_depth: int = 1):
        if start_node not in self.functions:
            print(f"Function '{start_node}' not found in graph.")
            return

        print(f"\nTrace {direction} for: {start_node}")
        info = self.functions[start_node]
        print(f"  Def: {info.file}:{info.line}:{info.column}")
        
        edges = self.forward_edges if direction == 'forward' else self.backward_edges
        
        def _print_recursive(current_node, current_depth, visited):
            if current_depth > max_depth: return
            if current_node in visited:
                print(f"{'  ' * (current_depth + 1)}-> {current_node} (recursion)")
                return
            
            children = edges.get(current_node, [])
            if not children: return

            for child in children:
                child_info = self.functions.get(child)
                loc = f" ({Path(child_info.file).name}:{child_info.line})" if child_info else " (external/unknown)"
                print(f"{'  ' * (current_depth + 1)}-> {child}{loc}")
                _print_recursive(child, current_depth + 1, visited | {current_node})

        _print_recursive(start_node, 0, set())

    def visualize(self, output_file="call_graph", format="png"):
        try:
            from graphviz import Digraph
        except ImportError:
            logger.error("Graphviz not installed. Please install it with `pip install graphviz`.")
            return

        dot = Digraph(comment='Call Graph', format=format)
        dot.attr(rankdir='LR')

        # Add nodes
        for name, func in self.functions.items():
            label = f"{func.name}\n({Path(func.file).name}:{func.line})"
            dot.node(name, label=label, shape='box', style='filled', fillcolor='lightblue')

        # Add edges
        for caller, callees in self.forward_edges.items():
            for callee in callees:
                if callee in self.functions:
                    dot.edge(caller, callee)

        try:
            dot.render(output_file, view=False)
            logger.info(f"Graph visualization saved to {output_file}.{format}")
        except Exception as e:
            logger.error(f"Failed to render graph: {e}")

    def find_all_callers(self, sink, max_depth=15):
        if sink not in self.functions: logger.error(f"Sink '{sink}' not found."); return []
        if sink not in self.backward_edges: logger.warning(f"'{sink}' is an entry point."); return [[sink]]
        paths, queue = [], [(sink, [sink])]
        while queue:
            curr, path = queue.pop(0)
            if curr not in self.backward_edges: paths.append(list(reversed(path))); continue
            if len(path) >= max_depth: paths.append(['...'] + list(reversed(path))); continue
            for caller in self.backward_edges[curr]:
                if caller in path: paths.append(['... (recursion)'] + list(reversed(path+[caller]))); continue
                queue.append((caller, path + [caller]))
        return paths

    def find_paths(self, source: str, sink: str, max_depth: int = 15) -> List[List[str]]:
        if source not in self.functions: logger.error(f"Source '{source}' not found."); return []
        if sink not in self.functions: logger.error(f"Sink '{sink}' not found."); return []
        
        paths = []
        queue = [(source, [source])]
        
        while queue:
            curr, path = queue.pop(0)
            if curr == sink:
                paths.append(path)
                continue
            
            if len(path) >= max_depth: continue
            
            for neighbor in self.forward_edges.get(curr, []):
                if neighbor in path: continue # Avoid cycles
                queue.append((neighbor, path + [neighbor]))
                
        return paths

    def trace_all_paths(self, start_nodes: List[str], max_depth: int = 15) -> Dict[str, List[List[str]]]:
        all_paths = {}
        for start_node in start_nodes:
            if start_node not in self.functions: continue
            
            paths = []
            queue = [(start_node, [start_node])]
            
            while queue:
                curr, path = queue.pop(0)
                
                # If leaf node or max depth reached, add path
                if curr not in self.forward_edges or not self.forward_edges[curr] or len(path) >= max_depth:
                    paths.append(path)
                    continue
                
                for neighbor in self.forward_edges[curr]:
                    if neighbor in path: # Cycle detected
                        paths.append(path + [neighbor + " (recursion)"])
                        continue
                    queue.append((neighbor, path + [neighbor]))
            
            all_paths[start_node] = paths
        return all_paths
class RepositoryAnalyzer:
    def __init__(self, r, l): self.repo_path, self.language = r, l; self.parser = UniversalCodeParser(l, r); self.linker = InterProceduralLinker()
    def analyze(self):
        logger.info(f"Analyzing {self.repo_path} ({self.language})")
        funcs, calls, imps = self._parse_all_files()
        self.linker.register_definitions(funcs, imps)
        edges = self.linker.resolve_calls(calls)
        graph = CallGraph(functions={f.full_name: f for f in funcs})
        for c, e in edges:
            if '<module_level>' in c or '<module_level>' in e: continue
            graph.add_edge(c, e)
        logger.info(f"Analysis complete: {len(graph.functions)} funcs, {len(edges)} edges.")
        return graph
    def _parse_all_files(self):
        all_funcs, all_calls, all_imports = [], [], {}
        ext = "py" if self.language == "python" else self.language
        files = list(Path(self.repo_path).rglob(f"*.{ext}"))
        logger.info(f"Found {len(files)} files to parse.")
        for i, f in enumerate(files, 1):
            if i % 100 == 0: logger.info(f"Parsing progress: {i}/{len(files)} files...")
            mod_name = self.parser._get_module_name(f); funcs, calls, imps = self.parser.parse_file(str(f))
            all_funcs.extend(funcs); all_calls.extend(calls)
            if imps: all_imports[mod_name] = imps
        logger.info(f"Finished parsing: {len(all_funcs)} funcs, {len(all_calls)} calls in {len(all_imports)} modules.")
        return all_funcs, all_calls, all_imports
def main():
    parser = argparse.ArgumentParser(description="Build Inter-Procedural Call Graph")
    parser.add_argument("--repo", help="Path to repository to analyze")
    parser.add_argument("--language", default="python", choices=["python"])
    parser.add_argument("--output", default="call_graph.json")
    parser.add_argument("--load", help="Load existing call graph JSON instead of parsing")
    parser.add_argument("--find-sink", help="Find all paths to a specific function (sink)")
    parser.add_argument("--find-path", nargs=2, metavar=('SOURCE', 'SINK'), help="Find all paths from source to sink")
    parser.add_argument("--trace-all", action="store_true", help="Trace all paths from entry points (e.g. Flask routes)")
    parser.add_argument("--visualize", action="store_true", help="Generate a visual graph using Graphviz")
    parser.add_argument("--trace-forward", help="Trace calls made by function")
    parser.add_argument("--trace-backward", help="Trace callers of function")
    parser.add_argument("--info", help="Show definition info for function")
    parser.add_argument("--depth", type=int, default=1, help="Depth for tracing")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug: logging.getLogger().setLevel(logging.DEBUG)

    if args.load:
        logger.info(f"Loading graph from {args.load}")
        graph = CallGraph.from_json(args.load)
    elif args.repo:
        analyzer = RepositoryAnalyzer(args.repo, args.language)
        graph = analyzer.analyze()
        with open(args.output, 'w') as f: json.dump(graph.to_json(), f, indent=2)
        logger.info(f"Full graph saved to {args.output}")
    else:
        parser.error("Either --repo or --load must be specified")

    if args.find_sink:
        logger.info(f"\n--- Finding call chains for SINK: {args.find_sink} ---")
        paths = graph.find_all_callers(args.find_sink)
        if paths:
            paths.sort(key=len); logger.info(f"Found {len(paths)} paths. Sample:")
            for i, path in enumerate(paths[:15], 1): print(f"  {i:2d}. {' → '.join(path)}")
        else: logger.info("No paths found.")

    if args.find_path:
        source, sink = args.find_path
        logger.info(f"\n--- Finding paths from {source} to {sink} ---")
        paths = graph.find_paths(source, sink)
        if paths:
            paths.sort(key=len)
            logger.info(f"Found {len(paths)} paths:")
            for i, path in enumerate(paths[:15], 1): print(f"  {i:2d}. {' → '.join(path)}")
        else: logger.info("No paths found.")

    if args.trace_all:
        # Universal entry point detection
        entry_points = []
        
        # 1. Framework-specific decorators
        framework_decorators = [
            'app.route', 'bp.route', 'router.get', 'router.post', 'router.put', 'router.delete', # Flask, FastAPI
            'api_view', 'action' # Django DRF
        ]
        
        # 2. Naming conventions
        entry_point_patterns = ['views', 'api', 'routes', 'controllers', 'endpoints']
        
        for name, func in graph.functions.items():
            is_entry = False
            
            # Check decorators
            for dec in func.decorators:
                if any(d in dec for d in framework_decorators):
                    is_entry = True
                    break
            
            # Check module path patterns if no decorators found
            if not is_entry:
                if any(p in name for p in entry_point_patterns):
                    is_entry = True
            
            if is_entry:
                entry_points.append(name)

        logger.info(f"\n--- Tracing all paths from {len(entry_points)} detected entry points ---")
        all_traces = graph.trace_all_paths(entry_points, max_depth=args.depth)
        
        for start_node, paths in all_traces.items():
            if not paths: continue
            print(f"\nEntry Point: {start_node}")
            for i, path in enumerate(paths[:5], 1): # Show top 5 paths per entry point
                print(f"  Path {i}: {' -> '.join(path)}")
            if len(paths) > 5:
                print(f"  ... and {len(paths) - 5} more paths")

    if args.trace_forward:
        graph.print_trace(args.trace_forward, 'forward', args.depth)
    
    if args.trace_backward:
        graph.print_trace(args.trace_backward, 'backward', args.depth)

    if args.info:
        info = graph.get_function_info(args.info)
        if info:
            print(f"\nFunction: {info.name}")
            print(f"Full Name: {info.full_name}")
            print(f"Location: {info.file}:{info.line}:{info.column}")
        else:
            print(f"Function '{args.info}' not found.")

    if args.visualize:
        graph.visualize(output_file=Path(args.output).stem)

if __name__ == "__main__":
    main()
