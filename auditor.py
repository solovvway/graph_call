#!/usr/bin/env python3
"""
ASCG (Advanced Security Call Graph Auditor) - WEB EntryPoints + PHP Sources + require/include sinks

What it does:
- Builds a call graph (best-effort) for multiple languages using tree-sitter.
- Entry points: ONLY web entry points (routes/handlers/controllers), not name heuristics.
- PHP sources: any function/method/<global>/closure that reads $_GET/$_POST/... or php://input.
- PHP require/include: extracted as edges + treated as sinks (require/require_once/include/include_once).

Install:
  pip install tree-sitter tree-sitter-languages graphviz
Also install system graphviz if you want --visualize (dot executable).
"""

import os, sys, logging, argparse, shutil, warnings, re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Iterable
from dataclasses import dataclass
from collections import defaultdict

warnings.simplefilter(action="ignore", category=FutureWarning)

try:
    from tree_sitter_languages import get_language, get_parser
except ImportError:
    print("CRITICAL: Missing libraries. Run: pip install tree-sitter tree-sitter-languages graphviz")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ============================================================================
# SINKS
# ============================================================================
KNOWN_SINKS: Dict[str, Set[str]] = {
    "python": {
        "exec", "eval", "compile", "open", "execfile", "input", "__import__",
        "os.system", "os.popen", "os.spawn",
        "subprocess.Popen", "subprocess.call", "subprocess.run",
        "pickle.loads", "yaml.load", "marshal.load", "shelve.open",
        "sqlite3.connect", "cursor.execute",
        "flask.render_template_string",
    },
    "javascript": {
        "eval", "Function", "setTimeout", "setInterval",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln",
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
    },
    "typescript": {
        "eval", "Function", "setTimeout", "setInterval",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln",
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
    },
    "tsx": {
        "eval", "Function", "setTimeout", "setInterval",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln",
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
    },
    "java": {
        "Runtime.exec", "ProcessBuilder.start",
        "Statement.execute", "Statement.executeQuery",
        "PreparedStatement.execute", "PreparedStatement.executeQuery",
    },
    "php": {
        "exec", "system", "passthru", "shell_exec", "eval", "popen", "proc_open", "mysqli_query",
        # requested sinks:
        "require", "require_once", "include", "include_once",
    },
    "go": {"os.StartProcess", "exec.Command", "sql.Query", "sql.Exec", "template.Execute"},
    "ruby": {"eval", "system", "exec", "syscall", "open", "send", "public_send"},
    "c_sharp": {"Process.Start", "Assembly.Load", "Type.GetType", "SqlCommand.ExecuteReader", "SqlCommand.ExecuteNonQuery"},
}

# ============================================================================
# PHP SOURCES (requested)
# ============================================================================
PHP_SOURCE_REGEX = re.compile(
    r"""(?ix)
    (?:\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV|SESSION)\b)
    |(?:php://input\b)
    |(?:\$HTTP_RAW_POST_DATA\b)
    """
)

# ============================================================================
# Tree-sitter language specs
# Captures:
#  - function defs: @def and @name
#  - calls: @call and @callee_expr (full expression)
# ============================================================================
LANG_SPECS: Dict[str, Dict] = {
    "python": {
        "class_node_types": {"class_definition"},
        "scope_node_types": {"function_definition", "lambda"},
        "func_queries": [
            "(function_definition name: (identifier) @name) @def",
        ],
        "call_queries": [
            "(call function: (identifier) @callee_expr) @call",
            "(call function: (attribute) @callee_expr) @call",
        ],
    },

    "javascript": {
        "class_node_types": {"class_declaration", "class"},
        "scope_node_types": {"function_declaration", "method_definition", "arrow_function", "function_expression"},
        "func_queries": [
            "(function_declaration name: (identifier) @name) @def",
            "(method_definition name: (property_identifier) @name) @def",
            "(variable_declarator name: (identifier) @name value: [(arrow_function) (function_expression)]) @def",
            "(export_statement declaration: (function_declaration name: (identifier) @name) @def)",
        ],
        "call_queries": [
            "(call_expression function: (identifier) @callee_expr) @call",
            "(call_expression function: (member_expression) @callee_expr) @call",
            "(call_expression function: (optional_chain) @callee_expr) @call",
        ],
    },

    "typescript": {},  # inherited from javascript
    "tsx": {},         # inherited from javascript

    "java": {
        "class_node_types": {"class_declaration"},
        "scope_node_types": {"method_declaration", "constructor_declaration"},
        "func_queries": [
            "(method_declaration name: (identifier) @name) @def",
            "(constructor_declaration name: (identifier) @name) @def",
        ],
        "call_queries": [
            "(method_invocation name: (identifier) @callee_expr) @call",
            "(method_invocation object: (_) name: (identifier) @callee_expr) @call",
        ],
    },

    "go": {
        "class_node_types": set(),
        "scope_node_types": {"function_declaration", "method_declaration", "func_literal"},
        "func_queries": [
            "(function_declaration name: (identifier) @name) @def",
            "(method_declaration name: (field_identifier) @name) @def",
        ],
        "call_queries": [
            "(call_expression function: (identifier) @callee_expr) @call",
            "(call_expression function: (selector_expression) @callee_expr) @call",
        ],
    },

    "php": {
        "class_node_types": {"class_declaration"},
        "scope_node_types": {"function_definition", "method_declaration"},
        "func_queries": [
            "(function_definition name: (name) @name) @def",
            "(method_declaration name: (name) @name) @def",
        ],
        "call_queries": [
            "(function_call_expression function: (_) @callee_expr) @call",
            "(member_call_expression name: (name) @callee_expr) @call",
            "(scoped_call_expression name: (name) @callee_expr) @call",
        ],
    },

    "ruby": {
        "class_node_types": {"class", "module"},
        "scope_node_types": {"method", "singleton_method"},
        "func_queries": [
            "(method name: (identifier) @name) @def",
            "(singleton_method name: (identifier) @name) @def",
        ],
        "call_queries": [
            "(call method: (identifier) @callee_expr) @call",
            "(call method: (constant) @callee_expr) @call",
        ],
    },

    "c_sharp": {
        "class_node_types": {"class_declaration", "struct_declaration"},
        "scope_node_types": {"method_declaration", "constructor_declaration", "local_function_statement"},
        "func_queries": [
            "(method_declaration name: (identifier) @name) @def",
            "(constructor_declaration name: (identifier) @name) @def",
            "(local_function_statement name: (identifier) @name) @def",
        ],
        "call_queries": [
            "(invocation_expression expression: (identifier) @callee_expr) @call",
            "(invocation_expression expression: (member_access_expression) @callee_expr) @call",
        ],
    },
}

LANG_SPECS["typescript"] = {**LANG_SPECS["javascript"]}
LANG_SPECS["tsx"] = {**LANG_SPECS["javascript"]}

EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "c_sharp",
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
    is_entry: bool = False       # WEB entrypoint only
    is_source: bool = False      # SOURCE (currently: PHP superglobals/php://input)
    is_builtin: bool = False

@dataclass
class Edge:
    src: str
    dst: str
    file: str
    line: int

# ============================================================================
# Utilities
# ============================================================================
_ws_re = re.compile(r"\s+")

def normalize_callee(text: str) -> str:
    """Normalize callee expression: remove whitespace, optional chaining, scope :: -> ."""
    if not text:
        return ""
    t = _ws_re.sub("", text)
    t = t.replace("?.", ".")
    t = t.replace("::", ".")
    return t.strip()

def walk(node) -> Iterable:
    """Generic tree-sitter AST DFS."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        try:
            ch = n.children
            if ch:
                stack.extend(reversed(ch))
        except Exception:
            pass

def safe_text(content: bytes, node) -> str:
    try:
        return content[node.start_byte:node.end_byte].decode("utf-8", "ignore")
    except Exception:
        return ""

# ============================================================================
# PARSER ENGINE
# ============================================================================
class CodeParser:
    def __init__(self, lang: str, repo_root: Path):
        self.lang = lang
        self.repo_root = repo_root
        self.spec = LANG_SPECS.get(lang, LANG_SPECS["python"])

        try:
            self.parser = get_parser(lang)
            self.lib = get_language(lang)
        except Exception as e:
            logger.warning(f"Tree-sitter parser not available for '{lang}': {e}")
            self.parser = None
            self.lib = None

    def parse_file(self, path: Path, content: bytes) -> Tuple[List[Node], List[Edge]]:
        if not self.parser or not self.lib:
            return [], []

        try:
            tree = self.parser.parse(content)
        except Exception as e:
            logger.warning(f"Parse error {path}: {e}")
            return [], []

        module_id = self._module_id(path)

        # Always create <global> node (important for PHP/JS where routing is in global scope)
        nodes: List[Node] = []
        global_uid = f"{module_id}.<global>"
        global_is_entry = self._is_web_global_entry_file(path)
        global_is_source = self._is_php_source_text(content.decode("utf-8", "ignore")) if self.lang == "php" else False
        nodes.append(Node(uid=global_uid, name="<global>", file=str(path), line=1,
                          is_entry=global_is_entry, is_source=global_is_source))

        # Regular functions/methods
        nodes.extend(self._extract_functions(tree, path, content, module_id))

        # Calls (edges)
        edges = self._extract_calls(tree, path, content, module_id)

        # Mark WEB entrypoints by route registrations / controller annotations
        entry_uids = self._extract_web_entrypoints(tree, path, content, module_id, nodes)
        if entry_uids:
            by_uid = {n.uid: n for n in nodes}
            for uid in entry_uids:
                if uid in by_uid:
                    by_uid[uid].is_entry = True

        return nodes, edges

    def _module_id(self, path: Path) -> str:
        try:
            rel = path.resolve().relative_to(self.repo_root)
        except Exception:
            rel = path.name
        no_ext = str(rel).rsplit(".", 1)[0]
        return no_ext.replace("\\", ".").replace("/", ".")

    def _run_queries(self, queries: List[str], root_node):
        caps = []
        for q in queries:
            try:
                query = self.lib.query(q)
                caps.extend(query.captures(root_node) or [])
            except Exception:
                continue
        return caps

    def _get_enclosing_classes(self, node, content: bytes) -> List[str]:
        class_types = self.spec.get("class_node_types", set())
        out = []
        curr = node.parent
        while curr:
            if curr.type in class_types:
                name_node = curr.child_by_field_name("name")
                if name_node:
                    out.append(safe_text(content, name_node))
            curr = curr.parent
        return list(reversed(out))

    def _def_uid(self, module_id: str, name: str, class_stack: List[str]) -> str:
        if class_stack:
            return f"{module_id}." + ".".join(class_stack) + f".{name}"
        return f"{module_id}.{name}"

    # -----------------------------
    # Web-entry helpers
    # -----------------------------
    def _is_web_global_entry_file(self, path: Path) -> bool:
        """
        Mark <global> as WEB entry for known web bootstrap files.
        Especially important for PHP where index.php is the front controller.
        """
        name = path.name.lower()
        p = str(path).replace("\\", "/").lower()

        if self.lang == "php":
            # common web entrypoints
            if name == "index.php":
                return True
            # Laravel route files are also web entry in practice (closures / controller mapping)
            if "/routes/web.php" in p or "/routes/api.php" in p:
                return True
            # Symfony public/index.php
            if "/public/index.php" in p:
                return True

        if self.lang in {"javascript", "typescript", "tsx"}:
            # Node apps often declare routes in app/server/index files; keep conservative:
            if name in {"app.js", "server.js", "index.js", "main.js", "app.ts", "server.ts", "index.ts", "main.ts"}:
                return True

        if self.lang == "python":
            # python web apps often define routes in app.py/main.py
            if name in {"app.py", "main.py", "wsgi.py", "asgi.py"}:
                return True

        return False

    # -----------------------------
    # PHP SOURCES detection
    # -----------------------------
    def _is_php_source_text(self, text: str) -> bool:
        return bool(PHP_SOURCE_REGEX.search(text or ""))

    # -----------------------------
    # Function extraction
    # -----------------------------
    def _extract_functions(self, tree, path: Path, content: bytes, module_id: str) -> List[Node]:
        nodes: List[Node] = []
        caps = self._run_queries(self.spec.get("func_queries", []), tree.root_node)

        for cap_node, tag in caps:
            if tag != "name":
                continue

            name = safe_text(content, cap_node)

            # find definition-like parent (for annotation + source scanning)
            def_node = cap_node
            curr = cap_node.parent
            while curr:
                if curr.type.endswith("definition") or curr.type.endswith("declaration") or "method" in curr.type:
                    def_node = curr
                    break
                curr = curr.parent

            class_stack = self._get_enclosing_classes(def_node, content)
            uid = self._def_uid(module_id, name, class_stack)

            # WEB entry: only annotations/decorators on definition (where applicable)
            is_entry = self._is_web_entry_by_definition_annotation(def_node, content)

            # SOURCES: PHP only (as requested)
            is_source = False
            if self.lang == "php":
                def_text = safe_text(content, def_node)
                is_source = self._is_php_source_text(def_text)

            nodes.append(Node(uid=uid, name=name, file=str(path), line=cap_node.start_point[0] + 1,
                              is_entry=is_entry, is_source=is_source))
        return nodes

    def _is_web_entry_by_definition_annotation(self, def_node, content: bytes) -> bool:
        """
        WEB-only entrypoints by annotations/attributes/decorators on the definition itself.
        - Python: @app.get/post/... @router.* @bp.route
        - Java: @GetMapping/@PostMapping/...
        - C#: [HttpGet]/[Route]/...
        - PHP: #[Route]/@Route (Symfony)
        """
        txt = safe_text(content, def_node)
        low = txt.lower()

        if self.lang == "python":
            if "@" not in txt:
                return False
            keys = [
                ".route", " route",  # flask blueprint / route etc
                ".get", ".post", ".put", ".delete", ".patch", ".options", ".head",
                "websocket",
            ]
            return any(k in low for k in keys)

        if self.lang == "java":
            return any(a in low for a in ["@requestmapping", "@getmapping", "@postmapping", "@putmapping", "@deletemapping", "@patchmapping"])

        if self.lang == "c_sharp":
            return any(a in low for a in ["[httpget", "[httppost", "[httpput", "[httpdelete", "[httppatch", "[route", "[acceptverbs"])

        if self.lang == "php":
            return ("#[route" in low) or ("@route" in low)

        return False

    # -----------------------------
    # Call extraction (graph edges)
    # -----------------------------
    def _extract_calls(self, tree, path: Path, content: bytes, module_id: str) -> List[Edge]:
        edges: List[Edge] = []
        caps = self._run_queries(self.spec.get("call_queries", []), tree.root_node)

        # pair @call with @callee_expr
        pairs = []
        pending_call = None
        for n, tag in caps:
            if tag == "call":
                pending_call = n
            elif tag == "callee_expr":
                if pending_call is not None:
                    pairs.append((pending_call, n))
                    pending_call = None
                else:
                    pairs.append((n.parent if n.parent else n, n))

        scope_types = self.spec.get("scope_node_types", set())

        def get_def_name(scope_node) -> Optional[str]:
            name_node = scope_node.child_by_field_name("name")
            if name_node:
                return safe_text(content, name_node)
            for child in getattr(scope_node, "children", []):
                if child.type in {"identifier", "property_identifier", "name", "field_identifier"}:
                    return safe_text(content, child)
            return None

        def find_scope_uid(node) -> str:
            curr = node
            while curr:
                if curr.type in scope_types or curr.type.endswith("definition") or curr.type.endswith("declaration"):
                    nm = get_def_name(curr)
                    if nm:
                        class_stack = self._get_enclosing_classes(curr, content)
                        return self._def_uid(module_id, nm, class_stack)
                curr = curr.parent
            return f"{module_id}.<global>"

        # normal call edges
        for call_node, callee_expr_node in pairs:
            callee = normalize_callee(safe_text(content, callee_expr_node))
            if not callee:
                continue
            caller_uid = find_scope_uid(call_node)
            edges.append(Edge(src=caller_uid, dst=callee, file=str(path), line=call_node.start_point[0] + 1))

        # EXTRA: PHP require/include are often not represented as function calls
        if self.lang == "php":
            type_map = {
                "require_expression": "require",
                "require_once_expression": "require_once",
                "include_expression": "include",
                "include_once_expression": "include_once",
            }

            for n in walk(tree.root_node):
                # best-effort: exact known node types OR contains require/include keywords
                if n.type in type_map:
                    callee = type_map[n.type]
                elif "require" in n.type:
                    callee = "require_once" if "once" in n.type else "require"
                elif "include" in n.type:
                    callee = "include_once" if "once" in n.type else "include"
                else:
                    continue

                caller_uid = find_scope_uid(n)
                edges.append(Edge(src=caller_uid, dst=callee, file=str(path), line=n.start_point[0] + 1))

        return edges

    # -----------------------------
    # WEB entrypoint extraction from route registrations (Node/PHP/Python etc.)
    # -----------------------------
    def _extract_web_entrypoints(self, tree, path: Path, content: bytes, module_id: str, nodes: List[Node]) -> Set[str]:
        """
        Extract entrypoints by analyzing route registrations / handler bindings.
        Returns uids to mark as entry.
        May append anonymous handler nodes for inline closures (JS/PHP).
        """
        by_name_local: Dict[str, List[str]] = defaultdict(list)
        for n in nodes:
            by_name_local[n.name].append(n.uid)

        entry_uids: Set[str] = set()

        if self.lang == "python":
            entry_uids |= self._web_entries_python(tree, content, module_id, by_name_local)

        elif self.lang in {"javascript", "typescript", "tsx"}:
            entry_uids |= self._web_entries_js(tree, path, content, module_id, by_name_local, nodes)

        elif self.lang == "php":
            entry_uids |= self._web_entries_php(tree, path, content, module_id, by_name_local, nodes)

        elif self.lang == "go":
            entry_uids |= self._web_entries_go(tree, content, module_id, by_name_local)

        elif self.lang == "ruby":
            entry_uids |= self._web_entries_ruby(tree, path, module_id, nodes)

        return entry_uids

    # Python: app.add_url_rule(..., handler) (decorators already handled)
    def _web_entries_python(self, tree, content: bytes, module_id: str,
                           by_name_local: Dict[str, List[str]]) -> Set[str]:
        out: Set[str] = set()
        for n in walk(tree.root_node):
            if n.type != "call":
                continue
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            if not fn or not args:
                continue

            callee = normalize_callee(safe_text(content, fn))
            if not callee:
                continue

            if callee.endswith("add_url_rule"):
                for arg in walk(args):
                    if arg.type == "identifier":
                        name = safe_text(content, arg)
                        for uid in by_name_local.get(name, []):
                            out.add(uid)
        return out

    # JS/TS: app.get('/x', handler), router.post(...), app.use(...)
    def _web_entries_js(self, tree, path: Path, content: bytes, module_id: str,
                       by_name_local: Dict[str, List[str]], nodes: List[Node]) -> Set[str]:
        out: Set[str] = set()
        route_methods = {"get", "post", "put", "delete", "patch", "options", "head", "all", "use"}

        def mk_anon_uid(line0: int) -> str:
            return f"{module_id}.<anon@{line0+1}>"

        for n in walk(tree.root_node):
            if n.type != "call_expression":
                continue
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            if not fn or not args:
                continue

            callee = normalize_callee(safe_text(content, fn))
            last = callee.split(".")[-1] if callee else ""
            if last not in route_methods:
                continue

            arg_children = [c for c in args.children if getattr(c, "is_named", False)]
            if not arg_children:
                continue
            handler = arg_children[-1]

            if handler.type == "identifier":
                name = safe_text(content, handler)
                for uid in by_name_local.get(name, []):
                    out.add(uid)

            elif handler.type in {"arrow_function", "function_expression"}:
                uid = mk_anon_uid(handler.start_point[0])
                nodes.append(Node(uid=uid, name=f"<anon@{handler.start_point[0]+1}>",
                                  file=str(path), line=handler.start_point[0] + 1,
                                  is_entry=True))
                out.add(uid)

        return out

    # PHP: Laravel Route::get(..., handler). Symfony #[Route]/@Route handled on defs + <global> entry file.
    def _web_entries_php(self, tree, path: Path, content: bytes, module_id: str,
                         by_name_local: Dict[str, List[str]], nodes: List[Node]) -> Set[str]:
        out: Set[str] = set()
        route_methods = {"get", "post", "put", "delete", "patch", "options", "any", "match", "resource", "apiresource", "group"}

        def add_anon(line0: int, closure_text: str) -> str:
            uid = f"{module_id}.<anon@{line0+1}>"
            is_source = self._is_php_source_text(closure_text)
            nodes.append(Node(uid=uid, name=f"<anon@{line0+1}>", file=str(path), line=line0 + 1,
                              is_entry=True, is_source=is_source))
            return uid

        for n in walk(tree.root_node):
            if n.type not in {"function_call_expression", "scoped_call_expression", "member_call_expression"}:
                continue

            # normalize full call text and check "Route.<method>("
            call_txt = normalize_callee(safe_text(content, n))
            m = re.search(r"\bRoute\.(\w+)\s*\(", call_txt)
            if not m:
                continue
            method = m.group(1).lower()
            if method not in route_methods:
                continue

            # locate argument list
            args = None
            for ch in getattr(n, "children", []):
                if ch.type in {"arguments", "argument_list"}:
                    args = ch
                    break
            if not args:
                continue

            named_args = [c for c in args.children if getattr(c, "is_named", False)]
            if len(named_args) < 2:
                continue
            handler = named_args[1]  # often second argument
            htxt = safe_text(content, handler).strip()

            # closure => anonymous entry; also mark SOURCE if it uses $_GET/$_POST/php://input
            if "function" in htxt or "fn(" in htxt:
                out.add(add_anon(handler.start_point[0], htxt))
                continue

            # array callback [Controller::class, 'method'] or ["Controller", "method"]
            if htxt.startswith("[") and htxt.endswith("]"):
                m2 = re.findall(r"['\"]([A-Za-z0-9_]+)['\"]", htxt)
                if m2:
                    meth = m2[-1]
                    for uid in by_name_local.get(meth, []):
                        out.add(uid)
                continue

            # string 'Controller@method'
            if ("@" in htxt) and (htxt.startswith(("'", '"'))):
                s = htxt.strip("'\"")
                parts = s.split("@", 1)
                if len(parts) == 2:
                    meth = parts[1]
                    for uid in by_name_local.get(meth, []):
                        out.add(uid)
                continue

        return out

    # Go: http.HandleFunc("/x", handler)
    def _web_entries_go(self, tree, content: bytes, module_id: str,
                       by_name_local: Dict[str, List[str]]) -> Set[str]:
        out: Set[str] = set()
        for n in walk(tree.root_node):
            if n.type != "call_expression":
                continue
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            if not fn or not args:
                continue
            callee = normalize_callee(safe_text(content, fn))
            if not (callee.endswith("HandleFunc") or callee.endswith(".HandleFunc") or callee.endswith("Handle")):
                continue
            arg_children = [c for c in args.children if getattr(c, "is_named", False)]
            if len(arg_children) < 2:
                continue
            handler = arg_children[1]
            if handler.type == "identifier":
                name = safe_text(content, handler)
                for uid in by_name_local.get(name, []):
                    out.add(uid)
        return out

    # Ruby best-effort (Sinatra-style): get '/x' do ... end => anon entry
    def _web_entries_ruby(self, tree, path: Path, module_id: str, nodes: List[Node]) -> Set[str]:
        out: Set[str] = set()
        route_methods = {"get", "post", "put", "delete", "patch"}
        for n in walk(tree.root_node):
            if n.type != "call":
                continue
            meth = n.child_by_field_name("method")
            if not meth:
                continue
            name = normalize_callee(safe_text(path.read_bytes() if path.exists() else b"", meth))
            if name not in route_methods:
                continue
            uid = f"{module_id}.<anon@{n.start_point[0]+1}>"
            nodes.append(Node(uid=uid, name=f"<anon@{n.start_point[0]+1}>", file=str(path), line=n.start_point[0]+1, is_entry=True))
            out.add(uid)
        return out

# ============================================================================
# GRAPH
# ============================================================================
class SecurityGraph:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.adj: Dict[str, Set[str]] = defaultdict(set)
        self.rev_adj: Dict[str, Set[str]] = defaultdict(set)
        self.sinks_found: Set[str] = set()

    def add_node(self, n: Node):
        if n.uid in self.nodes:
            old = self.nodes[n.uid]
            old.is_entry = old.is_entry or n.is_entry
            old.is_sink = old.is_sink or n.is_sink
            old.is_source = old.is_source or n.is_source
            return
        self.nodes[n.uid] = n
        if n.is_sink:
            self.sinks_found.add(n.uid)

    def add_edge(self, caller_uid: str, callee_name: str, lang: str):
        if caller_uid not in self.nodes:
            self.nodes[caller_uid] = Node(caller_uid, caller_uid.split(".")[-1], "unknown", 0)

        sinks = KNOWN_SINKS.get(lang, set())
        callee_norm = normalize_callee(callee_name)

        is_sink = (callee_norm in sinks) or any(callee_norm.endswith("." + s) for s in sinks)

        if is_sink:
            target_uid = f"builtin.{lang}.{callee_norm}"
            if target_uid not in self.nodes:
                self.nodes[target_uid] = Node(
                    uid=target_uid, name=callee_norm, file="<builtin>", line=0,
                    is_sink=True, is_builtin=True
                )
            self.sinks_found.add(target_uid)
        else:
            target_uid = None

            # attempt resolve local if simple identifier
            if "." not in callee_norm:
                caller_mod = caller_uid.rsplit(".", 1)[0]
                candidate_local = f"{caller_mod}.{callee_norm}"
                if candidate_local in self.nodes:
                    target_uid = candidate_local

            # fallback: match by last segment name
            if not target_uid:
                callee_last = callee_norm.split(".")[-1]
                matches = [uid for uid, n in self.nodes.items() if n.name == callee_last]
                if matches:
                    target_uid = matches[0]

            if not target_uid:
                target_uid = f"ext.{lang}.{callee_norm}"
                if target_uid not in self.nodes:
                    self.nodes[target_uid] = Node(target_uid, callee_norm, "<external>", 0, is_builtin=True)

        self.adj[caller_uid].add(target_uid)
        self.rev_adj[target_uid].add(caller_uid)

    def _format_loc(self, n: Node) -> str:
        if n.is_builtin:
            return "<builtin>"
        if n.file == "unknown":
            return "<unknown source>"
        if n.file == "<external>":
            return "<external lib>"
        try:
            return f"{Path(n.file).relative_to(Path.cwd())}:{n.line}"
        except Exception:
            return f"{n.file}:{n.line}"

    def _label(self, uid: str) -> str:
        n = self.nodes[uid]
        tags = []
        if n.is_entry: tags.append("WEB_ENTRY")
        if n.is_source: tags.append("SOURCE")
        if n.is_sink: tags.append("SINK")
        return f"{n.name}" + (f" [{'|'.join(tags)}]" if tags else "")

    def _print_formatted_path(self, path: List[str]):
        names = [self._label(uid) for uid in path]
        print(f"\n[PATH] {' -> '.join(names)}")
        for uid in path:
            n = self.nodes[uid]
            print(f"   {self._label(uid)} ({self._format_loc(n)})")

    def trace_all(self):
        print(f"\n{'='*30} VULNERABILITY REPORT {'='*30}")
        entries = [uid for uid, n in self.nodes.items() if n.is_entry]
        sources = [uid for uid, n in self.nodes.items() if n.is_source]
        print(f"Total Nodes: {len(self.nodes)} | WEB Entry Points: {len(entries)} | Sources: {len(sources)} | Sinks Found: {len(self.sinks_found)}")

        if not self.sinks_found:
            print("No dangerous sinks detected.")
            return
        if not entries:
            print("[WARN] No WEB entrypoints detected. (You may need framework-specific route patterns.)")

        paths_found = 0
        max_depth = 16

        def dfs(curr, path, visited_local):
            nonlocal paths_found
            if self.nodes[curr].is_sink:
                paths_found += 1
                self._print_formatted_path(path)
                return
            if len(path) > max_depth:
                return
            for neighbor in self.adj.get(curr, []):
                if neighbor not in visited_local:
                    dfs(neighbor, path + [neighbor], visited_local | {neighbor})

        # Trace from WEB entrypoints only (as requested)
        for entry in entries:
            dfs(entry, [entry], {entry})

        if paths_found == 0:
            print("\n[INFO] No direct paths from WEB Entry Points found.")
            print("Showing immediate callers of Sinks (Backward Trace):")
            for sink in sorted(self.sinks_found):
                callers = list(self.rev_adj.get(sink, []))
                for c in callers[:10]:
                    self._print_formatted_path([c, sink])

    def visualize(self, filename="vuln_graph"):
        if not shutil.which("dot"):
            logger.warning("Graphviz 'dot' not found. Visualization skipped. (Install graphviz)")
            return
        try:
            from graphviz import Digraph
            dot = Digraph(comment="Security Graph", format="png")
            dot.attr(rankdir="LR", overlap="false")

            for uid, n in self.nodes.items():
                if n.is_sink:
                    dot.node(uid, label=f"{n.name}\n(SINK)", style="filled", fillcolor="#ffcccc", color="red")
                elif n.is_entry:
                    dot.node(uid, label=f"{n.name}\n(WEB ENTRY)", style="filled", fillcolor="#ccffcc")
                elif n.is_source:
                    dot.node(uid, label=f"{n.name}\n(SOURCE)", style="filled", fillcolor="#fff2b2")
                elif not n.is_builtin:
                    dot.node(uid, label=f"{n.name}\n{Path(n.file).name}")

            for src, dests in self.adj.items():
                for dst in dests:
                    color = "red" if dst in self.sinks_found else "#666666"
                    dot.edge(src, dst, color=color)

            dot.render(filename, view=False)
            logger.info(f"Graph saved to {filename}.png")
        except Exception as e:
            logger.error(f"Visualization error: {e}")

# ============================================================================
# MAIN
# ============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="Path to repository")
    ap.add_argument("--visualize", action="store_true", help="Generate PNG")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    if not repo.exists():
        print(f"Repo not found: {repo}")
        sys.exit(2)

    graph = SecurityGraph()
    files_map: Dict[str, List[Path]] = defaultdict(list)

    for root, _, files in os.walk(repo):
        for f in files:
            ext = Path(f).suffix.lower()
            if ext in EXT_TO_LANG:
                files_map[EXT_TO_LANG[ext]].append(Path(root) / f)

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
        graph.add_edge(e.src, e.dst, lang)

    graph.trace_all()
    if args.visualize:
        graph.visualize()

if __name__ == "__main__":
    main()
