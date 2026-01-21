#!/usr/bin/env python3
"""AST core module: Tree-sitter language specs, models, utilities, and parser engine."""
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Iterable, DefaultDict
from dataclasses import dataclass
from collections import defaultdict

from tree_sitter_languages import get_language, get_parser
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# MODELS
# ============================================================================
@dataclass
class Node:
    uid: str
    name: str
    file: str
    line: int
    end_line: int = 0
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
    if not text:
        return ""
    t = _ws_re.sub("", text)
    t = t.replace("?.", ".")
    t = t.replace("::", ".")
    return t.strip()

def walk(node) -> Iterable:
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
# Tree-sitter language specs
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

        # Always create <global> node (crucial for PHP/Node)
        nodes: List[Node] = []
        global_uid = f"{module_id}.<global>"
        global_is_entry = self._is_web_global_entry_file(path)
        global_is_source = self._is_php_source_text(content.decode("utf-8", "ignore")) if self.lang == "php" else False
        file_end_line = content.count(b"\n") + 1

        nodes.append(Node(
            uid=global_uid,
            name="<global>",
            file=str(path),
            line=1,
            end_line=file_end_line,
            is_entry=global_is_entry,
            is_source=global_is_source
        ))

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
        name = path.name.lower()
        p = str(path).replace("\\", "/").lower()

        if self.lang == "python":
            if name in {"app.py", "main.py", "server.py", "urls.py", "wsgi.py", "asgi.py", "routes.py"}:
                return True
            return False

        if self.lang in {"javascript", "typescript", "javascriptreact", "typescriptreact", "tsx"}:
            if name in {"app.js", "server.js", "index.js", "main.js", "app.ts", "server.ts", "index.ts", "main.ts"}:
                return True
            if name in {"routes.js", "router.js", "routes.ts", "router.ts"}:
                return True
            if name in {"page.tsx", "page.js", "_app.js", "_app.tsx", "layout.tsx"}:
                return True
            return False

        if self.lang == "php":
            if name == "index.php":
                return True
            if "/routes/" in p and name in {"web.php", "api.php", "routes.php"}:
                return True
            return False

        if self.lang == "c_sharp":
            if name in {"program.cs", "startup.cs"}:
                return True
            return False

        if self.lang == "java":
            if name in {"application.java", "main.java", "webconfig.java"}:
                return True
            return False

        if self.lang == "go":
            if name in {"main.go", "router.go", "routes.go", "server.go"}:
                return True
            return False

        if self.lang == "ruby":
            if name in {"config.ru", "routes.rb", "application.rb"}:
                return True
            return False

        return False

    # -----------------------------
    # PHP SOURCES detection
    # -----------------------------
    def _is_php_source_text(self, text: str) -> bool:
        # Import here to avoid circular imports
        from .sources import is_php_source
        return is_php_source(text)

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

            # SOURCES: PHP only
            is_source = False
            if self.lang == "php":
                def_text = safe_text(content, def_node)
                is_source = self._is_php_source_text(def_text)

            start_line = def_node.start_point[0] + 1
            end_line = def_node.end_point[0] + 1

            nodes.append(Node(
                uid=uid, name=name, file=str(path),
                line=start_line, end_line=end_line,
                is_entry=is_entry, is_source=is_source
            ))

        return nodes

    def _is_web_entry_by_definition_annotation(self, def_node, content: bytes) -> bool:
        txt = safe_text(content, def_node)
        low = txt.lower()

        if self.lang == "python":
            if "@" in txt:
                keys = [
                    ".route", " route",
                    ".get", ".post", ".put", ".delete", ".patch", ".options", ".head",
                    "websocket"
                ]
                if any(k in low for k in keys):
                    return True
            if "path(" in low or "re_path(" in low:
                return True
            return False

        if self.lang in ("javascript", "typescript", "javascriptreact", "typescriptreact", "tsx"):
            call_patterns = [
                "app.get(", "app.post(", "app.put(", "app.delete(", "app.patch(",
                "router.get(", "router.post(", "router.put(", "router.delete(", "router.patch(",
                "route("
            ]
            if any(p in low for p in call_patterns):
                return True

            if "@" in txt:
                nest_keys = ["@get", "@post", "@put", "@delete", "@patch", "@options", "@head", "@requestmapping"]
                if any(k in low for k in nest_keys):
                    return True
            return False

        if self.lang == "java":
            spring_annotations = [
                "@requestmapping", "@getmapping", "@postmapping",
                "@putmapping", "@deletemapping", "@patchmapping"
            ]
            return any(a in low for a in spring_annotations)

        if self.lang == "c_sharp":
            attributes = [
                "[httpget", "[httppost", "[httpput", "[httpdelete", "[httppatch",
                "[route", "[acceptverbs"
            ]
            if any(a in low for a in attributes):
                return True

            map_patterns = [".mapget", ".mappost", ".mapput", ".mapdelete", ".mappatch", ".mapgroup"]
            if any(m in low for m in map_patterns):
                return True

            return False

        if self.lang == "php":
            return ("#[route" in low) or ("@route" in low) or ("Route" in low)

        if self.lang == "go":
            go_patterns = [".get(", ".post(", ".put(", ".delete(", ".patch(", ".group(", ".handlefunc("]
            return any(p in low for p in go_patterns)

        if self.lang == "ruby":
            ruby_patterns = [
                "get '", 'get "',
                "post '", 'post "',
                "put '", 'put "',
                "delete '", 'delete "',
                "patch '", 'patch "',
                "resources :"
            ]
            return any(p in low for p in ruby_patterns)

        return False

    # -----------------------------
    # Call extraction (graph edges)
    # -----------------------------
    def _extract_calls(self, tree, path: Path, content: bytes, module_id: str) -> List[Edge]:
        edges: List[Edge] = []
        caps = self._run_queries(self.spec.get("call_queries", []), tree.root_node)

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

        # normal call edges
        for call_node, callee_expr_node in pairs:
            callee = normalize_callee(safe_text(content, callee_expr_node))
            if not callee:
                continue
            caller_uid = find_scope_uid(call_node)
            edges.append(Edge(src=caller_uid, dst=callee, file=str(path), line=call_node.start_point[0] + 1))

        # EXTRA: PHP require/include (AST scan + regex fallback)
        if self.lang == "php":
            edges.extend(self._extract_php_require_edges(tree, path, content, module_id, find_scope_uid))

        return edges

    def _extract_php_require_edges(self, tree, path: Path, content: bytes, module_id: str, find_scope_uid) -> List[Edge]:
        # Import here to avoid circular imports
        from .sources import PHP_REQUIRE_REGEX, PHP_BLOCK_COMMENT_RE, PHP_LINE_COMMENT_RE
        
        out: List[Edge] = []

        # 1) AST-based (works on some tree-sitter-php versions)
        type_map = {
            "require_expression": "require",
            "require_once_expression": "require_once",
            "include_expression": "include",
            "include_once_expression": "include_once",
            "require_statement": "require",
            "require_once_statement": "require_once",
            "include_statement": "include",
            "include_once_statement": "include_once",
        }

        for n in walk(tree.root_node):
            callee = None
            if n.type in type_map:
                callee = type_map[n.type]
            else:
                t = n.type.lower()
                if "require" in t:
                    callee = "require_once" if "once" in t else "require"
                elif "include" in t:
                    callee = "include_once" if "once" in t else "include"

            if not callee:
                continue

            caller_uid = find_scope_uid(n)
            out.append(Edge(src=caller_uid, dst=callee, file=str(path), line=n.start_point[0] + 1))

        # 2) Regex fallback with comment stripping
        text = content.decode("utf-8", "ignore")
        text_wo_comments = PHP_BLOCK_COMMENT_RE.sub("", text)
        text_wo_comments = PHP_LINE_COMMENT_RE.sub("", text_wo_comments)

        for m in PHP_REQUIRE_REGEX.finditer(text_wo_comments):
            kw = m.group(1).lower()
            line = text_wo_comments.count("\n", 0, m.start()) + 1
            caller_uid = f"{module_id}.<global>"  # fallback
            out.append(Edge(src=caller_uid, dst=kw, file=str(path), line=line))

        return out

    # -----------------------------
    # WEB entrypoint extraction from route registrations
    # -----------------------------
    def _extract_web_entrypoints(self, tree, path: Path, content: bytes, module_id: str, nodes: List[Node]) -> Set[str]:
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

        return entry_uids

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
                nodes.append(Node(
                    uid=uid,
                    name=f"<anon@{handler.start_point[0]+1}>",
                    file=str(path),
                    line=handler.start_point[0] + 1,
                    end_line=handler.end_point[0] + 1,
                    is_entry=True
                ))
                out.add(uid)

        return out

    def _web_entries_php(self, tree, path: Path, content: bytes, module_id: str,
                         by_name_local: Dict[str, List[str]], nodes: List[Node]) -> Set[str]:
        out: Set[str] = set()
        route_methods = {
            "get", "post", "put", "delete", "patch", "options",
            "any", "match", "resource", "apiresource", "group"
        }

        def add_anon(line0: int, closure_text: str) -> str:
            uid = f"{module_id}.<anon@{line0+1}>"
            is_source = self._is_php_source_text(closure_text)
            nodes.append(Node(
                uid=uid,
                name=f"<anon@{line0+1}>",
                file=str(path),
                line=line0 + 1,
                end_line=line0 + max(0, closure_text.count("\n")) + 1,
                is_entry=True,
                is_source=is_source
            ))
            return uid

        for n in walk(tree.root_node):
            if n.type not in {"function_call_expression", "scoped_call_expression", "member_call_expression"}:
                continue

            call_txt = normalize_callee(safe_text(content, n))
            m = re.search(r"\bRoute\.(\w+)\s*\(", call_txt)
            if not m:
                continue
            method = m.group(1).lower()
            if method not in route_methods:
                continue

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
            handler = named_args[1]
            htxt = safe_text(content, handler).strip()

            if "function" in htxt or "fn(" in htxt:
                out.add(add_anon(handler.start_point[0], htxt))
                continue

            # ["Controller", "method"]
            if htxt.startswith("[") and htxt.endswith("]"):
                m2 = re.findall(r"['\"]([A-Za-z0-9_]+)['\"]", htxt)
                if m2:
                    meth = m2[-1]
                    for uid in by_name_local.get(meth, []):
                        out.add(uid)
                continue

            # 'Controller@method'
            if ("@" in htxt) and (htxt.startswith(("'", '"'))):
                s = htxt.strip("'\"")
                parts = s.split("@", 1)
                if len(parts) == 2:
                    meth = parts[1]
                    for uid in by_name_local.get(meth, []):
                        out.add(uid)
                continue

        return out

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