#!/usr/bin/env python3
"""
AST Loader Script - Loads saved AST data and processes it with core2/auditor.py
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Iterable, DefaultDict
from dataclasses import dataclass
from collections import defaultdict
import re
import shutil
import hashlib


# ============================================================================
# AST CORE MODULE CODE
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
# SINKS MODULE CODE
# ============================================================================

KNOWN_SINKS: Dict[str, Set[str]] = {
    "python": {
        # Existing sinks
        "exec", "eval", "compile", "open", "execfile", "input", "__import__",
        "os.system", "os.popen", "os.spawn",
        "subprocess.Popen", "subprocess.call", "subprocess.run",
        "pickle.loads", "yaml.load", "marshal.load", "shelve.open",
        "sqlite3.connect", "cursor.execute",
        "flask.render_template_string",
        # Added from regex
        "subprocess.check_output", "commands.getoutput",
        "pickle.load", "marshal.loads",
        "cursor.executemany", "cursor.executescript",
        "jinja2.Template", "mako.template",
        "urllib.request.urlopen", "requests.get", "requests.post",
        "xml.etree.ElementTree.parse", "lxml.etree.fromstring",
        "shutil.rmtree", "os.remove",
        "zipfile.ZipFile.extractall", "tarfile.TarFile.extractall",
        "flask.redirect", "django.shortcuts.redirect",
        "re.compile", "re.search",
    },
    "javascript": {
        # Existing sinks
        "eval", "Function", "setTimeout", "setInterval",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln",
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
        # Added from regex
        "child_process.execSync", "child_process.spawnSync",
        "vm.runInNewContext", "vm.runInThisContext",
        "db.query", "connection.query", "sequelize.query", # SQLi
        "res.render", "ejs.render", "pug.render", # SSTI
        "JSON.parse", "deserialize", "node-serialize.unserialize", # Deserialization
        "http.request", "axios.get", "request", # SSRF
        "fs.writeFile", "fs.unlink", # File System
        "res.redirect", "window.location.href", # Open Redirect
        "new RegExp", "RegExp", # ReDoS
    },
    # typescript & tsx share a lot with javascript
    "typescript": {
        "eval", "Function", "setTimeout", "setInterval",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln",
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
        "child_process.execSync",
        "vm.runInNewContext",
        "db.query", "connection.query",
        "res.render",
        "JSON.parse",
        "http.request", "axios.get",
        "fs.writeFile",
        "res.redirect",
        "new RegExp",
    },
    "tsx": {
        "eval", "Function", "setTimeout", "setInterval",
        "child_process.exec", "child_process.spawn", "child_process.execFile",
        "document.write", "document.writeln",
        "innerHTML", "outerHTML", "dangerouslySetInnerHTML",
        "child_process.execSync",
        "db.query", "res.render",
        "http.request", "axios.get",
        "res.redirect",
        "new RegExp",
    },
    "java": {
        # Existing sinks
        "Runtime.exec", "ProcessBuilder.start",
        "Statement.execute", "Statement.executeQuery",
        "PreparedStatement.execute", "PreparedStatement.executeQuery",
        # Added from regex
        "Runtime.getRuntime().exec", "ProcessBuilder",
        "ScriptEngine.eval", "Method.invoke", "Class.forName",
        "EntityManager.createQuery", "JdbcTemplate.query", # SQLi
        "ObjectInputStream.readObject", "XMLDecoder.readObject", "new XMLDecoder", # Deserialization
        "XPathExpression.compile", "DocumentBuilderFactory.newInstance", # XXE
        "URL.openConnection", "HttpURLConnection", "RestTemplate.getForObject", # SSRF
        "Files.write", "File.delete", # File system
        "response.sendRedirect", "new RedirectView", # Open Redirect
        "Pattern.compile", "String.matches", # ReDoS
    },
    "php": {
        # Existing sinks and user requests
        "exec", "system", "passthru", "shell_exec", "eval", "popen", "proc_open", "mysqli_query",
        "require", "require_once", "include", "include_once", "file_get_contents",
        # Added from regex
        "pcntl_exec", "assert", "create_function", "preg_replace", # Code Execution
        "mysql_query", "pg_query", "PDO->query", "PDO->prepare", # SQLi
        "unserialize", "igbinary_unserialize", # Deserialization
        "simplexml_load_string", "DOMDocument->loadXML", # XXE
        "curl_exec", "fsockopen", # SSRF
        "unlink", "rmdir", "move_uploaded_file", # File System
        "header", # Open Redirect
        "sleep", "usleep", # DoS
        "preg_match", # ReDoS
    },
    "go": {
        # Existing sinks
        "os.StartProcess", "exec.Command", "sql.Query", "sql.Exec", "template.Execute",
        # Added from regex
        "exec.CommandContext", "syscall.Exec", # Command Injection
        "db.Query", "db.Exec", "db.Prepare", # SQLi
        "json.Unmarshal",
        "xml.Unmarshal", "gob.Decode", # Deserialization
        "template.ExecuteTemplate", "pongo2.FromString", # SSTI
        "xml.NewDecoder", # XXE
        "http.Get", "http.Post", "net.Dial", # SSRF
        "os.Remove", "os.WriteFile", # File System
        "http.Redirect", # Open Redirect
        "fmt.Sprintf",
        "regexp.Compile", # ReDoS
    },
    "ruby": {
        # Existing sinks
        "eval", "system", "exec", "syscall", "open", "send", "public_send",
        # Added from regex
        "spawn", "popen", "`", "%x", "instance_eval", "class_eval", # Code Execution
        "find_by_sql", "connection.execute", "where", # SQLi
        "Marshal.load", "YAML.load", "Oj.load", # Deserialization
        "ERB.new", "ERB#result", # SSTI
        "Nokogiri::XML", "REXML::Document.new", # XXE
        "Net::HTTP.get", "URI.open", "RestClient.get", # SSRF
        "File.write", "File.delete", "IO.write", # File System
        "redirect_to", # Open Redirect
        "Regexp.new", # ReDoS
        "sleep", # DoS
    },
    "c_sharp": {
        # Existing sinks (c_sharp -> CSharp)
        "Process.Start", "Assembly.Load", "Type.GetType",
        "SqlCommand.ExecuteReader", "SqlCommand.ExecuteNonQuery",
        # Added from regex
        "ProcessStartInfo", "PowerShell.Invoke", "CodeDomProvider.CompileAssemblyFromSource", # Code Execution
        "OdbcCommand.ExecuteReader", "OleDbCommand.ExecuteNonQuery", # SQLi
        "BinaryFormatter.Deserialize", "JsonConvert.DeserializeObject", "XmlSerializer.Deserialize", # Deserialization
        "XPathNavigator.Evaluate", "XPathDocument.Create", # XPath Injection
        "XmlDocument.Load", "XmlReader.Create", # XXE
        "HttpClient.GetAsync", "WebRequest.Create", # SSRF
        "File.WriteAllText", "Directory.Delete", # File System
        "Response.Redirect", "RedirectToAction", "RedirectPermanent", # Open Redirect
        "new Regex", "Regex.Match", # ReDoS
    },
    # New languages from regex logs
    "clojure": {
        "clojure.java.shell/sh", "eval", "load-string", "Class/forName",  # Code execution
        "jdbc/query", "jdbc/execute!",  # SQLi
        "ObjectInputStream.", "cheshire.parse-string", # Deserialization
        "selmer/render", "clostache/render", # SSTI
        "clojure.xml/parse", "DocumentBuilderFactory", # XXE
        "http/get", "slurp", # SSRF
        "spit", "clojure.java.io/copy", # File system
        "ring.util.response/redirect", # Open Redirect
        "re-pattern" # ReDoS
    },
    "elixir": {
        "System.cmd", "Port.open", ":os.cmd", "Code.eval_string", # Code execution
        "Ecto.Repo.query", "Ecto.Repo.query!", # SQLi
        ":erlang.binary_to_term", # Deserialization
        "EEx.eval_string", "Mustache.render", # SSTI
        "SweetXml.xpath", ":xmerl_xpath.string", # XPath/XXE
        "HTTPoison.get", "Tesla.get", ":httpc.request", # SSRF
        "File.write", "File.rm", # File system
        "Plug.Conn.redirect", # Open Redirect
        "Regex.compile" # ReDoS
    },
    "erlang": {
        "os:cmd", "open_port", "erl_eval:exprs", # Code execution
        "epgsql:squery", "emysql:execute", # SQLi
        "binary_to_term", # Deserialization
        "erlydtl:render", "mustache:render", # SSTI
        "xmerl_xpath:string", "xmerl_scan:file", # XXE
        "httpc:request", "ibrowse:send_req", # SSRF
        "file:write_file", "file:delete", # File system
        "cowboy_req:reply", # Can be used for open redirect
        "re:compile", "re:run" # ReDoS
    },
    "kotlin": {
        "Runtime.getRuntime().exec", "ProcessBuilder", "ScriptEngineManager",  # Code execution
        "Connection.createStatement", "prepareStatement", "EntityManager.createQuery", # SQLi
        "ObjectInputStream.readObject", "Gson.fromJson", "ObjectMapper.readValue", # Deserialization
        "Thymeleaf", "FreeMarker", "PebbleEngine", # SSTI
        "DocumentBuilderFactory.newInstance", "SAXParserFactory.newInstance", # XXE
        "URL.openConnection", "OkHttpClient.newCall", "RestTemplate", # SSRF
        "File.delete", "Files.write", # File system
        "response.sendRedirect", "RedirectView", # Open Redirect
        "Pattern.compile", "Regex" # ReDoS
    },
    "perl": {
        "system", "exec", "eval", "open", "require", "`", "qx", # Code Execution
        "prepare", "execute", "selectall_arrayref", "DBI->prepare", # SQLi
        "Storable::thaw", "Storable::retrieve", "Data::Dumper::eval", # Deserialization
        "Template->process", "Text::Template->fill_in", # SSTI
        "XML::LibXML", "XML::Parser", # XXE
        "LWP::UserAgent", "HTTP::Tiny", "get", # SSRF
        "unlink", "rename", "print", # File I/O
        "redirect", # Open Redirect
        "qr", "m//" # Regex
    },
    "rust": {
        "std::process::Command::new", "spawn", "output", # Command Injection
        "rusqlite::Connection::execute", "sqlx::query", "diesel::sql_query", # SQLi
        "serde_json::from_str", "bincode::deserialize", # Deserialization
        "tera::Tera::render", "handlebars::Handlebars::render", # SSTI
        "quick_xml::Reader::from_file", "roxmltree::Document::parse", # XXE
        "reqwest::Client::get", "ureq::get", "hyper::Client::request", # SSRF
        "std::fs::write", "std::fs::remove_file", # File System
        "rocket::response::Redirect::to", "warp::redirect", # Open Redirect
        "fancy_regex::Regex::new", "regex::Regex::new" # ReDoS
    },
}


# ============================================================================
# SOURCES MODULE CODE
# ============================================================================

PHP_SOURCE_REGEX = re.compile(
    r"""(?ix)
    (?:\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV|SESSION)\b)
    |(?:php://input\b)
    |(?:\$HTTP_RAW_POST_DATA\b)
    """
)

# PHP require/include fallback regex
PHP_REQUIRE_REGEX = re.compile(r"\b(require_once|require|include_once|include)\b", re.IGNORECASE)

# crude comment stripping for PHP (helps regex fallback)
PHP_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
PHP_LINE_COMMENT_RE = re.compile(r"(?m)//.*?$|#.*?$")


def is_php_source(text: str) -> bool:
    """Return True if the text contains PHP source indicators (superglobals, php://input)."""
    return bool(PHP_SOURCE_REGEX.search(text or ""))


def strip_php_comments(text: str) -> str:
    """Strip PHP comments from text for regex fallback."""
    text = PHP_BLOCK_COMMENT_RE.sub("", text)
    text = PHP_LINE_COMMENT_RE.sub("", text)
    return text


# ============================================================================
# TRACE PROCESSOR MODULE CODE
# ============================================================================

class TraceProcessor:
    def __init__(self, show_code: bool = False, out_dir: Optional[Path] = None):
        self.show_code = show_code
        self.out_dir = out_dir
        self._trace_counter: int = 0
        self._file_text_cache: Dict[str, List[str]] = {}

        # Deduplication: track files by code hash (excluding sink)
        # Maps: code_hash -> (trace_id, path_set)
        # path_set contains all paths that share the same function code
        self._code_hash_to_file: Dict[str, Tuple[int, Set[Tuple[str, ...]]]] = {}
        self._traces_found: int = 0  # Счетчик найденных trace'ов для прогресс-бара

    def _get_file_lines(self, file_path: str) -> List[str]:
        if file_path in self._file_text_cache:
            return self._file_text_cache[file_path]
        try:
            txt = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            lines = txt.splitlines()
        except Exception:
            lines = []
        self._file_text_cache[file_path] = lines
        return lines

    def _node_code(self, nodes: Dict[str, Node], uid: str, max_lines: int = 400) -> str:
        n = nodes[uid]
        if n.is_builtin or n.file in {"<external>", "unknown", "<builtin>"}:
            return ""

        lines = self._get_file_lines(n.file)
        if not lines:
            return ""

        start = max(1, int(n.line or 1))
        end = int(n.end_line or n.line or start)
        end = max(start, end)

        # keep output bounded
        if (end - start + 1) > max_lines:
            end = start + max_lines - 1

        snippet = lines[start - 1:end]
        return "\n".join(snippet)

    def _get_path_code_hash(self, path: List[str], nodes: Dict[str, Node]) -> str:
        """
        Вычисляет хеш кода всех функций в пути (исключая sink).
        Используется для дедупликации файлов с одинаковым кодом.
        """
        if not path:
            return ""

        # Исключаем sink из хеша, так как sinks могут быть разными
        # Берем все функции кроме последней (sink)
        function_uids = path[:-1] if len(path) > 1 else []

        if not function_uids:
            return ""

        # Собираем код всех функций
        codes = []
        for uid in function_uids:
            code = self._node_code(nodes, uid)
            if code:
                codes.append(f"{uid}:{code}")

        # Создаем хеш из отсортированного списка кодов
        # Сортируем для консистентности
        combined = "\n---\n".join(sorted(codes))
        return hashlib.md5(combined.encode('utf-8')).hexdigest()

    def _get_functions_code_set(self, path: List[str], nodes: Dict[str, Node]) -> Set[str]:
        """
        Возвращает множество хешей кода функций в пути (исключая sink).
        Используется для проверки, является ли путь расширением существующего.
        """
        if not path or len(path) <= 1:
            return set()

        # Исключаем sink
        function_uids = path[:-1]
        code_hashes = set()

        for uid in function_uids:
            code = self._node_code(nodes, uid)
            if code:
                # Создаем хеш для каждой функции отдельно
                code_hash = hashlib.md5(f"{uid}:{code}".encode('utf-8')).hexdigest()
                code_hashes.add(code_hash)

        return code_hashes

    def _find_existing_file_for_path(self, path: List[str], nodes: Dict[str, Node]) -> Optional[Tuple[int, List[str]]]:
        """
        Ищет существующий файл для данного пути на основе кода функций.
        Возвращает (trace_id, existing_path) если:
        1. Найден файл с точно таким же кодом функций (хеш совпадает), или
        2. Новый путь содержит все функции из существующего пути (является расширением).
        Sink может быть разным - это нормально.
        """
        code_hash = self._get_path_code_hash(path, nodes)
        if not code_hash:
            # Если нет кода функций (только sink), создаем отдельный файл
            return None

        # Сначала проверяем точное совпадение хеша
        if code_hash in self._code_hash_to_file:
            trace_id, existing_paths = self._code_hash_to_file[code_hash]
            if existing_paths:
                first_path = list(next(iter(existing_paths)))
                return (trace_id, first_path)

        # Если точного совпадения нет, проверяем, является ли новый путь расширением существующего
        # (содержит все функции из существующего пути + еще)
        new_functions_set = self._get_functions_code_set(path, nodes)
        if not new_functions_set:
            return None

        # Проверяем все существующие файлы
        for existing_hash, (trace_id, existing_paths) in self._code_hash_to_file.items():
            # Берем первый путь из существующих для проверки
            if existing_paths:
                existing_path = list(next(iter(existing_paths)))
                existing_functions_set = self._get_functions_code_set(existing_path, nodes)

                # Если новый путь содержит все функции из существующего (является расширением)
                if existing_functions_set and existing_functions_set.issubset(new_functions_set):
                    return (trace_id, existing_path)

        return None

    def _label(self, uid: str, nodes: Dict[str, Node]) -> str:
        n = nodes[uid]
        tags = []
        if n.is_entry: tags.append("WEB_ENTRY")
        if n.is_source: tags.append("SOURCE")
        if n.is_sink: tags.append("SINK")
        return f"{n.name}" + (f" [{'|'.join(tags)}]" if tags else "")

    def _format_loc(self, n: Node) -> str:
        if n.is_builtin:
            return "<builtin>"
        if n.file == "unknown":
            return "<unknown source>"
        if n.file == "<external>":
            return "<external lib>"
        loc = f"{n.file}:{n.line}"
        if n.end_line and n.end_line != n.line:
            loc = f"{n.file}:{n.line}-{n.end_line}"
        return loc

    def _path_to_text(self, path: List[str], nodes: Dict[str, Node], edge_sites: DefaultDict[Tuple[str, str], List[Tuple[str, int]]], include_code: bool) -> str:
        out: List[str] = []
        names = [self._label(uid, nodes) for uid in path]
        out.append(f"[PATH] {' -> '.join(names)}")
        out.append("")

        for uid in path:
            n = nodes[uid]
            out.append(f"{self._label(uid, nodes)} ({self._format_loc(n)})")
            if include_code:
                code = self._node_code(nodes, uid)
                if code:
                    out.append("----- CODE BEGIN -----")
                    out.append(code)
                    out.append("----- CODE END -----")
            out.append("")

        # callsites for each hop
        if len(path) >= 2:
            out.append("callsites:")
            for i in range(len(path) - 1):
                src, dst = path[i], path[i + 1]
                sites = edge_sites.get((src, dst), [])
                if not sites:
                    continue
                uniq = list(dict.fromkeys(sites))[:20]
                out.append(f"  {self._label(src, nodes)} -> {self._label(dst, nodes)}")
                for f, ln in uniq:
                    out.append(f"    - {f}:{ln}")
            out.append("")

        return "\n".join(out)

    def _update_progress(self):
        """Обновляет прогресс-бар на месте"""
        bar_length = 50
        filled = min(bar_length, self._traces_found)
        bar = "█" * filled + "░" * (bar_length - filled)
        progress_text = f"\r[PROGRESS] [{bar}] Traces found: {self._traces_found}"
        sys.stdout.write(progress_text)
        sys.stdout.flush()

    def emit_trace(self, path: List[str], nodes: Dict[str, Node], edge_sites: DefaultDict[Tuple[str, str], List[Tuple[str, int]]]):
        self._traces_found += 1

        # File output with deduplication
        if self.out_dir:
            self.out_dir.mkdir(parents=True, exist_ok=True)

            code_hash = self._get_path_code_hash(path, nodes)

            # Проверяем, есть ли уже файл с таким же кодом функций
            existing = self._find_existing_file_for_path(path, nodes)

            if existing:
                # Найден существующий файл - добавляем новый путь в него
                existing_trace_id, existing_path = existing
                path_tuple = tuple(path)

                # Обновляем множество путей для этого хеша
                if code_hash in self._code_hash_to_file:
                    trace_id, existing_paths = self._code_hash_to_file[code_hash]
                    existing_paths.add(path_tuple)

                    # Читаем существующий файл и добавляем новый путь
                    txt_file = self.out_dir / f"{existing_trace_id}.txt"
                    code_file = self.out_dir / f"{existing_trace_id}_code.txt"

                    # Добавляем новый путь в текстовый файл
                    if txt_file.exists():
                        existing_content = txt_file.read_text(encoding="utf-8", errors="ignore")
                        new_path_text = self._path_to_text(path, nodes, edge_sites, include_code=False)
                        # Добавляем разделитель и новый путь
                        updated_content = existing_content + "\n\n" + "="*80 + "\n\n" + new_path_text
                        txt_file.write_text(updated_content, encoding="utf-8", errors="ignore")
                    else:
                        # Если файл почему-то не существует, создаем заново
                        txt_file.write_text(
                            self._path_to_text(path, nodes, edge_sites, include_code=False),
                            encoding="utf-8", errors="ignore"
                        )

                    # Добавляем новый путь в файл с кодом (только если show_code=True)
                    if self.show_code:
                        if code_file.exists():
                            existing_code_content = code_file.read_text(encoding="utf-8", errors="ignore")
                            new_path_code = self._path_to_text(path, nodes, edge_sites, include_code=True)
                            # Добавляем разделитель и новый путь
                            updated_code_content = existing_code_content + "\n\n" + "="*80 + "\n\n" + new_path_code
                            code_file.write_text(updated_code_content, encoding="utf-8", errors="ignore")
                        else:
                            # Если файл почему-то не существует, создаем заново
                            code_file.write_text(
                                self._path_to_text(path, nodes, edge_sites, include_code=True),
                                encoding="utf-8", errors="ignore"
                            )

                    logger.debug(f"Added path to existing trace file {existing_trace_id} (code_hash: {code_hash[:8]}...)")
            else:
                # Новый уникальный код - создаем новый файл
                self._trace_counter += 1
                trace_id = self._trace_counter

                # Сохраняем хеш для будущих проверок
                if code_hash:
                    path_tuple = tuple(path)
                    self._code_hash_to_file[code_hash] = (trace_id, {path_tuple})

                (self.out_dir / f"{trace_id}.txt").write_text(
                    self._path_to_text(path, nodes, edge_sites, include_code=False),
                    encoding="utf-8", errors="ignore"
                )
                # Сохраняем код в файл только если show_code=True
                if self.show_code:
                    (self.out_dir / f"{trace_id}_code.txt").write_text(
                        self._path_to_text(path, nodes, edge_sites, include_code=True),
                        encoding="utf-8", errors="ignore"
                    )

        # Обновляем прогресс-бар (перезаписываем строку на месте)
        self._update_progress()

    def reset_counter(self):
        """Сбрасывает счетчик найденных trace'ов"""
        self._traces_found = 0

    def get_traces_found(self) -> int:
        """Возвращает количество найденных trace'ов"""
        return self._traces_found


# ============================================================================
# GRAPH BUILDER MODULE CODE
# ============================================================================

class SecurityGraph:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.adj: Dict[str, Set[str]] = defaultdict(set)         # for traversal
        self.rev_adj: Dict[str, Set[str]] = defaultdict(set)     # for traversal

        # IMPORTANT FIX: store callsites so edges aren't collapsed
        self.edge_sites: DefaultDict[Tuple[str, str], List[Tuple[str, int]]] = defaultdict(list)

        self.sinks_found: Set[str] = set()

        # Trace processor
        self.trace_processor: Optional[TraceProcessor] = None

    def set_trace_processor(self, processor: TraceProcessor):
        """Set the trace processor for handling trace output."""
        self.trace_processor = processor

    def add_node(self, n: Node):
        if n.uid in self.nodes:
            old = self.nodes[n.uid]
            old.is_entry = old.is_entry or n.is_entry
            old.is_sink = old.is_sink or n.is_sink
            old.is_source = old.is_source or n.is_source

            if n.end_line and (old.end_line == 0 or n.end_line > old.end_line):
                old.end_line = n.end_line
            if n.line and (old.line == 0 or n.line < old.line):
                old.line = n.line

            return

        self.nodes[n.uid] = n
        if n.is_sink:
            self.sinks_found.add(n.uid)

    def add_edge(self, caller_uid: str, callee_name: str, lang: str, file: str, line: int):
        if caller_uid not in self.nodes:
            self.nodes[caller_uid] = Node(caller_uid, caller_uid.split(".")[-1], "unknown", 0)

        sinks = KNOWN_SINKS.get(lang, set())
        callee_norm = normalize_callee(callee_name)

        is_sink = (callee_norm in sinks) or any(callee_norm.endswith("." + s) for s in sinks)

        if is_sink:
            target_uid = f"builtin.{lang}.{callee_norm}"
            if target_uid not in self.nodes:
                self.nodes[target_uid] = Node(
                    uid=target_uid, name=callee_norm, file="<builtin>", line=0, end_line=0,
                    is_sink=True, is_builtin=True
                )
            self.sinks_found.add(target_uid)
        else:
            target_uid = None

            if "." not in callee_norm:
                caller_mod = caller_uid.rsplit(".", 1)[0]
                candidate_local = f"{caller_mod}.{callee_norm}"
                if candidate_local in self.nodes:
                    target_uid = candidate_local

            if not target_uid:
                callee_last = callee_norm.split(".")[-1]
                matches = [uid for uid, n in self.nodes.items() if n.name == callee_last]
                if matches:
                    target_uid = matches[0]

            if not target_uid:
                target_uid = f"ext.{lang}.{callee_norm}"
                if target_uid not in self.nodes:
                    self.nodes[target_uid] = Node(target_uid, callee_norm, "<external>", 0, end_line=0, is_builtin=True)

        # traversal connectivity
        self.adj[caller_uid].add(target_uid)
        self.rev_adj[target_uid].add(caller_uid)

        # callsites (do NOT collapse)
        self.edge_sites[(caller_uid, target_uid)].append((file, line))

    def _print_sink_summary(self, top: int = 20):
        sink_counts: Dict[str, int] = defaultdict(int)
        for (src, dst), sites in self.edge_sites.items():
            if dst in self.nodes and self.nodes[dst].is_sink:
                sink_counts[dst] += len(sites)

        total = sum(sink_counts.values())
        print(f"\nSink callsites (all repo): {total}")
        if not sink_counts:
            return

        ranked = sorted(sink_counts.items(), key=lambda x: x[1], reverse=True)[:top]
        for dst, cnt in ranked:
            print(f"  - {self.nodes[dst].name}: {cnt}")

    def trace_all(self, show_code: bool = False, out_dir: Optional[Path] = None):
        # Initialize trace processor
        self.trace_processor = TraceProcessor(show_code=show_code, out_dir=out_dir)
        self.trace_processor.reset_counter()

        print(f"\n{'='*30} VULNERABILITY REPORT {'='*30}")

        # ==================== ИЗМЕНЕНИЕ НАЧАЛО ====================
        # Используем множества для автоматической дедупликации
        entries = {uid for uid, n in self.nodes.items() if n.is_entry}
        sources = {uid for uid, n in self.nodes.items() if n.is_source}

        print(f"Total Nodes: {len(self.nodes)} | WEB Entry Points: {len(entries)} | Sources: {len(sources)} | Sink Nodes: {len(self.sinks_found)}")
        self._print_sink_summary(top=30)

        # Объединяем точки входа и источники данных в единый список стартовых точек для трассировки
        start_points = entries | sources
        # ==================== ИЗМЕНЕНИЕ КОНЕЦ ====================

        if not self.sinks_found:
            print("No dangerous sinks detected.")
            return

        if not start_points:
            print("\n[WARN] No WEB entrypoints or data Sources found. Unable to start trace.")
            # Даже если нет стартовых точек, все равно покажем обратную трассировку от синков

        paths_found = 0
        max_depth = 16

        # Инициализируем прогресс-бар
        print("\n[PROGRESS] Analyzing traces...")
        import sys
        sys.stdout.write("[PROGRESS] [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] Traces found: 0\n")
        sys.stdout.flush()

        def dfs(curr, path, visited_local):
            nonlocal paths_found
            if self.nodes[curr].is_sink:
                paths_found += 1
                self.trace_processor.emit_trace(path, self.nodes, self.edge_sites)
                return
            if len(path) > max_depth:
                return
            for neighbor in self.adj.get(curr, []):
                if neighbor not in visited_local:
                    dfs(neighbor, path + [neighbor], visited_local | {neighbor})

        # ==================== ИЗМЕНЕНИЕ НАЧАЛО ====================
        # Запускаем трассировку от ВСЕХ стартовых точек (entry points + sources)
        for start_node in start_points:
            dfs(start_node, [start_node], {start_node})
        # ==================== ИЗМЕНЕНИЕ КОНЕЦ ====================

        # Завершаем прогресс-бар (переходим на новую строку)
        print()  # Новая строка после прогресс-бара

        if paths_found == 0:
            print("\n[INFO] No paths from WEB Entry Points or Sources to Sinks found.")
            print("Showing immediate callers of Sinks (Backward Trace):")
            for sink in sorted(self.sinks_found):
                callers = list(self.rev_adj.get(sink, []))
                # Покажем хотя бы один пример вызова для каждого "осиротевшего" синка
                for c in callers[:1]:
                    # Проверяем, что у вызывающей функции есть источник данных, чтобы не показывать совсем бесполезные пути
                    if self.nodes[c].is_source:
                       self.trace_processor.emit_trace([c, sink], self.nodes, self.edge_sites)
                       print()  # Новая строка после последнего trace'а

    def visualize(self, filename="vuln_graph"):
        if not shutil.which("dot"):
            print("Graphviz 'dot' not found. Visualization skipped. (Install graphviz)")
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
                    color = "red" if (dst in self.nodes and self.nodes[dst].is_sink) else "#666666"
                    dot.edge(src, dst, color=color)

            dot.render(filename, view=False)
            print(f"Graph saved to {filename}.png")
        except Exception as e:
            print(f"Visualization error: {e}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

def load_ast_data(file_path: Path) -> Dict:
    """Load AST data from a file (JSON or pickle format)"""
    if file_path.suffix.lower() == '.json':
        with open(file_path, 'r') as f:
            return json.load(f)
    else:  # Assume pickle format
        import pickle
        with open(file_path, 'rb') as f:
            return pickle.load(f)

def main():
    ap = argparse.ArgumentParser(description="Load saved AST data and process with auditor")
    ap.add_argument("--input", required=True, help="Path to the saved AST data file")
    ap.add_argument("--visualize", action="store_true", help="Generate PNG visualization")
    ap.add_argument("--code", action="store_true", help="Show code for each function in every trace")
    ap.add_argument("--out", help="Output directory to save traces: N.txt and N_code.txt")
    
    args = ap.parse_args()
    
    input_path = Path(args.input).resolve()
    if not input_path.exists():
        print(f"AST data file not found: {input_path}")
        sys.exit(2)
    
    out_dir = Path(args.out).resolve() if args.out else None
    
    # Load the AST data
    logger.info(f"Loading AST data from {input_path}")
    ast_data = load_ast_data(input_path)
    
    logger.info(f"Loaded AST data for repository: {ast_data['repository']}")
    logger.info(f"Found {len(ast_data['nodes'])} nodes and {len(ast_data['edges'])} edges")
    
    # Create a new security graph
    graph = SecurityGraph()
    
    # Convert dictionaries back to Node objects and add to graph
    for node_data in ast_data['nodes']:
        node = Node(
            uid=node_data['uid'],
            name=node_data['name'],
            file=node_data['file'],
            line=node_data['line'],
            end_line=node_data.get('end_line', 0),
            is_sink=node_data.get('is_sink', False),
            is_entry=node_data.get('is_entry', False),
            is_source=node_data.get('is_source', False),
            is_builtin=node_data.get('is_builtin', False)
        )
        graph.add_node(node)
    
    # Convert dictionaries back to Edge objects and add to graph
    for edge_data in ast_data['edges']:
        # Extract language from file extension
        file_path = Path(edge_data['file'])
        ext = file_path.suffix.lower()
        
        # Map extension to language (same as in ast_core.py)
        lang = EXT_TO_LANG.get(ext, "unknown")
        
        edge = Edge(
            src=edge_data['src'],
            dst=edge_data['dst'],
            file=edge_data['file'],
            line=edge_data['line']
        )
        graph.add_edge(edge.src, edge.dst, lang, edge.file, edge.line)
    
    # Process the graph
    graph.trace_all(show_code=args.code, out_dir=out_dir)
    
    if args.visualize:
        graph.visualize()
    
    logger.info("AST processing complete")

if __name__ == "__main__":
    main()