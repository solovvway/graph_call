#!/usr/bin/env python3
"""Trace processor module: handles trace processing, deduplication, and output."""
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, DefaultDict, Any
from collections import defaultdict
import logging

from .ast_core import Node, LANG_SPECS, EXT_TO_LANG
from .sources import validate_source

logger = logging.getLogger(__name__)

class TraceProcessor:
    def __init__(self, show_code: bool = False, repo_path: Optional[Path] = None):
        self.show_code = show_code
        self.repo_path = repo_path
        self._trace_counter: int = 0
        self._file_text_cache: Dict[str, List[str]] = {}
        
        # Deduplication: track files by code hash (excluding sink)
        # Maps: code_hash -> (trace_id, path_set)
        # path_set contains all paths that share the same function code
        self._code_hash_to_file: Dict[str, Tuple[int, Set[Tuple[str, ...]]]] = {}
        
        # Index for fast lookup: trace_id -> set of code_hashes
        # This allows O(1) lookup instead of O(n) scan
        self._trace_id_to_hashes: Dict[int, Set[str]] = defaultdict(set)
        
        # Store function code separately to avoid duplication
        # Maps: trace_id -> {uid: code}
        self._trace_code_cache: Dict[int, Dict[str, str]] = {}
        
        # Store collected traces: trace_id -> (path, code_hash, code_cache)
        self._collected_traces: Dict[int, Tuple[List[str], str, Dict[str, str]]] = {}
        
        # Store all sinks for each trace (for merging traces with same code but different sinks)
        # Maps: trace_id -> set of sink UIDs
        self._trace_sinks: Dict[int, Set[str]] = defaultdict(set)
        
        self._traces_found: int = 0  # Счетчик найденных trace'ов для прогресс-бара
        
        # Cache for parsers and class definitions
        self._parser_cache: Dict[str, Any] = {}  # lang -> parser
        self._language_cache: Dict[str, Any] = {}  # lang -> language
        self._class_def_cache: Dict[Tuple[str, str], Optional[Tuple[int, int]]] = {}  # (file, class_name) -> (start_line, end_line)
        
        # Cache for function code sets to avoid recomputation
        # Maps: path_tuple -> function_code_set
        self._path_function_set_cache: Dict[Tuple[str, ...], Set[str]] = {}

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
    
    def _get_language_from_file(self, file_path: str) -> Optional[str]:
        """Determine language from file extension."""
        ext = Path(file_path).suffix
        return EXT_TO_LANG.get(ext)
    
    def _get_parser(self, lang: str):
        """Get or create parser for language."""
        if lang in self._parser_cache:
            return self._parser_cache[lang]
        
        try:
            from tree_sitter_languages import get_parser, get_language
            parser = get_parser(lang)
            language = get_language(lang)
            self._parser_cache[lang] = parser
            self._language_cache[lang] = language
            return parser
        except Exception as e:
            logger.debug(f"Failed to get parser for {lang}: {e}")
            return None
    
    def _find_class_definition(self, file_path: str, class_name: str) -> Optional[Tuple[int, int]]:
        """
        Find class definition in file and return (start_line, end_line).
        Returns None if class not found.
        """
        cache_key = (file_path, class_name)
        if cache_key in self._class_def_cache:
            return self._class_def_cache[cache_key]
        
        lang = self._get_language_from_file(file_path)
        if not lang:
            self._class_def_cache[cache_key] = None
            return None
        
        parser = self._get_parser(lang)
        if not parser:
            self._class_def_cache[cache_key] = None
            return None
        
        try:
            content = Path(file_path).read_bytes()
            tree = parser.parse(content)
            
            lang_spec = LANG_SPECS.get(lang, {})
            class_node_types = lang_spec.get("class_node_types", set())
            
            if not class_node_types:
                self._class_def_cache[cache_key] = None
                return None
            
            language = self._language_cache.get(lang)
            if not language:
                self._class_def_cache[cache_key] = None
                return None
            
            # Walk tree to find class definition
            def walk_tree(node):
                stack = [node]
                while stack:
                    n = stack.pop()
                    if n.type in class_node_types:
                        # Check if this is the class we're looking for
                        name_node = n.child_by_field_name("name")
                        if name_node:
                            class_name_found = content[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="ignore")
                            if class_name_found == class_name:
                                start_line = n.start_point[0] + 1
                                end_line = n.end_point[0] + 1
                                return (start_line, end_line)
                    
                    # Add children to stack
                    for child in n.children:
                        stack.append(child)
                return None
            
            result = walk_tree(tree.root_node)
            self._class_def_cache[cache_key] = result
            return result
            
        except Exception as e:
            logger.debug(f"Error finding class {class_name} in {file_path}: {e}")
            self._class_def_cache[cache_key] = None
            return None
    
    def _is_class_method(self, uid: str, file_path: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check if UID represents a class method.
        Returns (is_method, class_name, method_name) or (False, None, None).
        
        For UID format like: module.submodule.ClassName.method
        We try to identify if second-to-last part is a class name.
        """
        parts = uid.split(".")
        if len(parts) < 3:
            return (False, None, None)
        
        # Method name is always the last part
        method_name = parts[-1]
        
        # Class name should be second to last
        # UID format: module.submodule.ClassName.method
        # We need at least: module.ClassName.method (3 parts)
        if len(parts) >= 3:
            class_name = parts[-2]
            
            # First, use heuristics to quickly identify likely class methods
            # For Python/Java/C#: class names typically start with uppercase
            is_likely_class = class_name and len(class_name) > 0 and class_name[0].isupper()
            
            # If file_path is provided and it looks like a class, verify by finding the class
            if file_path and is_likely_class:
                # Try to find class definition - if found, it's definitely a class method
                class_def = self._find_class_definition(file_path, class_name)
                if class_def:
                    return (True, class_name, method_name)
            
            # If heuristic suggests it's a class, return True
            # (even if we couldn't verify, we'll try to find the class in _node_code)
            if is_likely_class:
                return (True, class_name, method_name)
            
            # If we have 3+ parts, it might still be a class method
            # (some languages don't follow uppercase convention)
            # We'll try to find the class in _node_code
            if len(parts) >= 3:
                return (True, class_name, method_name)
        
        return (False, None, None)

    def _node_code(self, nodes: Dict[str, Node], uid: str, max_lines: int = 400, shown_lines: Optional[Set[Tuple[str, int]]] = None) -> Tuple[str, Tuple[int, int]]:
        """
        Extract code for a node, excluding already shown lines.
        Returns (code, (start_line, end_line)) tuple.
        """
        n = nodes[uid]
        if n.is_builtin or n.file in {"<external>", "unknown", "<builtin>"}:
            return ("", (0, 0))

        lines = self._get_file_lines(n.file)
        if not lines:
            return ("", (0, 0))

        shown_lines = shown_lines or set()
        file_key = n.file

        # Check if this is a class method - if so, extract entire class code
        is_method, class_name, method_name = self._is_class_method(uid, n.file)
        
        if is_method and class_name:
            # Try to find class definition
            class_def = self._find_class_definition(n.file, class_name)
            if class_def:
                class_start, class_end = class_def
                
                # Check if class is already fully shown
                # Ensure class_end doesn't exceed file length
                class_end_safe = min(class_end, len(lines))
                class_all_shown = all((file_key, line_num) in shown_lines for line_num in range(class_start, class_end_safe + 1))
                
                if class_all_shown:
                    # Class already shown - show only method to avoid duplication
                    # Fall through to method-only extraction below
                    pass
                else:
                    # Class not fully shown - show entire class (or remaining parts)
                    start = max(1, class_start)
                    end = min(len(lines), class_end)
                    
                    # If start exceeds file length, return empty
                    if start > len(lines):
                        return ("", (class_start, class_end))
                    
                    # Keep output bounded
                    if (end - start + 1) > max_lines:
                        end = min(start + max_lines - 1, len(lines))
                    
                    # Filter out already shown lines
                    filtered_lines = []
                    actual_start = None
                    actual_end = None
                    for line_num in range(start, end + 1):
                        # Check bounds - line_num is 1-based, lines is 0-based
                        if line_num < 1 or line_num > len(lines):
                            continue
                        if (file_key, line_num) not in shown_lines:
                            if actual_start is None:
                                actual_start = line_num
                            actual_end = line_num
                            filtered_lines.append(lines[line_num - 1])
                        elif actual_start is not None:
                            # We've already started showing code, add empty line to indicate gap
                            if filtered_lines and filtered_lines[-1].strip():
                                filtered_lines.append("")
                    
                    if filtered_lines:
                        return ("\n".join(filtered_lines), (actual_start or start, actual_end or end))
                    else:
                        # All lines already shown - return empty but with correct line range
                        return ("", (start, end))
            # If class not found, fall through to method-only extraction
        
        # Default: extract method/function code only
        start = max(1, int(n.line or 1))
        end = int(n.end_line or n.line or start)
        end = max(start, end)
        
        # Ensure bounds don't exceed file length
        if start > len(lines):
            return ("", (start, end))
        end = min(end, len(lines))

        # keep output bounded
        if (end - start + 1) > max_lines:
            end = min(start + max_lines - 1, len(lines))

        # Filter out already shown lines
        filtered_lines = []
        actual_start = None
        actual_end = None
        for line_num in range(start, end + 1):
            # Check bounds - line_num is 1-based, lines is 0-based
            if line_num < 1 or line_num > len(lines):
                continue
            if (file_key, line_num) not in shown_lines:
                if actual_start is None:
                    actual_start = line_num
                actual_end = line_num
                filtered_lines.append(lines[line_num - 1])
            elif actual_start is not None:
                # We've already started showing code, add empty line to indicate gap
                if filtered_lines and filtered_lines[-1].strip():
                    filtered_lines.append("")
        
        if filtered_lines:
            return ("\n".join(filtered_lines), (actual_start or start, actual_end or end))
        else:
            # All lines already shown - return empty but with correct line range
            return ("", (start, end))

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
            code, _ = self._node_code(nodes, uid, shown_lines=None)
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
        Использует кэш для ускорения.
        """
        if not path or len(path) <= 1:
            return set()
        
        # Проверяем кэш
        path_tuple = tuple(path)
        if path_tuple in self._path_function_set_cache:
            return self._path_function_set_cache[path_tuple]
        
        # Исключаем sink
        function_uids = path[:-1]
        code_hashes = set()
        
        for uid in function_uids:
            code, _ = self._node_code(nodes, uid, shown_lines=None)
            if code:
                # Создаем хеш для каждой функции отдельно
                code_hash = hashlib.md5(f"{uid}:{code}".encode('utf-8')).hexdigest()
                code_hashes.add(code_hash)
        
        # Сохраняем в кэш
        self._path_function_set_cache[path_tuple] = code_hashes
        return code_hashes

    def _find_existing_file_for_path(self, path: List[str], nodes: Dict[str, Node]) -> Optional[Tuple[int, List[str]]]:
        """
        Ищет существующий файл для данного пути на основе кода функций.
        Возвращает (trace_id, existing_path) если:
        1. Найден файл с точно таким же кодом функций (хеш совпадает), или
        2. Новый путь содержит все функции из существующего пути (является расширением).
        Sink может быть разным - это нормально.
        Оптимизировано с использованием индексов и кэша.
        """
        code_hash = self._get_path_code_hash(path, nodes)
        if not code_hash:
            # Если нет кода функций (только sink), создаем отдельный файл
            return None
        
        # Сначала проверяем точное совпадение хеша (O(1))
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
        
        new_path_len = len(path)
        
        # Оптимизация: используем индекс trace_id для более эффективного поиска
        # Вместо прохода по всем хешам, проходим по trace_id и проверяем их пути
        # Это быстрее, так как у нас обычно меньше trace_id, чем хешей
        checked_trace_ids = set()
        
        # Проходим по всем trace_id через индекс
        for trace_id in self._trace_id_to_hashes.keys():
            if trace_id in checked_trace_ids:
                continue
            
            # Получаем все пути для этого trace_id из всех его хешей
            # Проверяем только пути из collected_traces, которые короче нового
            if trace_id in self._collected_traces:
                existing_path, _, _ = self._collected_traces[trace_id]
                
                # Быстрая проверка: пропускаем пути, которые не короче нового
                if len(existing_path) >= new_path_len:
                    continue
                
                existing_functions_set = self._get_functions_code_set(existing_path, nodes)
                
                # Если новый путь содержит все функции из существующего (является расширением)
                if existing_functions_set and existing_functions_set.issubset(new_functions_set):
                    checked_trace_ids.add(trace_id)
                    return (trace_id, existing_path)
        
        return None

    def _label(self, uid: str, nodes: Dict[str, Node]) -> str:
        n = nodes[uid]
        tags = []
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

    def _path_to_yaml(self, path: List[str], nodes: Dict[str, Node], edge_sites: DefaultDict[Tuple[str, str], List[Tuple[str, int]]], code_cache: Optional[Dict[str, str]] = None, indent: int = 0, show_code: bool = True, shown_lines: Optional[Set[Tuple[str, int]]] = None, additional_sinks: Optional[Set[str]] = None) -> Tuple[str, Set[Tuple[str, int]]]:
        """Generate YAML representation of path with nested function calls.
        
        Args:
            show_code: If False, skip code blocks even if code_cache is provided
            shown_lines: Set of (file, line_number) tuples for lines already shown
        
        Returns:
            (yaml_string, updated_shown_lines)
        """
        if not path:
            return ("", shown_lines or set())
        
        shown_lines = shown_lines or set()
        out: List[str] = []
        indent_str = "  " * indent
        
        # Process first function in path
        uid = path[0]
        n = nodes[uid]
        label = self._label(uid, nodes)
        loc = self._format_loc(n)
        
        # Build YAML entry for current function
        # Escape special YAML characters in label and loc
        label_escaped = label.replace('"', '\\"').replace(':', '\\:')
        loc_escaped = loc.replace('"', '\\"').replace(':', '\\:')
        
        # Use quotes if label contains special characters
        if any(c in label for c in ['[', ']', ':', '"', "'", '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`']):
            out.append(f'{indent_str}- function: "{label_escaped}"')
        else:
            out.append(f"{indent_str}- function: {label}")
        
        if any(c in loc for c in ['[', ']', ':', '"', "'", '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`']):
            out.append(f'{indent_str}  location: "{loc_escaped}"')
        else:
            out.append(f"{indent_str}  location: {loc}")
        
        # Add tags if present
        tags = []
        if n.is_source:
            tags.append("SOURCE")
        if n.is_sink:
            tags.append("SINK")
        if tags:
            out.append(f"{indent_str}  tags: [{', '.join(tags)}]")
        
        # Add code if available and show_code is True
        if show_code and not (n.is_builtin or n.file in {"<external>", "unknown", "<builtin>"}):
            # Get code with filtering of already shown lines
            code, (code_start, code_end) = self._node_code(nodes, uid, shown_lines=shown_lines)
            
            if code:
                # Update shown_lines with the lines we're about to show
                file_key = n.file
                for line_num in range(code_start, code_end + 1):
                    shown_lines.add((file_key, line_num))
                
                # Escape code for YAML (use literal block scalar)
                code_lines = code.split('\n')
                out.append(f"{indent_str}  code: |")
                # Add line range information
                if code_start == code_end:
                    out.append(f"{indent_str}    # Lines {code_start}")
                else:
                    out.append(f"{indent_str}    # Lines {code_start}-{code_end}")
                for line in code_lines:
                    out.append(f"{indent_str}    {line}")
        
        # If there are more functions in path, add them as nested calls
        if len(path) > 1:
            # Check if next element is a sink and we have additional sinks to show
            next_uid = path[1]
            is_next_sink = next_uid in nodes and nodes[next_uid].is_sink
            
            # If this is the last function before sink(s), and we have additional sinks
            if is_next_sink and additional_sinks and len(additional_sinks) > 1:
                # Show all sinks as multiple calls from this function
                out.append(f"{indent_str}  callsites:")
                # Collect all callsites for all sinks
                all_sites = []
                for sink_uid in additional_sinks:
                    sites = edge_sites.get((uid, sink_uid), [])
                    all_sites.extend(sites)
                
                if all_sites:
                    uniq = list(dict.fromkeys(all_sites))[:10]
                    for f, ln in uniq:
                        out.append(f"{indent_str}    - {f}:{ln}")
                
                out.append(f"{indent_str}  calls:")
                # Show all sinks
                for sink_uid in sorted(additional_sinks):
                    sink_node = nodes.get(sink_uid)
                    if sink_node:
                        sink_label = self._label(sink_uid, nodes)
                        sink_loc = self._format_loc(sink_node)
                        
                        label_escaped = sink_label.replace('"', '\\"').replace(':', '\\:')
                        loc_escaped = sink_loc.replace('"', '\\"').replace(':', '\\:')
                        
                        if any(c in sink_label for c in ['[', ']', ':', '"', "'", '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`']):
                            out.append(f'{indent_str}  - function: "{label_escaped}"')
                        else:
                            out.append(f"{indent_str}  - function: {sink_label}")
                        
                        if any(c in sink_loc for c in ['[', ']', ':', '"', "'", '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`']):
                            out.append(f'{indent_str}    location: "{loc_escaped}"')
                        else:
                            out.append(f"{indent_str}    location: {sink_loc}")
                        
                        out.append(f"{indent_str}    tags: [SINK]")
            else:
                # Normal recursive call
                # Add callsites for the call to next function
                dst = path[1]
                sites = edge_sites.get((uid, dst), [])
                if sites:
                    uniq = list(dict.fromkeys(sites))[:10]  # Limit to 10 callsites
                    out.append(f"{indent_str}  callsites:")
                    for f, ln in uniq:
                        out.append(f"{indent_str}    - {f}:{ln}")
                
                # Recursively add next function(s) as nested calls
                out.append(f"{indent_str}  calls:")
                nested, shown_lines = self._path_to_yaml(path[1:], nodes, edge_sites, code_cache, indent + 1, show_code=show_code, shown_lines=shown_lines, additional_sinks=additional_sinks)
                if nested:
                    out.append(nested)
        
        return ("\n".join(out), shown_lines)
    
    def _path_to_text(self, path: List[str], nodes: Dict[str, Node], edge_sites: DefaultDict[Tuple[str, str], List[Tuple[str, int]]], code_cache: Optional[Dict[str, str]] = None, show_code: bool = True, additional_sinks: Optional[Set[str]] = None) -> str:
        """Generate YAML representation of path."""
        yaml_text, _ = self._path_to_yaml(path, nodes, edge_sites, code_cache, indent=0, show_code=show_code, additional_sinks=additional_sinks)
        return yaml_text

    def _update_progress(self):
        """Обновляет прогресс-бар на месте"""
        bar_length = 50
        filled = min(bar_length, self._traces_found)
        bar = "█" * filled + "░" * (bar_length - filled)
        progress_text = f"\r[PROGRESS] [{bar}] Traces found: {self._traces_found}"
        sys.stdout.write(progress_text)
        sys.stdout.flush()

    def emit_trace(self, path: List[str], nodes: Dict[str, Node], edge_sites: DefaultDict[Tuple[str, str], List[Tuple[str, int]]]):
        """Collect trace without saving. Returns trace_id for later retrieval."""
        self._traces_found += 1
        
        # Forward-validation: check if the first node (source) matches source criteria
        if not validate_source(path, nodes, self.repo_path):
            logger.debug(f"Trace rejected by forward-validation: path starts with {path[0] if path else 'empty'}")
            return
        
        code_hash = self._get_path_code_hash(path, nodes)
        
        # Extract sink from path (last element if it's a sink)
        sink_uid = None
        if path:
            last_uid = path[-1]
            if last_uid in nodes and nodes[last_uid].is_sink:
                sink_uid = last_uid
        
        # Build code cache for this path (only for functions, not sinks)
        # Note: We don't filter shown lines here - that will be done during rendering
        code_cache: Dict[str, str] = {}
        if self.show_code:
            for uid in path:
                if uid not in code_cache:
                    code, _ = self._node_code(nodes, uid, shown_lines=None)
                    if code:
                        code_cache[uid] = code
        
        # Проверяем, есть ли уже трейс с таким же кодом функций
        existing = self._find_existing_file_for_path(path, nodes)
        
        if existing:
            # Найден существующий трейс - добавляем новый путь в него
            existing_trace_id, existing_path = existing
            path_tuple = tuple(path)
            
            # Добавляем sink к существующему трейсу, если он отличается
            if sink_uid:
                self._trace_sinks[existing_trace_id].add(sink_uid)
            
            # Определяем, какой путь длиннее - используем более длинный как основной
            use_new_path = len(path) > len(existing_path)
            main_path = path if use_new_path else existing_path
            
            # Оптимизация: используем индекс для быстрого доступа к хешам этого trace_id
            # Вместо O(n) поиска по всем хешам, используем O(1) доступ через индекс
            if code_hash:
                # Добавляем новый хеш в индекс
                self._trace_id_to_hashes[existing_trace_id].add(code_hash)
                
                # Обновляем или создаем запись для этого хеша
                if code_hash in self._code_hash_to_file:
                    # Хеш уже существует - добавляем путь
                    _, paths_set = self._code_hash_to_file[code_hash]
                    paths_set.add(path_tuple)
                else:
                    # Новый хеш для существующего trace_id
                    # Находим существующий paths_set из любого хеша этого trace_id
                    existing_hashes = self._trace_id_to_hashes[existing_trace_id]
                    paths_set = None
                    for hash_key in existing_hashes:
                        if hash_key in self._code_hash_to_file:
                            _, paths_set = self._code_hash_to_file[hash_key]
                            break
                    
                    if paths_set is None:
                        paths_set = set()
                    
                    paths_set.add(path_tuple)
                    self._code_hash_to_file[code_hash] = (existing_trace_id, paths_set)
            
            # Обновляем кэш кода - добавляем только новые функции
            if existing_trace_id in self._trace_code_cache:
                existing_code_cache = self._trace_code_cache[existing_trace_id]
                # Добавляем только код функций, которых еще нет
                for uid, code in code_cache.items():
                    if uid not in existing_code_cache:
                        existing_code_cache[uid] = code
            else:
                self._trace_code_cache[existing_trace_id] = code_cache.copy()
            
            # Обновляем сохраненный трейс - используем более длинный путь
            if existing_trace_id in self._collected_traces:
                old_path, old_hash, old_cache = self._collected_traces[existing_trace_id]
                # Объединяем кэши кода
                merged_cache = {**old_cache, **code_cache}
                # Используем более длинный путь как основной
                final_hash = code_hash if code_hash else old_hash
                self._collected_traces[existing_trace_id] = (main_path, final_hash, merged_cache)
            
            logger.debug(f"Added path to existing trace {existing_trace_id} (code_hash: {code_hash[:8] if code_hash else 'none'}...), using path length: {len(main_path)} (was {len(existing_path)})")
        else:
            # Новый уникальный код - создаем новый трейс
            self._trace_counter += 1
            trace_id = self._trace_counter
            
            # Добавляем sink к новому трейсу
            if sink_uid:
                self._trace_sinks[trace_id].add(sink_uid)
            
            # Сохраняем хеш для будущих проверок
            if code_hash:
                path_tuple = tuple(path)
                self._code_hash_to_file[code_hash] = (trace_id, {path_tuple})
                # Обновляем индекс для быстрого поиска
                self._trace_id_to_hashes[trace_id].add(code_hash)
            
            # Сохраняем кэш кода
            if self.show_code:
                self._trace_code_cache[trace_id] = code_cache.copy()
            
            # Сохраняем трейс для последующего извлечения
            self._collected_traces[trace_id] = (path, code_hash, code_cache)
        
        # Обновляем прогресс-бар (перезаписываем строку на месте)
        self._update_progress()
    
    def get_trace_text(self, trace_id: int, nodes: Dict[str, Node], edge_sites: DefaultDict[Tuple[str, str], List[Tuple[str, int]]], show_code: bool = True) -> str:
        """Get trace text for a given trace_id."""
        if trace_id not in self._collected_traces:
            return ""
        
        path, code_hash, code_cache = self._collected_traces[trace_id]
        
        # Get additional sinks for this trace (excluding the one in path)
        additional_sinks = self._trace_sinks.get(trace_id, set()).copy()
        if path and path[-1] in additional_sinks:
            # Keep all sinks, including the one in path
            pass
        elif path and path[-1] in nodes and nodes[path[-1]].is_sink:
            # Add the sink from path to additional_sinks
            additional_sinks.add(path[-1])
        
        # Если нужно показать код, используем кэш
        if show_code and code_cache:
            return self._path_to_text(path, nodes, edge_sites, code_cache=code_cache, show_code=True, additional_sinks=additional_sinks if len(additional_sinks) > 1 else None)
        else:
            return self._path_to_text(path, nodes, edge_sites, code_cache=None, show_code=False, additional_sinks=additional_sinks if len(additional_sinks) > 1 else None)
    
    def get_all_trace_ids(self) -> List[int]:
        """Get all collected trace IDs."""
        return sorted(self._collected_traces.keys())
    
    def get_trace_path(self, trace_id: int) -> Optional[List[str]]:
        """Get trace path for a given trace_id."""
        if trace_id not in self._collected_traces:
            return None
        path, _, _ = self._collected_traces[trace_id]
        return path

    def reset_counter(self):
        """Сбрасывает счетчик найденных trace'ов"""
        self._traces_found = 0

    def get_traces_found(self) -> int:
        """Возвращает количество найденных trace'ов"""
        return self._traces_found