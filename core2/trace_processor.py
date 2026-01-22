#!/usr/bin/env python3
"""Trace processor module: handles trace processing, deduplication, and output."""
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, DefaultDict
from collections import defaultdict
import logging

from ast_core import Node

logger = logging.getLogger(__name__)

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
        
        # Store function code separately to avoid duplication
        # Maps: trace_id -> {uid: code}
        self._trace_code_cache: Dict[int, Dict[str, str]] = {}
        
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

    def _path_to_yaml(self, path: List[str], nodes: Dict[str, Node], edge_sites: DefaultDict[Tuple[str, str], List[Tuple[str, int]]], code_cache: Optional[Dict[str, str]] = None, indent: int = 0, show_code: bool = True) -> str:
        """Generate YAML representation of path with nested function calls.
        
        Args:
            show_code: If False, skip code blocks even if code_cache is provided
        """
        if not path:
            return ""
        
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
        if show_code and code_cache and uid in code_cache:
            code = code_cache[uid]
            if code:
                # Escape code for YAML (use literal block scalar)
                code_lines = code.split('\n')
                out.append(f"{indent_str}  code: |")
                for line in code_lines:
                    out.append(f"{indent_str}    {line}")
        
        # If there are more functions in path, add them as nested calls
        if len(path) > 1:
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
            nested = self._path_to_yaml(path[1:], nodes, edge_sites, code_cache, indent + 1, show_code=show_code)
            if nested:
                out.append(nested)
        
        return "\n".join(out)
    
    def _path_to_text(self, path: List[str], nodes: Dict[str, Node], edge_sites: DefaultDict[Tuple[str, str], List[Tuple[str, int]]], code_cache: Optional[Dict[str, str]] = None, show_code: bool = True) -> str:
        """Generate YAML representation of path."""
        return self._path_to_yaml(path, nodes, edge_sites, code_cache, indent=0, show_code=show_code)

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
            
            # Build code cache for this path (only for functions, not sinks)
            code_cache: Dict[str, str] = {}
            if self.show_code:
                for uid in path:
                    if uid not in code_cache:
                        code = self._node_code(nodes, uid)
                        if code:
                            code_cache[uid] = code
            
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
                    
                    # Обновляем кэш кода - добавляем только новые функции
                    if existing_trace_id in self._trace_code_cache:
                        existing_code_cache = self._trace_code_cache[existing_trace_id]
                        # Добавляем только код функций, которых еще нет
                        for uid, code in code_cache.items():
                            if uid not in existing_code_cache:
                                existing_code_cache[uid] = code
                    else:
                        self._trace_code_cache[existing_trace_id] = code_cache.copy()
                    
                    # Читаем существующий файл и добавляем новый путь
                    txt_file = self.out_dir / f"{existing_trace_id}.txt"
                    code_file = self.out_dir / f"{existing_trace_id}_code.txt"
                    
                    # Получаем полный кэш кода для этого trace
                    full_code_cache = self._trace_code_cache.get(existing_trace_id, {})
                    
                    # Добавляем новый путь в текстовый файл (без кода)
                    if txt_file.exists():
                        existing_content = txt_file.read_text(encoding="utf-8", errors="ignore")
                        new_path_text = self._path_to_text(path, nodes, edge_sites, code_cache=None, show_code=False)
                        # Добавляем разделитель и новый путь
                        updated_content = existing_content + "\n\n---\n\n" + new_path_text
                        txt_file.write_text(updated_content, encoding="utf-8", errors="ignore")
                    else:
                        # Если файл почему-то не существует, создаем заново
                        txt_file.write_text(
                            self._path_to_text(path, nodes, edge_sites, code_cache=None, show_code=False),
                            encoding="utf-8", errors="ignore"
                        )
                    
                    # Обновляем файл с кодом (только если show_code=True)
                    # Для первого пути показываем код, для остальных - только структуру
                    if self.show_code:
                        all_paths = list(existing_paths)
                        all_paths_text = []
                        for idx, p in enumerate(all_paths):
                            # Первый путь - с кодом, остальные - без кода
                            show_code_for_path = (idx == 0)
                            all_paths_text.append(
                                self._path_to_text(list(p), nodes, edge_sites, code_cache=full_code_cache, show_code=show_code_for_path)
                            )
                        
                        code_file.write_text(
                            "\n\n---\n\n".join(all_paths_text),
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
                
                # Сохраняем кэш кода
                if self.show_code:
                    self._trace_code_cache[trace_id] = code_cache.copy()
                
                # Создаем файл без кода
                (self.out_dir / f"{trace_id}.txt").write_text(
                    self._path_to_text(path, nodes, edge_sites, code_cache=None),
                    encoding="utf-8", errors="ignore"
                )
                
                # Создаем файл с кодом только если show_code=True
                if self.show_code:
                    (self.out_dir / f"{trace_id}_code.txt").write_text(
                        self._path_to_text(path, nodes, edge_sites, code_cache=code_cache),
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