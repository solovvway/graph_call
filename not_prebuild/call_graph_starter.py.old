#!/usr/bin/env python3
"""
Starter implementation для Inter-Procedural Call Graph анализа
Language-agnostic, используя Tree-Sitter

Usage:
    python3 call_graph_starter.py --repo /path/to/repo --language python --output graph.json
"""

import os
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import logging

# Tree-Sitter парсинг
try:
    from tree_sitter import Language, Parser
except ImportError:
    print("Install tree-sitter: pip install tree-sitter")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class FunctionDefinition:
    """Определение функции"""
    name: str
    file: str
    line: int
    column: int
    signature: str = ""
    full_name: str = ""  # module.function_name

@dataclass
class FunctionCall:
    """Вызов функции"""
    caller_name: str
    callee_name: str
    file: str
    line: int
    column: int
    is_resolved: bool = False
    resolved_to: str = ""  # full_name разрешенной функции

# ============================================================================
# TREE-SITTER PARSER (Language-Agnostic)
# ============================================================================

class UniversalCodeParser:
    """
    Universal parser используя Tree-Sitter.
    Работает с любым языком, который поддерживает Tree-Sitter.
    """
    
    # Language-specific queries для извлечения функций
    FUNCTION_QUERIES = {
        "python": """
            (function_definition
              name: (identifier) @func_name) @func_def
        """,
        "javascript": """
            (function_declaration
              name: (identifier) @func_name) @func_def
            |
            (method_definition
              name: (property_identifier) @func_name) @func_def
        """,
        "java": """
            (method_declaration
              name: (identifier) @func_name) @func_def
        """,
        "go": """
            (function_declaration
              name: (identifier) @func_name) @func_def
        """,
    }
    
    # Queries для извлечения вызовов
    CALL_QUERIES = {
        "python": """
            (call
              function: (identifier) @callee) @call
            |
            (call
              function: (attribute
                object: (identifier)
                attribute: (identifier) @callee)) @call
        """,
        "javascript": """
            (call_expression
              function: (identifier) @callee) @call
            |
            (call_expression
              function: (member_expression
                object: (identifier)
                property: (identifier) @callee)) @call
        """,
        "java": """
            (method_invocation
              name: (identifier) @callee) @call
        """,
        "go": """
            (call_expression
              function: (identifier) @callee) @call
        """,
    }
    
    def __init__(self, language: str):
        """Инициализировать парсер для конкретного языка"""
        self.language_name = language
        self.parser = Parser()
        
        # Загрузить library для языка
        # Требует наличия libpython.so, libtree-sitter-javascript.so и т.д.
        try:
            lang_lib = Language(f"build/my-{language}.so", language)
            self.parser.set_language(lang_lib)
        except Exception as e:
            logger.warning(f"Could not load language library: {e}. Using generic parsing.")
            self.parser = None
    
    def parse_file(self, file_path: str) -> Tuple[List[FunctionDefinition], List[FunctionCall]]:
        """Распарсить файл и извлечь функции и вызовы"""
        
        with open(file_path, 'rb') as f:
            content = f.read()
        
        if self.parser is None:
            # Fallback: базовое регулярное выражение парсинг
            return self._parse_with_regex(file_path, content)
        
        tree = self.parser.parse(content)
        functions = self._extract_functions(tree, file_path, content)
        calls = self._extract_calls(tree, file_path, content)
        
        return functions, calls
    
    def _extract_functions(self, tree, file_path: str, content: bytes) -> List[FunctionDefinition]:
        """Извлечь все определения функций из дерева парсинга"""
        functions = []
        
        def traverse(node, file_bytes):
            # Ищем узлы, которые являются определениями функций
            if node.type in ["function_definition", "function_declaration", "method_declaration"]:
                func_name = None
                line = node.start_point[0]
                column = node.start_point[1]
                
                # Найти имя функции в дочерних узлах
                for child in node.children:
                    if child.type == "identifier":
                        func_name = file_bytes[child.start_byte:child.end_byte].decode('utf-8')
                        break
                
                if func_name:
                    functions.append(FunctionDefinition(
                        name=func_name,
                        file=file_path,
                        line=line,
                        column=column,
                        signature=self._extract_signature(node, file_bytes)
                    ))
            
            # Рекурсивно обойти дочерние узлы
            for child in node.children:
                traverse(child, file_bytes)
        
        traverse(tree.root_node, content)
        return functions
    
    def _extract_calls(self, tree, file_path: str, content: bytes) -> List[FunctionCall]:
        """Извлечь все вызовы функций из дерева парсинга"""
        calls = []
        current_function = "module_level"  # По умолчанию на уровне модуля
        
        def traverse(node, file_bytes, in_function=None):
            nonlocal current_function
            
            # Обновить текущую функцию контекст
            if node.type in ["function_definition", "function_declaration", "method_declaration"]:
                for child in node.children:
                    if child.type == "identifier":
                        current_function = file_bytes[child.start_byte:child.end_byte].decode('utf-8')
                        break
            
            # Ищем вызовы функций
            if node.type in ["call_expression", "call"]:
                callee_name = None
                
                # Найти имя вызываемой функции
                if node.child_by_field_name("function"):
                    func_node = node.child_by_field_name("function")
                    if func_node.type == "identifier":
                        callee_name = file_bytes[func_node.start_byte:func_node.end_byte].decode('utf-8')
                
                if callee_name:
                    calls.append(FunctionCall(
                        caller_name=current_function,
                        callee_name=callee_name,
                        file=file_path,
                        line=node.start_point[0],
                        column=node.start_point[1]
                    ))
            
            # Рекурсивно обойти дочерние узлы
            for child in node.children:
                traverse(child, file_bytes, current_function)
        
        traverse(tree.root_node, content)
        return calls
    
    def _extract_signature(self, func_node, content: bytes) -> str:
        """Извлечь сигнатуру функции (параметры)"""
        try:
            signature = content[func_node.start_byte:func_node.end_byte].decode('utf-8')
            # Обрезать до первой строки
            return signature.split('\n')[0][:100]
        except:
            return ""
    
    def _parse_with_regex(self, file_path: str, content: bytes) -> Tuple[List[FunctionDefinition], List[FunctionCall]]:
        """Fallback парсинг с помощью регулярных выражений"""
        import re
        
        content_str = content.decode('utf-8', errors='ignore')
        functions = []
        calls = []
        
        if self.language_name == "python":
            # Python функции
            for i, line in enumerate(content_str.split('\n'), 1):
                if line.strip().startswith('def '):
                    match = re.search(r'def\s+(\w+)\s*\(', line)
                    if match:
                        functions.append(FunctionDefinition(
                            name=match.group(1),
                            file=file_path,
                            line=i,
                            column=line.find('def')
                        ))
            
            # Python вызовы
            for i, line in enumerate(content_str.split('\n'), 1):
                matches = re.findall(r'(\w+)\s*\(', line)
                for match in matches:
                    calls.append(FunctionCall(
                        caller_name="unknown",
                        callee_name=match,
                        file=file_path,
                        line=i,
                        column=0
                    ))
        
        return functions, calls

# ============================================================================
# INTER-PROCEDURAL LINKER
# ============================================================================

class InterProceduralLinker:
    """
    Разрешить вызовы функций в их определения.
    Это ключевой компонент для построения IPCG.
    """
    
    def __init__(self):
        self.functions: Dict[str, FunctionDefinition] = {}  # {full_name: FunctionDefinition}
        self.module_exports: Dict[str, Set[str]] = defaultdict(set)  # {module: {exported_names}}
        self.resolved_edges: List[Tuple[str, str]] = []  # [(caller, callee_full_name)]
    
    def register_functions(self, functions: List[FunctionDefinition]):
        """Зарегистрировать все найденные функции в глобальной таблице символов"""
        for func in functions:
            # Создать fully qualified name
            module = self._get_module_name(func.file)
            func.full_name = f"{module}.{func.name}"
            
            self.functions[func.full_name] = func
            self.module_exports[module].add(func.name)
    
    def resolve_calls(self, calls: List[FunctionCall]) -> List[Tuple[str, str]]:
        """
        Разрешить все вызовы в их определения.
        Возвращает список (caller_full_name, callee_full_name).
        """
        resolved_edges = []
        unresolved = []
        
        for call in calls:
            # Попробовать разрешить вызов
            caller_module = self._get_module_name(call.file)
            caller_full_name = f"{caller_module}.{call.caller_name}"
            
            # Кандидаты на разрешение (в порядке приоритета)
            candidates = [
                f"{caller_module}.{call.callee_name}",  # Локальная область видимости
                call.callee_name,  # Глобальная область видимости (builtin)
                f"builtins.{call.callee_name}",  # Built-in функции
            ]
            
            resolved = False
            for candidate in candidates:
                if candidate in self.functions:
                    resolved_edges.append((caller_full_name, candidate))
                    resolved = True
                    break
            
            if not resolved:
                unresolved.append((call.caller_name, call.callee_name))
        
        if unresolved:
            logger.info(f"Could not resolve {len(unresolved)} calls (may be dynamic, external, or builtins)")
        
        return resolved_edges
    
    @staticmethod
    def _get_module_name(file_path: str) -> str:
        """Получить имя модуля из пути файла"""
        # file_path: "/path/to/repo/app/models/user.py"
        # module: "app.models.user"
        
        path = Path(file_path)
        
        # Удалить расширение файла
        parts = list(path.parts)
        if parts[-1].endswith(('.py', '.js', '.java', '.go')):
            parts[-1] = parts[-1].rsplit('.', 1)[0]
        
        # Вернуть относительный путь как модуль
        return '.'.join(parts[-3:]) if len(parts) >= 3 else '.'.join(parts)

# ============================================================================
# CALL GRAPH BUILDER
# ============================================================================

class CallGraphBuilder:
    """
    Построить граф вызовов на основе разрешенных вызовов.
    Выходной формат - JSON для дальнейшей обработки.
    """
    
    def __init__(self):
        self.functions: Dict[str, FunctionDefinition] = {}
        self.edges: List[Dict] = []
        self.call_counts: Dict[str, int] = defaultdict(int)  # Сколько раз каждая функция вызывается
    
    def add_functions(self, functions: List[FunctionDefinition]):
        """Добавить определения функций в граф"""
        for func in functions:
            self.functions[func.full_name] = func
    
    def add_edge(self, caller: str, callee: str, line: int):
        """Добавить ребро вызова в граф"""
        self.edges.append({
            "from": caller,
            "to": callee,
            "line": line,
            "type": "direct_call"
        })
        self.call_counts[callee] += 1
    
    def find_sources_for_sink(self, sink_name: str, max_depth: int = 10) -> List[List[str]]:
        """
        Найти все цепочки вызовов от sources к sink.
        
        Source: функции, которые не имеют входящих вызовов (entry points)
        Sink: заданная функция
        
        Возвращает список цепочек вызовов.
        """
        
        # Найти все incoming edges
        incoming = defaultdict(list)
        for edge in self.edges:
            incoming[edge["to"]].append(edge["from"])
        
        # Найти entry points (функции без входящих вызовов)
        all_functions = set(self.functions.keys())
        called_functions = set(edge["to"] for edge in self.edges)
        entry_points = all_functions - called_functions
        
        logger.info(f"Found {len(entry_points)} entry points")
        
        # BFS для поиска всех путей от entry points к sink
        paths = []
        
        def bfs(source: str, target: str):
            queue = [(source, [source])]
            visited = set()
            found_paths = []
            
            while queue:
                current, path = queue.pop(0)
                
                if current == target:
                    found_paths.append(path)
                    continue
                
                if len(path) > max_depth or current in visited:
                    continue
                
                visited.add(current)
                
                # Найти всех, кого вызывает current
                for edge in self.edges:
                    if edge["from"] == current and edge["to"] not in visited:
                        queue.append((edge["to"], path + [edge["to"]]))
            
            return found_paths
        
        # Поиск из каждого entry point
        for entry in entry_points:
            paths.extend(bfs(entry, sink_name))
        
        return paths
    
    def find_all_callers(self, func_name: str) -> List[str]:
        """Найти все функции, которые прямо вызывают func_name"""
        callers = set()
        for edge in self.edges:
            if edge["to"] == func_name:
                callers.add(edge["from"])
        return list(callers)
    
    def to_json(self) -> Dict:
        """Экспортировать граф в JSON"""
        return {
            "functions": {
                name: asdict(func) for name, func in self.functions.items()
            },
            "edges": self.edges,
            "call_counts": dict(self.call_counts),
            "statistics": {
                "total_functions": len(self.functions),
                "total_edges": len(self.edges),
                "entry_points": len([f for f in self.functions if self.call_counts[f] == 0])
            }
        }

# ============================================================================
# MAIN ANALYZER
# ============================================================================

class RepositoryAnalyzer:
    """Основной анализатор репозитория"""
    
    def __init__(self, repo_path: str, language: str):
        self.repo_path = repo_path
        self.language = language
        self.parser = UniversalCodeParser(language)
        self.linker = InterProceduralLinker()
        self.graph = CallGraphBuilder()
    
    def analyze(self) -> Dict:
        """Проанализировать весь репозиторий"""
        
        logger.info(f"Analyzing {self.repo_path} ({self.language})")
        
        # Phase 1: Парсинг всех файлов
        all_functions = []
        all_calls = []
        
        file_extensions = {
            "python": ".py",
            "javascript": ".js",
            "java": ".java",
            "go": ".go",
        }
        
        extension = file_extensions.get(self.language, ".py")
        
        for file_path in Path(self.repo_path).rglob(f"*{extension}"):
            logger.debug(f"Parsing {file_path}")
            try:
                functions, calls = self.parser.parse_file(str(file_path))
                all_functions.extend(functions)
                all_calls.extend(calls)
            except Exception as e:
                logger.warning(f"Error parsing {file_path}: {e}")
        
        logger.info(f"Found {len(all_functions)} functions and {len(all_calls)} calls")
        
        # Phase 2: Register functions and resolve calls
        self.linker.register_functions(all_functions)
        resolved_edges = self.linker.resolve_calls(all_calls)
        
        logger.info(f"Resolved {len(resolved_edges)} calls")
        
        # Phase 3: Build graph
        self.graph.add_functions(all_functions)
        for caller, callee in resolved_edges:
            # Find line number
            line = next((call.line for call in all_calls if call.callee_name in callee), 0)
            self.graph.add_edge(caller, callee, line)
        
        return self.graph.to_json()

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Build Inter-Procedural Call Graph")
    parser.add_argument("--repo", required=True, help="Path to repository")
    parser.add_argument("--language", default="python", choices=["python", "javascript", "java", "go"])
    parser.add_argument("--output", default="call_graph.json", help="Output JSON file")
    parser.add_argument("--find-sink", help="Find all sources for a given sink function")
    
    args = parser.parse_args()
    
    # Analyze
    analyzer = RepositoryAnalyzer(args.repo, args.language)
    graph_data = analyzer.analyze()
    
    # Find sources for sink if requested
    if args.find_sink:
        sources = analyzer.graph.find_sources_for_sink(args.find_sink)
        logger.info(f"\nFound {len(sources)} paths to {args.find_sink}:")
        for i, path in enumerate(sources[:5], 1):  # Show first 5
            logger.info(f"  {i}. {' → '.join(path)}")
    
    # Save to file
    with open(args.output, 'w') as f:
        json.dump(graph_data, f, indent=2)
    
    logger.info(f"Graph saved to {args.output}")

if __name__ == "__main__":
    main()
