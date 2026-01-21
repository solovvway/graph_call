#!/usr/bin/env python3
"""
Скрипт для парсинга репозитория и создания графа кода в Neo4j.
Использует CodeParser из auditor.py для извлечения AST.
"""

import os
import sys
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

# Добавляем родительскую директорию в путь для импорта auditor
sys.path.insert(0, str(Path(__file__).parent.parent))

from auditor import CodeParser, Node, Edge, EXT_TO_LANG, normalize_callee, KNOWN_SINKS
from ast_logger import ASTLogger

try:
    from neo4j import GraphDatabase
except ImportError:
    print("CRITICAL: Missing neo4j library. Run: pip install neo4j")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


class Neo4jGraphBuilder:
    """Класс для создания графа кода в Neo4j."""
    
    def __init__(self, uri: str, user: str, password: str):
        logger.info(f"Connecting to Neo4j at {uri}...")
        try:
            # Use IPv4 explicitly if localhost is used to avoid IPv6 timeout issues
            if "localhost" in uri and "127.0.0.1" not in uri:
                uri = uri.replace("localhost", "127.0.0.1")
                logger.info(f"Using IPv4 address: {uri}")
            
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(
                uri, 
                auth=(user, password),
                connection_timeout=30,  # 30 seconds timeout
                max_connection_lifetime=3600
            )
            # Verify connection immediately
            self.verify_connectivity()
            logger.info("Successfully connected to Neo4j")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            logger.error(f"Make sure Neo4j is running. Try: cd neo4j && docker-compose up -d")
            logger.error(f"Check Neo4j logs: cd neo4j && docker-compose logs neo4j")
            raise
        self.nodes_created: Set[str] = set()
        self.edges_created: Set[Tuple[str, str]] = set()
    
    def verify_connectivity(self):
        """Проверяет соединение с Neo4j."""
        try:
            with self.driver.session() as session:
                session.run("RETURN 1").single()
        except Exception as e:
            logger.error(f"Connection verification failed: {e}")
            raise
    
    def close(self):
        """Закрывает соединение с Neo4j."""
        if self.driver:
            self.driver.close()
    
    def clear_database(self):
        """Очищает базу данных Neo4j."""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            logger.info("Database cleared")
    
    def create_node(self, node: Node, lang: str):
        """Создает узел в Neo4j."""
        if node.uid in self.nodes_created:
            # Обновляем существующий узел
            with self.driver.session() as session:
                session.run("""
                    MATCH (n {uid: $uid})
                    SET n.is_entry = n.is_entry OR $is_entry,
                        n.is_sink = n.is_sink OR $is_sink,
                        n.is_source = n.is_source OR $is_source,
                        n.is_builtin = n.is_builtin OR $is_builtin,
                        n.end_line = CASE 
                            WHEN $end_line > n.end_line THEN $end_line 
                            ELSE n.end_line 
                        END,
                        n.line = CASE 
                            WHEN n.line = 0 OR ($line > 0 AND $line < n.line) THEN $line 
                            ELSE n.line 
                        END
                """, uid=node.uid, is_entry=node.is_entry, is_sink=node.is_sink,
                    is_source=node.is_source, is_builtin=node.is_builtin,
                    end_line=node.end_line, line=node.line)
            return
        
        self.nodes_created.add(node.uid)
        
        with self.driver.session() as session:
            session.run("""
                CREATE (n:Function {
                    uid: $uid,
                    name: $name,
                    file: $file,
                    line: $line,
                    end_line: $end_line,
                    is_entry: $is_entry,
                    is_sink: $is_sink,
                    is_source: $is_source,
                    is_builtin: $is_builtin,
                    language: $language
                })
            """, uid=node.uid, name=node.name, file=node.file,
                line=node.line, end_line=node.end_line,
                is_entry=node.is_entry, is_sink=node.is_sink,
                is_source=node.is_source, is_builtin=node.is_builtin,
                language=lang)
    
    def create_edge(self, src_uid: str, dst_uid: str, file: str, line: int, lang: str):
        """Создает ребро (вызов функции) в Neo4j."""
        # Убеждаемся, что оба узла существуют
        if src_uid not in self.nodes_created:
            logger.warning(f"Source node {src_uid} not found, skipping edge")
            return
        if dst_uid not in self.nodes_created:
            logger.warning(f"Destination node {dst_uid} not found, skipping edge")
            return
        
        edge_key = (src_uid, dst_uid)
        if edge_key in self.edges_created:
            # Обновляем существующее ребро, добавляя новое место вызова
            with self.driver.session() as session:
                # Проверяем, существует ли уже такой callsite
                result = session.run("""
                    MATCH (src {uid: $src_uid})-[r:CALLS]->(dst {uid: $dst_uid})
                    RETURN r.callsites as callsites
                """, src_uid=src_uid, dst_uid=dst_uid)
                record = result.single()
                if record:
                    callsites = record["callsites"] or []
                    callsite_str = f"{file}:{line}"
                    if callsite_str not in callsites:
                        callsites.append(callsite_str)
                        session.run("""
                            MATCH (src {uid: $src_uid})-[r:CALLS]->(dst {uid: $dst_uid})
                            SET r.callsites = $callsites
                        """, src_uid=src_uid, dst_uid=dst_uid, callsites=callsites)
            return
        
        self.edges_created.add(edge_key)
        
        with self.driver.session() as session:
            session.run("""
                MATCH (src {uid: $src_uid}), (dst {uid: $dst_uid})
                CREATE (src)-[r:CALLS {
                    file: $file,
                    line: $line,
                    language: $language,
                    callsites: [$callsite]
                }]->(dst)
            """, src_uid=src_uid, dst_uid=dst_uid, file=file, line=line,
                language=lang, callsite=f"{file}:{line}")
    
    def ensure_node_exists(self, uid: str, name: str, lang: str, is_sink: bool = False, is_builtin: bool = False):
        """Убеждается, что узел существует (создает если нет)."""
        if uid in self.nodes_created:
            return
        
        self.nodes_created.add(uid)
        
        with self.driver.session() as session:
            session.run("""
                CREATE (n:Function {
                    uid: $uid,
                    name: $name,
                    file: $file,
                    line: 0,
                    end_line: 0,
                    is_entry: false,
                    is_sink: $is_sink,
                    is_source: false,
                    is_builtin: $is_builtin,
                    language: $language
                })
            """, uid=uid, name=name, file="<builtin>" if is_builtin else "<external>",
                is_sink=is_sink, is_builtin=is_builtin, language=lang)
    
    def add_edge_with_resolution(self, caller_uid: str, callee_name: str, lang: str, file: str, line: int):
        """Добавляет ребро с разрешением имени функции в UID."""
        # Убеждаемся, что вызывающий узел существует
        if caller_uid not in self.nodes_created:
            logger.debug(f"Caller node {caller_uid} not found, skipping edge")
            return
        
        sinks = KNOWN_SINKS.get(lang, set())
        callee_norm = normalize_callee(callee_name)
        
        is_sink = (callee_norm in sinks) or any(callee_norm.endswith("." + s) for s in sinks)
        
        if is_sink:
            target_uid = f"builtin.{lang}.{callee_norm}"
            self.ensure_node_exists(target_uid, callee_norm, lang, is_sink=True, is_builtin=True)
        else:
            target_uid = None
            
            # Попытка найти локальную функцию
            if "." not in callee_norm:
                caller_mod = caller_uid.rsplit(".", 1)[0]
                candidate_local = f"{caller_mod}.{callee_norm}"
                if candidate_local in self.nodes_created:
                    target_uid = candidate_local
            
            # Поиск по имени функции
            if not target_uid:
                # Нужно найти в базе данных
                with self.driver.session() as session:
                    result = session.run("""
                        MATCH (n:Function)
                        WHERE n.name = $name AND n.language = $lang
                        RETURN n.uid as uid
                        LIMIT 1
                    """, name=callee_norm.split(".")[-1], lang=lang)
                    record = result.single()
                    if record:
                        target_uid = record["uid"]
            
            if not target_uid:
                target_uid = f"ext.{lang}.{callee_norm}"
                self.ensure_node_exists(target_uid, callee_norm, lang, is_builtin=True)
        
        self.create_edge(caller_uid, target_uid, file, line, lang)
    
    def create_indexes(self):
        """Создает индексы для ускорения запросов."""
        with self.driver.session() as session:
            # Индекс по uid (уникальный идентификатор)
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:Function) ON (n.uid)")
            # Индекс по имени функции
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:Function) ON (n.name)")
            # Индекс по языку
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:Function) ON (n.language)")
            # Индекс по файлу
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:Function) ON (n.file)")
            logger.info("Indexes created")


def parse_repository(repo: Path, builder: Neo4jGraphBuilder, clear_db: bool = False):
    """Парсит репозиторий и создает граф в Neo4j."""
    
    if clear_db:
        builder.clear_database()
    
    builder.create_indexes()
    
    files_map: Dict[str, List[Path]] = defaultdict(list)
    
    for root, _, files in os.walk(repo):
        for f in files:
            ext = Path(f).suffix.lower()
            if ext in EXT_TO_LANG:
                files_map[EXT_TO_LANG[ext]].append(Path(root) / f)
    
    all_raw_edges: List[Tuple[Edge, str]] = []
    all_nodes: List[Tuple[Node, str]] = []
    
    # Используем ASTLogger для логирования
    ast_logger = ASTLogger(ASTLogger.calculate_total_files(files_map))
    
    for lang, paths in files_map.items():
        logger.info(f"Analyzing {len(paths)} {lang} files...")
        parser_eng = CodeParser(lang, repo_root=repo)
        
        ast_logger.init_progress(lang)
        
        for p in paths:
            try:
                content = p.read_bytes()
                nodes, edges = parser_eng.parse_file(p, content)
                
                for n in nodes:
                    all_nodes.append((n, lang))
                
                for e in edges:
                    all_raw_edges.append((e, lang))
                
                ast_logger.increment()
                ast_logger.update_progress(lang)
                
            except Exception as e:
                logger.debug(f"Failed reading/parsing {p}: {e}")
                ast_logger.increment()
                ast_logger.update_progress(lang)
        
        ast_logger.finish()
    
    logger.info(f"Creating {len(all_nodes)} nodes in Neo4j...")
    for node, lang in all_nodes:
        builder.create_node(node, lang)
    
    logger.info(f"Creating {len(all_raw_edges)} edges in Neo4j...")
    for edge, lang in all_raw_edges:
        builder.add_edge_with_resolution(edge.src, edge.dst, lang, edge.file, edge.line)
    
    logger.info("Graph creation completed!")


def main():
    ap = argparse.ArgumentParser(description="Parse repository and create code graph in Neo4j")
    ap.add_argument("--repo", required=True, help="Path to repository")
    ap.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI (default: bolt://localhost:7687)")
    ap.add_argument("--user", default="neo4j", help="Neo4j username (default: neo4j)")
    ap.add_argument("--password", default="password", help="Neo4j password (default: password)")
    ap.add_argument("--clear", action="store_true", help="Clear database before importing")
    
    args = ap.parse_args()
    
    repo = Path(args.repo).resolve()
    if not repo.exists():
        print(f"Repo not found: {repo}")
        sys.exit(2)
    
    builder = Neo4jGraphBuilder(args.uri, args.user, args.password)
    
    try:
        parse_repository(repo, builder, clear_db=args.clear)
    finally:
        builder.close()


if __name__ == "__main__":
    main()
