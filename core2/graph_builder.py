#!/usr/bin/env python3
"""Graph builder module: manages security graph construction and visualization."""
import shutil
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, DefaultDict
from collections import defaultdict
import logging

from ast_core import Node, Edge, normalize_callee
from sinks import KNOWN_SINKS
from trace_processor import TraceProcessor

logger = logging.getLogger(__name__)

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
                    color = "red" if (dst in self.nodes and self.nodes[dst].is_sink) else "#666666"
                    dot.edge(src, dst, color=color)

            dot.render(filename, view=False)
            logger.info(f"Graph saved to {filename}.png")
        except Exception as e:
            logger.error(f"Visualization error: {e}")