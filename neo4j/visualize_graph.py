#!/usr/bin/env python3
import sys
from pathlib import Path
from collections import deque
from neo4j import GraphDatabase
from pyvis.network import Network
import networkx as nx

def calculate_hierarchy_levels(G):
    """Вычисляет уровни иерархии для узлов на основе entry points"""
    levels = {}
    
    # Находим все entry points (узлы без входящих рёбер или помеченные как entry)
    entry_points = []
    for node, data in G.nodes(data=True):
        if data.get('is_entry', False) or G.in_degree(node) == 0:
            entry_points.append(node)
    
    # Если нет явных entry points, используем узлы без входящих рёбер
    if not entry_points:
        entry_points = [node for node in G.nodes() if G.in_degree(node) == 0]
    
    # Если всё ещё нет, используем все узлы с минимальным количеством входящих рёбер
    if not entry_points:
        min_in_degree = min(G.in_degree(node) for node in G.nodes()) if G.nodes() else 0
        entry_points = [node for node in G.nodes() if G.in_degree(node) == min_in_degree]
    
    # BFS для вычисления уровней от entry points
    queue = deque()
    visited = set()
    
    for entry in entry_points:
        levels[entry] = 0
        queue.append(entry)
        visited.add(entry)
    
    while queue:
        current = queue.popleft()
        current_level = levels[current]
        
        # Обрабатываем всех потомков
        for neighbor in G.successors(current):
            if neighbor not in visited:
                # Уровень потомка = уровень родителя + 1
                # Если узел уже имеет уровень, берём минимальный
                if neighbor in levels:
                    levels[neighbor] = min(levels[neighbor], current_level + 1)
                else:
                    levels[neighbor] = current_level + 1
                
                queue.append(neighbor)
                visited.add(neighbor)
            else:
                # Если узел уже посещён, обновляем уровень если нужно
                if neighbor in levels:
                    levels[neighbor] = min(levels[neighbor], current_level + 1)
    
    # Для узлов, которые не были достигнуты (изолированные компоненты)
    for node in G.nodes():
        if node not in levels:
            levels[node] = max(levels.values()) + 1 if levels else 0
    
    return levels

def visualize_call_graph(uri="bolt://localhost:7687", user="neo4j", password="password"):
    driver = GraphDatabase.driver(uri, auth=(user, password))
    
    with driver.session() as session:
        result = session.run("""
            MATCH (n:Function)
            WITH n, COUNT {(n)-[:CALLS]->()} as call_count
            RETURN n.uid, n.name, n.is_entry, n.is_sink, call_count
            ORDER BY call_count DESC
        """)
        
        nodes = {}
        for record in result:
            nodes[record['n.uid']] = {
                'name': record['n.name'],
                'is_entry': record['n.is_entry'],
                'is_sink': record['n.is_sink'],
                'call_count': record['call_count'] or 0
            }
        
        result = session.run("""
            MATCH (src:Function)-[:CALLS]->(dst:Function)
            RETURN src.uid, dst.uid
        """)
        
        edges = [(r['src.uid'], r['dst.uid']) for r in result]
    
    driver.close()
    
    print(f"📊 Загружено узлов: {len(nodes)}")
    print(f"📊 Загружено рёбер: {len(edges)}")
    
    if not nodes:
        print("❌ Граф пуст! Проверьте Neo4j базу данных.")
        return
    
    # Создаём граф NetworkX
    G = nx.DiGraph()
    for uid, data in nodes.items():
        G.add_node(uid, **data)
    G.add_edges_from(edges)
    
    # Вычисляем уровни иерархии
    hierarchy_levels = calculate_hierarchy_levels(G)
    max_level = max(hierarchy_levels.values()) if hierarchy_levels else 0
    print(f"🌳 Уровней иерархии: {max_level + 1}")
    
    # Создаём Pyvis сеть с правильными параметрами
    net = Network(height="1200px", width="100%", directed=True, notebook=False)
    
    # Добавляем узлы с цветом в зависимости от типа и уровнем иерархии
    for node, data in G.nodes(data=True):
        call_count = data['call_count']
        is_entry = data['is_entry']
        is_sink = data['is_sink']
        level = hierarchy_levels.get(node, 0)
        
        # Выбираем цвет в зависимости от роли функции
        if is_entry:
            color = '#00FF00'  # Зелёный для entry points
            title = f"{data['name']}\n(Entry Point, Уровень {level})\nВызывает: {call_count} функций"
        elif is_sink:
            color = '#FF0000'  # Красный для sinks
            title = f"{data['name']}\n(Sink, Уровень {level})\nВызывает: {call_count} функций"
        else:
            # Градация по количеству вызовов
            if call_count > 5:
                color = '#FFA500'  # Оранжевый для часто вызываемых
            else:
                color = '#87CEEB'  # Голубой для остальных
            title = f"{data['name']}\n(Уровень {level})\nВызывает: {call_count} функций"
        
        size = min(20 + call_count * 3, 50)
        
        # Устанавливаем y-позицию на основе уровня иерархии
        # Уровень 0 вверху, чем ниже уровень, тем ниже позиция
        y_pos = level * 150  # Расстояние между уровнями
        
        net.add_node(
            node,
            label=data['name'],
            title=title,
            color=color,
            size=size,
            level=level,
            y=y_pos
        )
    
    # Добавляем рёбра
    for src, dst in G.edges():
        net.add_edge(src, dst, arrows='to', width=1.5)
    
    # Генерируем HTML напрямую (исправление ошибки с шаблоном)
    net.write_html('callgraph.html')
    
    # Читаем сгенерированный HTML и добавляем конфиг для иерархического layout
    with open('callgraph.html', 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Конфигурация для иерархического layout (дерево сверху вниз)
    physics_config = """
    var options = {
        layout: {
            hierarchical: {
                enabled: true,
                direction: 'UD',
                sortMethod: 'directed',
                levelSeparation: 200,
                nodeSpacing: 150,
                treeSpacing: 200,
                blockShifting: true,
                edgeMinimization: true,
                parentCentralization: true,
                shakeTowards: 'leaves'
            }
        },
        physics: {
            enabled: false
        },
        edges: {
            smooth: {
                type: 'vertical',
                roundness: 0
            }
        },
        interaction: {
            dragNodes: true,
            dragView: true,
            zoomView: true
        }
    };
    network.setOptions(options);
    """
    
    # Вставляем конфиг в HTML
    # Ищем место где создаётся network и добавляем конфигурацию после инициализации
    if 'var network = new vis.Network' in html_content:
        # Находим строку с созданием network и добавляем setOptions после неё
        lines = html_content.split('\n')
        new_lines = []
        for i, line in enumerate(lines):
            new_lines.append(line)
            if 'var network = new vis.Network' in line and i + 1 < len(lines):
                # Добавляем конфигурацию на следующей строке
                indent = '    '  # Базовый отступ
                config_lines = physics_config.strip().split('\n')
                for config_line in config_lines:
                    new_lines.append(indent + config_line)
        html_content = '\n'.join(new_lines)
    elif 'network.setOptions' in html_content:
        # Если уже есть setOptions, заменяем его
        import re
        pattern = r'network\.setOptions\([^)]*\);'
        html_content = re.sub(pattern, physics_config.strip(), html_content)
    else:
        # Ищем последний </script> перед </body> и вставляем перед ним
        last_script_pos = html_content.rfind('</script>', 0, html_content.rfind('</body>'))
        if last_script_pos != -1:
            html_content = html_content[:last_script_pos] + physics_config.strip() + '\n    ' + html_content[last_script_pos:]
    
    # Сохраняем обновленный HTML
    with open('callgraph.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("✅ Граф сохранён в callgraph.html")
    print("🌐 Откройте файл в браузере")
    print("\n💡 Граф отображается в виде дерева (сверху вниз):")
    print("   - Entry points находятся наверху")
    print("   - Вызываемые функции расположены ниже")
    print("   - Используйте скролл для увеличения/уменьшения")
    print("   - Перетаскивайте узлы для перемещения")
    print("   - Наводите на узлы для просмотра информации")

if __name__ == "__main__":
    visualize_call_graph()
