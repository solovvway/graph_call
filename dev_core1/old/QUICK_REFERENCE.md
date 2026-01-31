# Quick Reference Guide

## Быстрая справка по Call Graph анализу

### Основные концепции в одном месте

\`\`\`
SOURCE (Entry Point)          INTERMEDIATE CALLS         SINK (Vulnerable Function)
        ↓                            ↓                              ↓
    route handler ──→  authenticate() ──→  database.query()
    GET /api/users      (verify_token)     SQL INJECTION!
                         |
                         ├─→ service.getUser()
                         └─→ database.connect()
\`\`\`

---

## Быстрый старт (5 минут)

### 1. Установка

\`\`\`bash
pip install tree-sitter neo4j pyyaml
python3 -m pip install tree-sitter-python  # Для Python анализа
\`\`\`

### 2. Запуск анализа

\`\`\`bash
python3 call_graph_starter.py \\
  --repo /path/to/code \\
  --language python \\
  --output graph.json
\`\`\`

### 3. Поиск уязвимостей

\`\`\`bash
python3 call_graph_starter.py \\
  --repo /path/to/code \\
  --language python \\
  --find-sink "database.query"
\`\`\`

### 4. Результат

\`\`\`
Found 2 paths to database.query:
  1. route[GET /users] → getUserHandler → service.get_user → database.query
  2. route[POST /create] → createHandler → service.create → database.query
\`\`\`

---

## Архитектура в 5 блоков

### Block 1: Парсинг
\`\`\`python
from tree_sitter import Language, Parser

parser = Parser()
lang = Language("build/my-python.so", "python")
parser.set_language(lang)

tree = parser.parse(content)
# Результат: AST синтаксического дерева
\`\`\`

### Block 2: Извлечение функций и вызовов
\`\`\`python
parser = UniversalCodeParser("python")
functions, calls = parser.parse_file("app.py")

# functions: [FunctionDef("getUserHandler", line=10), ...]
# calls: [Call("getUserHandler", "getUser", line=15), ...]
\`\`\`

### Block 3: Разрешение вызовов (межфайловое связывание)
\`\`\`python
linker = InterProceduralLinker()
linker.register_functions(all_functions)
resolved = linker.resolve_calls(all_calls)

# resolved: [(caller_full_name, callee_full_name), ...]
# Теперь знаем где каждая функция определена
\`\`\`

### Block 4: Построение графа
\`\`\`python
graph = CallGraphBuilder()
graph.add_functions(all_functions)

for caller, callee in resolved:
    graph.add_edge(caller, callee, line_number)

# Получить пути от source к sink
paths = graph.find_sources_for_sink("database.query")
\`\`\`

### Block 5: Хранение в БД (optional)
\`\`\`cypher
# Cypher query в Memgraph/Neo4j
MATCH path = (source:Function)-[:CALLS*1..5]->(sink:Function {name: 'query'})
WHERE NOT (sink)-[:CALLS]->()  # Это может быть entry point
RETURN path
\`\`\`

---

## Главные вызовы API

### Класс: UniversalCodeParser

\`\`\`python
parser = UniversalCodeParser("python")

# Распарсить файл
functions, calls = parser.parse_file("app.py")
# → (List[FunctionDefinition], List[FunctionCall])
\`\`\`

### Класс: InterProceduralLinker

\`\`\`python
linker = InterProceduralLinker()

# Зарегистрировать все функции
linker.register_functions(functions)

# Разрешить вызовы в их определения
resolved_edges = linker.resolve_calls(calls)
# → List[Tuple[str, str]]  # (caller_full_name, callee_full_name)
\`\`\`

### Класс: CallGraphBuilder

\`\`\`python
graph = CallGraphBuilder()

# Добавить функции и вызовы
graph.add_functions(functions)
graph.add_edge("module.func1", "module.func2", line=10)

# Найти sources для sink
paths = graph.find_sources_for_sink("database.execute")
# → List[List[str]]  # Цепочки вызовов

# Найти direct callers
callers = graph.find_all_callers("delete_user")
# → List[str]

# Экспортировать в JSON
data = graph.to_json()
\`\`\`

---

## Типичные source-sink пары для веб приложений

### Flask/Django (Python)

| Source | Sink | Vulnerability |
|--------|------|---|
| \`request.json\` | \`db.query(f"...")\` | SQL Injection |
| \`request.args\` | \`eval()\` | Code Injection |
| \`request.form\` | \`os.system()\` | Command Injection |
| \`request.headers\` | \`render_template()\` | Template Injection |
| \`request.files\` | \`pickle.loads()\` | Deserialization |

### Express/Koa (JavaScript)

| Source | Sink | Vulnerability |
|--------|------|---|
| \`req.body\` | \`db.query()\` | SQL Injection |
| \`req.query\` | \`res.send()\` | XSS |
| \`req.params\` | \`child_process.exec()\` | Command Injection |
| \`req.headers\` | \`eval()\` | Code Injection |
| \`req.files\` | \`fs.readFile()\` | Path Traversal |

---

## Чек-лист перед production

- [ ] Поддерживаются все языки в проекте
- [ ] Обработаны динамические вызовы
- [ ] Memgraph/Neo4j настроена и работает
- [ ] Индексы добавлены в БД
- [ ] Query performance протестирована
- [ ] Инкрементальные обновления работают
- [ ] Логирование включено
- [ ] Error handling покрыт
- [ ] Документация актуальна
- [ ] CI/CD интегрирована
