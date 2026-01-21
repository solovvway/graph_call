# Neo4j Code Graph Builder

Этот модуль содержит инструменты для создания графа кода в Neo4j на основе парсинга репозитория.

## Структура

- `ast_logger.py` - модуль для логирования работы с AST (извлечен из auditor.py)
- `repo_to_neo4j.py` - скрипт для парсинга репозитория и создания графа в Neo4j
- `docker-compose.yml` - конфигурация для запуска Neo4j в Docker

## Установка

1. Установите зависимости:
```bash
pip install neo4j tree-sitter tree-sitter-languages
```

2. Запустите Neo4j через Docker Compose:
```bash
cd neo4j
docker-compose up -d
```

Neo4j будет доступен по адресам:
- HTTP: http://localhost:7474
- Bolt: bolt://localhost:7687
- Username: neo4j
- Password: password

## Использование

### Парсинг репозитория и создание графа

```bash
python repo_to_neo4j.py --repo /path/to/repository --clear
```

Параметры:
- `--repo` - путь к репозиторию (обязательный)
- `--uri` - URI Neo4j (по умолчанию: bolt://localhost:7687)
- `--user` - имя пользователя Neo4j (по умолчанию: neo4j)
- `--password` - пароль Neo4j (по умолчанию: password)
- `--clear` - очистить базу данных перед импортом

### Примеры запросов в Neo4j

#### Найти все функции-точки входа (WEB entrypoints)
```cypher
MATCH (n:Function)
WHERE n.is_entry = true
RETURN n.name, n.file, n.line
```

#### Найти все sink функции
```cypher
MATCH (n:Function)
WHERE n.is_sink = true
RETURN n.name, n.language, count(n) as count
```

#### Найти пути от entry points до sinks
```cypher
MATCH path = (entry:Function)-[:CALLS*]->(sink:Function)
WHERE entry.is_entry = true AND sink.is_sink = true
RETURN path
LIMIT 10
```

#### Найти функции, вызывающие конкретный sink
```cypher
MATCH (caller:Function)-[:CALLS]->(sink:Function)
WHERE sink.name = 'eval' AND sink.is_sink = true
RETURN caller.name, caller.file, caller.line
```

#### Статистика по языкам
```cypher
MATCH (n:Function)
RETURN n.language, count(n) as count
ORDER BY count DESC
```

## Структура данных в Neo4j

### Узлы (Nodes)
- **Label**: `Function`
- **Свойства**:
  - `uid` - уникальный идентификатор функции
  - `name` - имя функции
  - `file` - путь к файлу
  - `line` - номер строки начала
  - `end_line` - номер строки конца
  - `is_entry` - является ли точкой входа (WEB entrypoint)
  - `is_sink` - является ли sink функцией
  - `is_source` - является ли источником данных
  - `is_builtin` - является ли встроенной функцией
  - `language` - язык программирования

### Ребра (Edges)
- **Type**: `CALLS`
- **Свойства**:
  - `file` - файл, где происходит вызов
  - `line` - номер строки вызова
  - `language` - язык программирования
  - `callsites` - массив мест вызова (file:line)

## Остановка Neo4j

```bash
docker-compose down
```

Для удаления всех данных:
```bash
docker-compose down -v
```
