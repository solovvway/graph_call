# Core3-Fast: Security Analysis with Forward-Validation

## Обзор

Core3-fast - это модуль для анализа безопасности кода с поддержкой **forward-validation** в процессе backward-анализа. Модуль строит граф вызовов функций, находит пути от источников данных (sources) к опасным функциям (sinks) и валидирует источники согласно конфигурации.

## Архитектура

### Основные компоненты

1. **ast_core.py** - Парсинг AST кода с использованием tree-sitter
2. **graph_builder.py** - Построение графа вызовов и backward-анализ
3. **trace_processor.py** - Обработка трейсов, дедупликация и forward-validation
4. **sources.py** - Валидация источников данных
5. **sinks.py** - Определение опасных функций (sinks)

## Backward-анализ

### Принцип работы

Backward-анализ начинается от **sinks** (опасных функций) и движется вверх по графу вызовов к **sources** (источникам данных):

```
Sink → Function3 → Function2 → Function1 → Source
```

### Процесс анализа

1. **Построение графа**: Парсинг всех файлов репозитория и построение графа вызовов
2. **Поиск sinks**: Идентификация всех опасных функций в коде
3. **Backward traversal**: DFS-обход от каждого sink вверх по вызовам
4. **Сбор трейсов**: Сохранение всех найденных путей от источников к sinks

### Пример

```python
# Source (web endpoint)
@app.route('/api/user', methods=['POST'])
def handle_user():
    data = request.json  # Source
    process_data(data)   # → Function1
    return "OK"

# Function1
def process_data(data):
    result = transform(data)  # → Function2
    save_result(result)       # → Function3

# Function3
def save_result(result):
    query = f"INSERT INTO users VALUES ({result})"  # Sink (SQL injection)
    db.execute(query)
```

Backward-анализ найдет путь: `save_result → process_data → handle_user`

## Forward-Validation

### Назначение

Forward-validation проверяет, что найденные источники действительно соответствуют критериям источников веб-данных, определенным в конфигурации `sources.json`.

### Когда выполняется

Forward-validation выполняется **в процессе backward-анализа** при сохранении каждого трейса:

1. Backward-анализ находит путь от sink к source
2. Перед сохранением трейса вызывается `validate_source()`
3. Если источник не соответствует критериям - трейс отбрасывается
4. Только валидные трейсы сохраняются

### Правила валидации

#### 1. Валидация по файлам (`file_patterns`)

Проверяет, что файл с источником соответствует паттернам:

```json
{
  "file_patterns": [
    {
      "pattern": "**/routes.py",
      "language": "python"
    }
  ]
}
```

**Логика**: Если указаны только `file_patterns`, источник должен находиться в файле, соответствующем паттерну.

#### 2. Валидация по функциям (`function_patterns` / `function_names`)

Проверяет, что имя функции соответствует паттернам или точным именам:

```json
{
  "function_patterns": [
    ".*_endpoint",
    "handle_.*"
  ],
  "function_names": [
    "register_route",
    "add_handler"
  ]
}
```

**Логика**: Если указаны только `function_patterns`/`function_names`, источник должен быть функцией, соответствующей паттерну/имени.

#### 3. Комбинированная валидация

Если указаны и файлы, и функции:

- **OR логика**: Источник валиден, если соответствует **либо** файлу, **либо** функции
- Можно указать только файлы, только функции, или оба

#### 4. Обратная совместимость

Если в конфиге нет ни `file_patterns`, ни `function_patterns`/`function_names`, используется старая логика:
- Проверка по `source_indicators` (подстроки в коде)
- Проверка по `language_specific.patterns` (regex-паттерны)
- Для PHP - проверка суперглобальных переменных

### Примеры конфигураций

#### Только файлы

```json
{
  "file_patterns": [
    {"pattern": "**/routes.py", "language": "python"},
    {"pattern": "**/app.py", "language": "python"}
  ]
}
```

**Результат**: Принимаются все источники из файлов `routes.py` или `app.py`

#### Только функции

```json
{
  "function_patterns": [
    ".*_handler",
    "handle_.*"
  ],
  "function_names": [
    "process_request",
    "api_endpoint"
  ]
}
```

**Результат**: Принимаются источники из функций, имена которых соответствуют паттернам или точным именам

#### Файлы И функции (OR)

```json
{
  "file_patterns": [
    {"pattern": "**/routes.py", "language": "python"}
  ],
  "function_patterns": [
    ".*_endpoint"
  ]
}
```

**Результат**: Принимаются источники, которые **либо** находятся в `routes.py`, **либо** являются функциями с именами, соответствующими `.*_endpoint`

## Конфигурация sources.json

### Структура файла

```json
{
  "file_patterns": [
    {
      "pattern": "**/routes.py",
      "language": "python"
    }
  ],
  "function_patterns": [
    ".*_endpoint",
    "handle_.*"
  ],
  "function_names": [
    "register_route",
    "api_handler"
  ],
  "source_indicators": [
    "POST",
    "GET",
    "@app.route"
  ],
  "language_specific": {
    "python": {
      "patterns": [
        "@app\\.route",
        "register_endpoint"
      ]
    }
  }
}
```

### Параметры

- **file_patterns**: Массив паттернов файлов (glob patterns)
  - `pattern`: Паттерн пути к файлу (поддерживает `**/` для рекурсивного поиска)
  - `language`: Язык программирования (опционально)

- **function_patterns**: Массив regex-паттернов для имен функций
  - Сопоставляются с полным именем функции (включая модуль)

- **function_names**: Массив точных имен функций
  - Точное совпадение или совпадение с окончанием (например, `module.function_name`)

- **source_indicators**: Подстроки, которые должны присутствовать в коде
  - Используются при отсутствии `file_patterns` и `function_patterns`

- **language_specific**: Языко-специфичные regex-паттерны
  - Компилируются в regex для эффективной проверки

### Приоритет конфигураций

1. **Репозиторий-специфичный** `sources.json` в корне репозитория
2. **Общий** `sources.json` в `core3-fast/sources.json`

## Использование

### Базовое использование

```bash
python3 auditor.py --core core3-fast --repo ./repos/ --out ./reports --code
```

### С репозиторий-специфичным конфигом

1. Создайте `sources.json` в корне репозитория:
```bash
./repos/myproject/sources.json
```

2. Запустите анализ:
```bash
python3 auditor.py --core core3-fast --repo ./repos/ --out ./reports --code
```

Система автоматически обнаружит и использует репозиторий-специфичный конфиг.

## Производительность

### Оптимизации

1. **Кэширование конфигов**: Конфиги загружаются один раз и кэшируются по ключу репозитория
2. **Кэширование паттернов**: Regex-паттерны компилируются один раз
3. **Кэширование проверок файлов**: Результаты проверки файлов кэшируются
4. **Раннее отбрасывание**: Невалидные трейсы отбрасываются до сохранения

### Дедупликация

- Трейсы с одинаковым кодом функций объединяются
- Разные sinks в одном трейсе сохраняются вместе
- Хеширование кода для быстрого сравнения

## Отладка

### Логирование

Forward-validation логирует отброшенные трейсы на уровне DEBUG:

```python
logger.debug(f"Trace rejected by forward-validation: path starts with {path[0]}")
```

Включите DEBUG-логирование для просмотра отброшенных трейсов:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Примеры

### Пример 1: Только файлы

```json
{
  "file_patterns": [
    {"pattern": "**/api/**/*.py", "language": "python"}
  ]
}
```

**Результат**: Все источники из файлов в директории `api/` будут приняты.

### Пример 2: Только функции

```json
{
  "function_names": [
    "handle_request",
    "process_api_call"
  ]
}
```

**Результат**: Только источники из функций `handle_request` и `process_api_call` будут приняты.

### Пример 3: Комбинация

```json
{
  "file_patterns": [
    {"pattern": "**/routes.py", "language": "python"}
  ],
  "function_patterns": [
    ".*_webhook"
  ]
}
```

**Результат**: Источники принимаются, если они:
- Находятся в `routes.py`, **ИЛИ**
- Являются функциями с именами, заканчивающимися на `_webhook`
