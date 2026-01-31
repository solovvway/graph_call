# prod_core1 — самодостаточная сборка и развёртывание

Все файлы для prod_core1: core, оркестратор, Docker, K8s Job и Ansible для развёртывания в кластере.

## Структура

- `prod_core1/` — модуль анализа (ast_core, graph_builder, sinks, sources, trace_processor, agent-config)
- `auditor.py`, `llm_aditor_prod_core1.py` — оркестратор (из корня репозитория)
- `config.json`, `prompts/`, `tools/`, `scripts/` — конфиг и общие скрипты (из корня)
- `run_scan.py` — entrypoint K8s Job (RabbitMQ, MinIO, сканирование)
- `Dockerfile` — образ на Python 3.10
- `job.yaml` — манифест Kubernetes Job
- `ansible/` — playbook для развёртывания в кластере

## Сборка образа

Из этой папки:

```bash
cd prod_core1_deploy
docker build -t sast-job:latest .
```

## Запуск контейнера локально

```bash
docker run --rm \
  -e SCAN_ID=test-scan-1 \
  -e REPO_ZIP_URL=https://example.com/repo.zip \
  -e RABBITMQ_URL=amqp://user:pass@host:5672/ \
  -e MINIO_ENDPOINT=minio:9000 \
  -e MINIO_ACCESS_KEY=... \
  -e MINIO_SECRET_KEY=... \
  sast-job:latest
```

## Развёртывание в кластер (Ansible)

1. Настроить доступ к кластеру (`kubectl` / `KUBECONFIG`).
2. Создать Secret с учётными данными RabbitMQ и MinIO, например:

```bash
kubectl create secret generic sast-secrets \
  --from-literal=rabbitmq-url='amqp://user:pass@rabbitmq:5672/' \
  --from-literal=minio-endpoint=minio:9000 \
  --from-literal=minio-access-key=... \
  --from-literal=minio-secret-key=... \
  -n default
```

3. При необходимости отредактировать `job.yaml` (REPO_ZIP_URL, namespace и т.д.).
4. Запустить playbook из папки `prod_core1_deploy`:

```bash
cd prod_core1_deploy
ansible-playbook -i ansible/inventory ansible/deploy.yaml
```

С параметрами (если playbook их поддерживает через `-e`):

```bash
ansible-playbook -i ansible/inventory ansible/deploy.yaml \
  -e "k8s_namespace=default"
```

## Оценка трейсов (LLM)

Используется **Yandex AI Studio SDK** (`yandex-ai-studio-sdk`), **AsyncAIStudio**, нативный async: `await model.run(messages)`, результат — `result[0].text`. Конфиг: `folder_id`, `api_key`, `model` (полный URI `gpt://folder/model/version` или короткое имя). Опционально `model_version` в конфиге (по умолчанию из URI или `rc`).

## Переменные окружения Job

| Переменная       | Описание |
|------------------|----------|
| `SCAN_ID`        | UUID скана (очередь статусов в RabbitMQ) |
| `REPO_ZIP_URL`   | URL zip-архива репозитория |
| `RABBITMQ_URL`   | URL подключения к RabbitMQ |
| `MINIO_*`        | Endpoint и ключи MinIO для загрузки отчётов |
| `CONFIG_PATH`    | Путь к config.json в контейнере |
| `GEN_SOURCES`    | `true` — генерировать sources.json через агента |

## Обновление файлов из родительской директории

Файлы, которые лежат в общем корне репозитория (не в prod_core1), скопированы сюда из родительской директории. Чтобы обновить их после изменений в корне:

```bash
# из корня репозитория graph_call
cp auditor.py llm_aditor_prod_core1.py config.json requirements.txt prod_core1_deploy/
cp -r prompts/* prod_core1_deploy/prompts/
cp -r tools/* prod_core1_deploy/tools/
cp -r scripts/* prod_core1_deploy/scripts/
```

Модуль `prod_core1/` обновлять отдельно:

```bash
cp -r prod_core1/* prod_core1_deploy/prod_core1/
```
