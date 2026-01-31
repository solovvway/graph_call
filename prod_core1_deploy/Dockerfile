# Сборка из папки prod_core1_deploy: docker build -t sast-job .
# Запуск: docker run -e SCAN_ID=uuid -e REPO_ZIP_URL=... -e RABBITMQ_URL=... sast-job
FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY auditor.py .
COPY llm_aditor_prod_core1.py .
COPY config.json .
COPY run_scan.py .
COPY prod_core1/ ./prod_core1/
COPY prompts/ ./prompts/
COPY tools/ ./tools/
COPY scripts/ ./scripts/

ENV SCAN_ID=
ENV REPO_ZIP_URL=
ENV RABBITMQ_URL=
ENV CONFIG_PATH=/app/config.json
ENV MINIO_ENDPOINT=
ENV MINIO_ACCESS_KEY=
ENV MINIO_SECRET_KEY=
ENV GEN_SOURCES=

ENTRYPOINT ["python", "run_scan.py"]
