# Build: docker build -t graph-call-sast .
# Run: docker run -e REPO_ZIP_URL=https://... -e CONFIG_PATH=/app/config.json -v $(pwd)/config.json:/app/config.json graph-call-sast
FROM python:3.11-slim

WORKDIR /app

# Install system deps for tree-sitter if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# config.json can be overridden by bind mount
ENV CONFIG_PATH=/app/config.json
ENV REPO_ZIP_URL=
ENTRYPOINT ["python", "scripts/docker_entrypoint.py"]
