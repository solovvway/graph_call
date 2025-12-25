FROM python:3.12-slim
RUN pip install --no-cache-dir tree-sitter tree-sitter-languages
WORKDIR /app
COPY call_graph_starter.py .
ENTRYPOINT ["python3", "call_graph_starter.py"]
