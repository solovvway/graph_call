FROM ubuntu:22.04

# Install system dependencies for building Tree-sitter parsers
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    nodejs \
    npm \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Tree-sitter CLI and Python bindings
RUN npm install -g tree-sitter-cli
RUN pip3 install tree-sitter

# Create app directory
WORKDIR /app
COPY call_graph_starter.py .

# Temporary directory for grammars
RUN mkdir -p /tmp/grammars

# Clone and prepare grammars for supported languages
RUN git clone https://github.com/tree-sitter/tree-sitter-python.git /tmp/grammars/tree-sitter-python \
    && cd /tmp/grammars/tree-sitter-python && tree-sitter generate
RUN git clone https://github.com/tree-sitter/tree-sitter-javascript.git /tmp/grammars/tree-sitter-javascript \
    && cd /tmp/grammars/tree-sitter-javascript && tree-sitter generate
RUN git clone https://github.com/tree-sitter/tree-sitter-java.git /tmp/grammars/tree-sitter-java \
    && cd /tmp/grammars/tree-sitter-java && tree-sitter generate
RUN git clone https://github.com/tree-sitter/tree-sitter-go.git /tmp/grammars/tree-sitter-go \
    && cd /tmp/grammars/tree-sitter-go && tree-sitter generate

# Build .so libraries as expected by the script (using Python's Language.build_library)
RUN mkdir -p build
RUN python3 -c "from tree_sitter import Language; Language.build_library('build/my-python.so', ['/tmp/grammars/tree-sitter-python'])" \
    && python3 -c "from tree_sitter import Language; Language.build_library('build/my-javascript.so', ['/tmp/grammars/tree-sitter-javascript'])" \
    && python3 -c "from tree_sitter import Language; Language.build_library('build/my-java.so', ['/tmp/grammars/tree-sitter-java'])" \
    && python3 -c "from tree_sitter import Language; Language.build_library('build/my-go.so', ['/tmp/grammars/tree-sitter-go'])"

# Clean up
RUN rm -rf /tmp/grammars

ENTRYPOINT ["python3", "call_graph_starter.py"]
