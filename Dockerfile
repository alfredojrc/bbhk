# Multi-stage build for BBHK production deployment
FROM python:3.13-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies including Vault client
RUN apt-get update && apt-get install -y \
    curl \
    git \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    postgresql-client \
    wget \
    unzip \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install HashiCorp Vault CLI
RUN VAULT_VERSION="1.15.2" && \
    curl -fsSL https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip -o vault.zip && \
    unzip vault.zip && \
    mv vault /usr/local/bin/vault && \
    chmod +x /usr/local/bin/vault && \
    rm vault.zip

# Create app user
RUN useradd --create-home --shell /bin/bash --uid 1000 bbhk
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt .
COPY setup.py .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Development stage
FROM base as development

# Install development dependencies
RUN pip install --no-cache-dir pytest pytest-asyncio pytest-cov black isort flake8 mypy

# Copy source code
COPY --chown=bbhk:bbhk . .

# Install in development mode
RUN pip install -e ".[dev]"

USER bbhk
EXPOSE 8080 8000
CMD ["python", "-m", "src.main", "--config", "config/development.json"]

# Production stage
FROM base as production

# Copy only necessary files
COPY --chown=bbhk:bbhk src/ ./src/
COPY --chown=bbhk:bbhk core/ ./core/
COPY --chown=bbhk:bbhk platforms/ ./platforms/
COPY --chown=bbhk:bbhk config/ ./config/
COPY --chown=bbhk:bbhk templates/ ./templates/
COPY --chown=bbhk:bbhk requirements.txt .
COPY --chown=bbhk:bbhk setup.py .

# Install production dependencies only
RUN pip install --no-cache-dir .

# Create necessary directories including vault-keys
RUN mkdir -p /app/logs /app/data /app/vault-keys /tmp/prometheus && \
    chown -R bbhk:bbhk /app/logs /app/data /app/vault-keys /tmp/prometheus

# Security: Run as non-root user
USER bbhk

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 8000

# Production command
CMD ["python", "-m", "src.main", "--config", "config/production.json"]

# Final stage selector
FROM ${BUILD_TARGET:-production} as final