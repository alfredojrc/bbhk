# Multi-stage build for FastAPI backend
FROM python:3.13-slim as builder

# Set build arguments
ARG BUILD_ENV=production
ARG APP_VERSION=1.0.0

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r bbhk && useradd -r -g bbhk bbhk

# Set work directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.13-slim as production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r bbhk && useradd -r -g bbhk bbhk

# Set work directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY web/backend/ ./web/backend/
COPY src/ ./src/
COPY core/ ./core/
COPY config/ ./config/
COPY platforms/ ./platforms/
COPY scripts/ ./scripts/

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/reports /app/database

# Set permissions
RUN chown -R bbhk:bbhk /app
RUN chmod +x /app/scripts/*.sh 2>/dev/null || true

# Create startup script
RUN echo '#!/bin/bash\n\
# Initialize database if it doesn'\''t exist\n\
if [ ! -f /app/database/bbhk.db ]; then\n\
    echo "Initializing database..."\n\
    sqlite3 /app/database/bbhk.db < /app/core/database/schema.sql\n\
fi\n\
\n\
# Start the FastAPI application\n\
exec uvicorn web.backend.main:app \\\n\
    --host ${HOST:-0.0.0.0} \\\n\
    --port ${PORT:-8000} \\\n\
    --workers ${WORKERS:-4} \\\n\
    --log-level ${LOG_LEVEL:-info} \\\n\
    --access-log \\\n\
    --reload-dir /app\n' > /app/start.sh && \
    chmod +x /app/start.sh

# Switch to non-root user
USER bbhk

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/ || exit 1

# Expose port
EXPOSE 8000

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Start application
CMD ["/app/start.sh"]