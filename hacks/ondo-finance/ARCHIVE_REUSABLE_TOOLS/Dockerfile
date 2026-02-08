# Oracle Price Monitoring Container - Ondo Finance Research
# Addresses Grok4 critique: "prices are mocked, need real feeds"

FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    tzdata \
    curl \
    git

# Set timezone to UTC for consistent logging
ENV TZ=UTC

# Copy package files
COPY package*.json ./

# Install Node.js dependencies
RUN npm install --omit=dev && npm cache clean --force

# Copy monitoring scripts
COPY real_oracle_monitor.js ./
COPY enhanced_real_arbitrage_poc.js ./

# Copy environment variables (will be mounted as volume)
# COPY .env ./

# Create logs directory
RUN mkdir -p /app/logs

# Create data directory for persistent storage
RUN mkdir -p /app/data

# Set permissions
RUN chown -R node:node /app
USER node

# Health check to ensure monitoring is running
HEALTHCHECK --interval=5m --timeout=30s --start-period=1m --retries=3 \
  CMD npm run health || exit 1

# Expose port for health checks (optional)
EXPOSE 8080

# Default command - run oracle monitor for 72 hours
CMD ["node", "real_oracle_monitor.js"]