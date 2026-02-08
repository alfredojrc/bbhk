# Multi-stage build for React frontend
FROM node:22-alpine as builder

# Set work directory
WORKDIR /app

# Copy package.json and install dependencies
COPY docker/frontend/package.json .
RUN npm install

# Copy application source code
COPY docker/frontend/src ./src
COPY docker/frontend/public ./public

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine as production

# Install curl for healthcheck
RUN apk add --no-cache curl

# Copy built application
COPY --from=builder /app/build /usr/share/nginx/html

# Create nginx config for React Router
COPY docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Expose port
EXPOSE 3000

# Start nginx
CMD ["nginx", "-g", "daemon off;"]