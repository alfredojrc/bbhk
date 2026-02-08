#!/bin/bash
# BBHK LAN Deployment Script
# Starts all services configured for network access

echo "🌐 BBHK LAN Deployment Script"
echo "=============================="
echo ""

# Get server IP
SERVER_IP=$(ip addr show | grep -E "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | cut -d'/' -f1)
echo "📍 Server IP detected: $SERVER_IP"
echo ""

# Update .env with current IP
if [ -f .env ]; then
    sed -i "s/SERVER_IP=.*/SERVER_IP=$SERVER_IP/" .env
    sed -i "s|REACT_APP_API_URL=.*|REACT_APP_API_URL=http://$SERVER_IP:8000|" .env
else
    echo "⚠️  .env file not found, creating..."
    cat > .env << EOF
SERVER_IP=$SERVER_IP
REACT_APP_API_URL=http://$SERVER_IP:8000
API_HOST=0.0.0.0
API_PORT=8000
FRONTEND_HOST=0.0.0.0
FRONTEND_PORT=3000
QDRANT_HOST=0.0.0.0
QDRANT_HTTP_PORT=6333
DATABASE_URL=sqlite:///database/bbhk.db
NODE_ENV=production
EOF
fi

# Update docker-compose.override.yml with current IP
cat > docker-compose.override.yml << EOF
version: '3.8'

services:
  backend:
    environment:
      - HOST=0.0.0.0
      - PORT=8000
      - CORS_ORIGINS=["http://localhost:3000","http://$SERVER_IP:3000","http://$SERVER_IP"]
    ports:
      - "0.0.0.0:8000:8000"

  frontend:
    environment:
      - REACT_APP_API_URL=http://$SERVER_IP:8000
      - HOST=0.0.0.0
      - PORT=3000
    ports:
      - "0.0.0.0:3000:3000"

  nginx:
    ports:
      - "0.0.0.0:80:80"

  qdrant:
    environment:
      - QDRANT__SERVICE__HTTP_PORT=6333
      - QDRANT__SERVICE__HOST=0.0.0.0
    ports:
      - "0.0.0.0:6333:6333"
EOF

echo "✅ Configuration updated for IP: $SERVER_IP"
echo ""

# Stop existing containers
echo "🛑 Stopping existing containers..."
docker-compose down

# Start services with override
echo "🚀 Starting services for LAN access..."
docker-compose up -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check service status
echo ""
echo "📊 Service Status:"
echo "=================="
docker-compose ps

echo ""
echo "🎉 BBHK Services are now accessible on your LAN!"
echo ""
echo "📍 Access URLs from any device on your network:"
echo "================================================"
echo ""
echo "🌐 Main Dashboard:        http://$SERVER_IP:3000"
echo "🔌 API Documentation:     http://$SERVER_IP:8000/docs"
echo "🧠 Qdrant Dashboard:      http://$SERVER_IP:6333/dashboard"
echo "📊 Qdrant Health:         http://$SERVER_IP:6333/health"
echo "🌍 Nginx (if configured): http://$SERVER_IP"
echo ""
echo "📱 From mobile devices or other computers, use these URLs"
echo ""
echo "🔒 Security Note: These services are now accessible to"
echo "   anyone on your local network. Configure firewall rules"
echo "   if you need to restrict access."
echo ""
echo "📋 Quick Commands:"
echo "  View logs:    docker-compose logs -f"
echo "  Stop all:     docker-compose down"
echo "  Restart:      docker-compose restart"
echo ""