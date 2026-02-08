#!/bin/bash

# BBHK Docker Setup Script
# This script sets up the complete Docker environment for BBHK

set -e

echo "🚀 Setting up BBHK Docker Environment..."

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root"
   exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Docker if not present
if ! command_exists docker; then
    echo "📦 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo "✅ Docker installed successfully"
else
    echo "✅ Docker already installed"
fi

# Install Docker Compose if not present
if ! command_exists docker-compose; then
    echo "📦 Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo "✅ Docker Compose installed successfully"
else
    echo "✅ Docker Compose already installed"
fi

# Create necessary directories
echo "📁 Creating directory structure..."
mkdir -p {logs,data/qdrant,reports,backups,docker/nginx/ssl}

# Set up environment file
if [ ! -f .env ]; then
    echo "⚙️ Setting up environment configuration..."
    cp .env.example .env
    
    # Generate random secrets
    SECRET_KEY=$(openssl rand -hex 32)
    JWT_SECRET=$(openssl rand -hex 32)
    POSTGRES_PASSWORD=$(openssl rand -hex 16)
    
    # Update .env file with generated secrets
    sed -i "s/your-secret-key-here/$SECRET_KEY/g" .env
    sed -i "s/your-jwt-secret-here/$JWT_SECRET/g" .env
    sed -i "s/change_me_to_secure_password/$POSTGRES_PASSWORD/g" .env
    
    echo "✅ Environment configuration created"
else
    echo "✅ Environment configuration already exists"
fi

# Generate SSL certificates for development
if [ ! -f docker/nginx/ssl/cert.pem ]; then
    echo "🔒 Generating SSL certificates..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout docker/nginx/ssl/key.pem \
        -out docker/nginx/ssl/cert.pem \
        -subj "/C=US/ST=CA/L=San Francisco/O=BBHK/OU=Development/CN=localhost"
    echo "✅ SSL certificates generated"
else
    echo "✅ SSL certificates already exist"
fi

# Ensure proper permissions
echo "🔐 Setting up permissions..."
chmod 600 docker/nginx/ssl/key.pem
chmod 644 docker/nginx/ssl/cert.pem
chmod +x scripts/*.sh

# Initialize database if it doesn't exist
if [ ! -f core/database/bbhk.db ]; then
    echo "🗄️ Initializing database..."
    sqlite3 core/database/bbhk.db < core/database/schema.sql
    echo "✅ Database initialized"
else
    echo "✅ Database already exists with $(sqlite3 core/database/bbhk.db "SELECT COUNT(*) FROM programs;") programs"
fi

# Pull Docker images
echo "📥 Pulling Docker images..."
docker-compose pull

# Build custom images
echo "🔨 Building custom images..."
docker-compose build

echo ""
echo "🎉 BBHK Docker setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Review and customize .env file if needed"
echo "2. Start services: docker-compose up -d"
echo "3. Access dashboard: http://localhost:3000"
echo "4. Access API: http://localhost:8000"
echo ""
echo "For production deployment:"
echo "1. Update SSL certificates in docker/nginx/ssl/"
echo "2. Use PostgreSQL: docker-compose --profile production up -d"
echo "3. Enable monitoring: docker-compose --profile monitoring up -d"
echo ""
echo "Useful commands:"
echo "- View logs: docker-compose logs -f"
echo "- Check status: docker-compose ps"
echo "- Stop services: docker-compose down"
echo "- Backup database: ./scripts/backup.sh"