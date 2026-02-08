#!/bin/bash
# BBHK Simple Startup Script
# Starts your personal bug bounty toolkit on your laptop

set -e

# Colors
GREEN='\\033[0;32m'
BLUE='\\033[0;34m'
YELLOW='\\033[1;33m'
RED='\\033[0;31m'
NC='\\033[0m'

echo -e \"${BLUE}🎯 Starting BBHK - Personal Bug Bounty Toolkit${NC}\"
echo -e \"${BLUE}===============================================${NC}\"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e \"${RED}❌ Docker not found. Please install: sudo apt install docker.io${NC}\"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e \"${RED}❌ Docker Compose not found. Please install: sudo apt install docker-compose${NC}\"
    exit 1
fi

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo -e \"${YELLOW}⚠️  Docker is not running. Starting Docker...${NC}\"
    sudo systemctl start docker
    sleep 2
fi

# Create directories
echo -e \"${BLUE}📁 Creating directories...${NC}\"
mkdir -p data workspace logs web

# Initialize database if it doesn't exist
if [ ! -f \"data/bbhk.db\" ]; then
    echo -e \"${BLUE}💾 Initializing database...${NC}\"
    sqlite3 data/bbhk.db < core/database/schema.sql
    echo -e \"${GREEN}✅ Database created${NC}\"
fi

# Check if config has real API keys
if grep -q \"your_.*_here\" core/config/system.yaml; then
    echo -e \"${YELLOW}⚠️  You need to add your API keys!${NC}\"
    echo -e \"${YELLOW}   Edit: nano core/config/system.yaml${NC}\"
    echo -e \"${YELLOW}   Add your HackerOne, Bugcrowd tokens${NC}\"
    echo \"\"
    echo -e \"${YELLOW}Press Enter to continue anyway, or Ctrl+C to stop and add keys...${NC}\"
    read
fi

# Build and start
echo -e \"${BLUE}🐳 Building containers...${NC}\"
docker-compose build --quiet

echo -e \"${BLUE}🚀 Starting BBHK...${NC}\"
docker-compose up -d

# Wait a bit for startup
echo -e \"${BLUE}⏳ Waiting for startup...${NC}\"
sleep 5

# Check if running
if docker-compose ps | grep -q \"Up\"; then
    echo \"\"
    echo -e \"${GREEN}🎉 BBHK is running!${NC}\"
    echo \"\"
    echo -e \"${BLUE}📊 Access your toolkit:${NC}\"
    echo -e \"  • Main app: ${GREEN}http://localhost:8080${NC}\"
    echo -e \"  • Dashboard: ${GREEN}http://localhost:8081${NC}\"
    echo \"\"
    echo -e \"${BLUE}🔧 Useful commands:${NC}\"
    echo -e \"  • Check status: ${YELLOW}docker-compose ps${NC}\"
    echo -e \"  • View logs: ${YELLOW}docker-compose logs -f${NC}\"
    echo -e \"  • Stop: ${YELLOW}docker-compose down${NC}\"
    echo \"\"
    echo -e \"${BLUE}📝 Next steps:${NC}\"
    echo -e \"  1. Add your API keys: ${YELLOW}nano core/config/system.yaml${NC}\"
    echo -e \"  2. Restart: ${YELLOW}docker-compose restart${NC}\"
    echo -e \"  3. Start hunting bugs!${NC}\"
else
    echo -e \"${RED}❌ Something went wrong. Check logs:${NC}\"
    echo -e \"${YELLOW}docker-compose logs${NC}\"
    exit 1
fi