#!/bin/bash
# BBHK - Start All Services (KISS Principle)
# Simple, one-command deployment

echo "🚀 BBHK Service Launcher - Starting all services..."
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Kill any existing services on our ports
echo -e "${YELLOW}Cleaning up existing services...${NC}"
pkill -f "python.*8000" 2>/dev/null
pkill -f "python.*8080" 2>/dev/null
pkill -f "python.*8001" 2>/dev/null
sleep 2

# 1. Ensure PostgreSQL is running
echo -e "${GREEN}1. Checking PostgreSQL...${NC}"
if docker ps | grep -q bbhk-postgres; then
    echo "   ✅ PostgreSQL already running"
else
    echo "   Starting PostgreSQL..."
    docker-compose up -d bbhk-postgres
    sleep 5
fi

# 2. Start Enhanced API Backend (port 8000)
echo -e "${GREEN}2. Starting API Backend...${NC}"
cd /home/kali/bbhk
python3 web/backend/api_enhanced.py > /tmp/bbhk-api.log 2>&1 &
API_PID=$!
echo "   ✅ API started (PID: $API_PID, Port: 8000)"

# 3. Start Web Portal (port 8080)
echo -e "${GREEN}3. Starting Web Portal...${NC}"
cd /home/kali/bbhk/web/portal_enhanced
python3 -m http.server 8080 > /tmp/bbhk-portal.log 2>&1 &
PORTAL_PID=$!
echo "   ✅ Portal started (PID: $PORTAL_PID, Port: 8080)"

# 4. Wait for services to be ready
echo -e "${YELLOW}Waiting for services to initialize...${NC}"
sleep 5

# 5. Test connectivity
echo -e "${GREEN}4. Testing Services...${NC}"
echo -n "   API Health Check: "
if curl -s -o /dev/null -w "%{http_code}" http://<YOUR_HOSTNAME>:8000/ | grep -q "200"; then
    echo -e "${GREEN}✅ OK${NC}"
else
    echo -e "${RED}❌ Failed${NC}"
fi

echo -n "   Portal Health Check: "
if curl -s -o /dev/null -w "%{http_code}" http://<YOUR_HOSTNAME>:8080/index-multitab.html | grep -q "200"; then
    echo -e "${GREEN}✅ OK${NC}"
else
    echo -e "${RED}❌ Failed${NC}"
fi

echo -n "   Database Health Check: "
if docker exec bbhk-postgres psql -U bbhk_user -d bbhk_db -c "SELECT 1" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ OK${NC}"
else
    echo -e "${RED}❌ Failed${NC}"
fi

# 6. Display access URLs
echo ""
echo "=========================================="
echo -e "${GREEN}✅ ALL SERVICES STARTED!${NC}"
echo "=========================================="
echo ""
echo "Access BBHK at:"
echo -e "${GREEN}  🌐 Main Portal: http://<YOUR_HOSTNAME>:8080/index-multitab.html${NC}"
echo -e "${GREEN}  🔌 API Docs:    http://<YOUR_HOSTNAME>:8000/docs${NC}"
echo -e "${GREEN}  🗄️  Database:    <YOUR_HOSTNAME>:5432${NC}"
echo ""
echo "Service PIDs:"
echo "  API: $API_PID"
echo "  Portal: $PORTAL_PID"
echo ""
echo "Logs:"
echo "  API: /tmp/bbhk-api.log"
echo "  Portal: /tmp/bbhk-portal.log"
echo ""
echo "To stop all services: pkill -f 'python.*bbhk'"
echo "=========================================="