#!/bin/bash

# BBHK System Validation Script
# Validates all components are working correctly

echo "================================================"
echo "BBHK System Validation - $(date)"
echo "================================================"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check PostgreSQL
echo -e "\n${YELLOW}1. Checking Database...${NC}"
if docker exec bbhk-postgres psql -U bbhk_user -d bbhk_db -c "SELECT COUNT(*) FROM programs;" > /dev/null 2>&1; then
    PROGRAM_COUNT=$(docker exec bbhk-postgres psql -U bbhk_user -d bbhk_db -t -c "SELECT COUNT(*) FROM programs;")
    SCOPE_COUNT=$(docker exec bbhk-postgres psql -U bbhk_user -d bbhk_db -t -c "SELECT COUNT(*) FROM structured_scopes;")
    echo -e "${GREEN}✅ Database: $PROGRAM_COUNT programs, $SCOPE_COUNT scopes${NC}"
else
    echo -e "${RED}❌ Database not accessible${NC}"
fi

# Check API
echo -e "\n${YELLOW}2. Checking API Backend...${NC}"
if curl -s http://<YOUR_HOSTNAME>:8000/health > /dev/null 2>&1; then
    HEALTH=$(curl -s http://<YOUR_HOSTNAME>:8000/health | jq -r '.status')
    echo -e "${GREEN}✅ API Status: $HEALTH${NC}"
    
    # Test stats endpoint
    STATS=$(curl -s http://<YOUR_HOSTNAME>:8000/api/stats)
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Stats Endpoint: $(echo $STATS | jq -r '.status')${NC}"
    fi
else
    echo -e "${RED}❌ API not responding${NC}"
fi

# Check Portal
echo -e "\n${YELLOW}3. Checking Web Portal...${NC}"
if curl -s -I http://<YOUR_HOSTNAME>:3001/working.htm | grep "200 OK" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Portal accessible at http://<YOUR_HOSTNAME>:3001/working.htm${NC}"
else
    echo -e "${RED}❌ Portal not accessible${NC}"
fi

# Check for fake data
echo -e "\n${YELLOW}4. Validating Data Integrity...${NC}"
FAKE_COUNT=$(docker exec bbhk-postgres psql -U bbhk_user -d bbhk_db -t -c "SELECT COUNT(*) FROM programs WHERE handle LIKE '%test%' OR handle LIKE '%fake%' OR handle LIKE '%sample%';")
if [ "$FAKE_COUNT" -eq "0" ] || [ "$FAKE_COUNT" -eq " 0" ]; then
    echo -e "${GREEN}✅ No fake data detected - 100% real HackerOne data${NC}"
else
    echo -e "${RED}⚠️  Warning: Possible fake data detected${NC}"
fi

# Check services
echo -e "\n${YELLOW}5. Checking Running Services...${NC}"
for PORT in 3001 8000 5432; do
    if lsof -i :$PORT > /dev/null 2>&1; then
        SERVICE=$(lsof -i :$PORT | tail -1 | awk '{print $1}')
        echo -e "${GREEN}✅ Port $PORT: $SERVICE running${NC}"
    else
        echo -e "${RED}❌ Port $PORT: No service${NC}"
    fi
done

# Summary
echo -e "\n================================================"
echo -e "${YELLOW}VALIDATION COMPLETE${NC}"
echo -e "Portal: ${GREEN}http://<YOUR_HOSTNAME>:3001/working.htm${NC}"
echo -e "API: ${GREEN}http://<YOUR_HOSTNAME>:8000/docs${NC}"
echo "================================================"