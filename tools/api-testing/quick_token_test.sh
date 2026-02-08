#!/bin/bash

# Quick HackerOne Token Test Script
# Run this after updating your .env file with new credentials

echo "======================================"
echo "Quick HackerOne Token Test"
echo "======================================"

# Load credentials from .env
if [ -f "/home/kali/bbhk/.env" ]; then
    export $(grep -E '^HACKERONE_API' /home/kali/bbhk/.env | xargs)
else
    echo "❌ ERROR: .env file not found!"
    exit 1
fi

echo "Username: $HACKERONE_API_USERNAME"
echo "Token: ${HACKERONE_API_TOKEN:0:20}..."
echo ""

# Test 1: Hacker profile
echo "1. Testing /hackers/me endpoint..."
response=$(curl -s -w "\n%{http_code}" https://api.hackerone.com/v1/hackers/me \
    -u "$HACKERONE_API_USERNAME:$HACKERONE_API_TOKEN" \
    -H 'Accept: application/json')

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "200" ]; then
    echo "   ✅ SUCCESS! Token is working!"
    echo "   Your hacker API access is confirmed!"
    
    # Try to extract username from response
    username=$(echo "$body" | grep -o '"username":"[^"]*"' | cut -d'"' -f4 || echo "")
    if [ ! -z "$username" ]; then
        echo "   Hacker username: $username"
    fi
else
    echo "   ❌ FAILED with status: $http_code"
    echo "   Response: ${body:0:100}"
fi

echo ""

# Test 2: Programs list
echo "2. Testing /hackers/programs endpoint..."
response=$(curl -s -w "\n%{http_code}" "https://api.hackerone.com/v1/hackers/programs?page[size]=1" \
    -u "$HACKERONE_API_USERNAME:$HACKERONE_API_TOKEN" \
    -H 'Accept: application/json')

http_code=$(echo "$response" | tail -n1)

if [ "$http_code" = "200" ]; then
    echo "   ✅ Programs endpoint working!"
else
    echo "   ❌ Programs endpoint failed: $http_code"
fi

echo ""
echo "======================================"

if [ "$http_code" = "200" ]; then
    echo "✅ CONGRATULATIONS! Your API token is working!"
    echo ""
    echo "You can now:"
    echo "  - Fetch program data"
    echo "  - Submit reports via API"
    echo "  - Track your earnings"
    echo "  - Automate your workflows"
    echo ""
    echo "Run the full test suite:"
    echo "  python3 /home/kali/bbhk/tools/api-testing/test_hacker_api.py"
else
    echo "❌ Token is not working. Please:"
    echo "1. Go to https://hackerone.com/settings/api_token"
    echo "2. Generate a NEW token"
    echo "3. Update .env file"
    echo "4. Run this test again"
fi

echo "======================================" 