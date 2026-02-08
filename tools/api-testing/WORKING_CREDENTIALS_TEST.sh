#!/bin/bash

# WORKING HackerOne API Test
# Confirms that <YOUR_H1_USERNAME> credentials work with HACKER endpoints

echo "=============================================="
echo "✅ WORKING HACKERONE API TEST"
echo "=============================================="
echo "User: \$HACKERONE_API_USERNAME"
echo "Endpoint: /v1/hackers/programs (HACKER API)"
echo "Cost: FREE!"
echo ""

# Test the working endpoint
echo "🧪 Testing HACKER API endpoint..."
response=$(curl -s -w "\n%{http_code}" \
    "https://api.hackerone.com/v1/hackers/programs?page[size]=5" \
    -u "$HACKERONE_API_USERNAME:$HACKERONE_API_TOKEN" \
    -H 'Accept: application/json')

status_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$status_code" = "200" ]; then
    echo "✅ SUCCESS! Hacker API is working!"
    echo ""
    
    # Extract program names if possible
    echo "🏆 Programs found:"
    echo "$body" | grep -o '"name":"[^"]*"' | head -5 | sed 's/"name":"\([^"]*\)"/  ✅ \1/' || echo "  Data received but couldn't parse names"
    
    echo ""
    echo "🎯 This proves:"
    echo "  • Hacker API endpoints work (FREE!)"
    echo "  • Real program data is accessible"
    echo "  • No $15K subscription needed"
    echo "  • BBHK can fetch real data"
    
else
    echo "❌ FAILED with status: $status_code"
    echo "Response: ${body:0:200}"
fi

echo ""
echo "=============================================="
echo "KEY LESSON: Use /v1/hackers/* endpoints!"
echo "❌ DON'T USE: /v1/programs (costs $15K+)"
echo "✅ DO USE: /v1/hackers/programs (FREE!)"
echo "=============================================="