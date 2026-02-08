#!/bin/bash

# 🎯 ONDO FINANCE ORACLE MONITORING - 72 HOUR EVIDENCE COLLECTION
# Addresses Grok4 critique: "prices are mocked, need real feeds"

set -e  # Exit on error

echo "🚀 STARTING ONDO FINANCE ORACLE MONITORING"
echo "=========================================="
echo "Purpose: Capture real oracle price divergence for bug bounty evidence"
echo "Duration: 72 hours continuous monitoring"
echo "Start Time: $(date)"
echo ""

# Check if running in the correct directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Error: docker-compose.yml not found. Run from deliverables directory."
    exit 1
fi

# Check if .env file exists
if [ ! -f "../.env" ]; then
    echo "❌ Error: .env file not found. Ensure API keys are configured."
    exit 1
fi

# Create necessary directories
echo "📁 Creating monitoring directories..."
mkdir -p logs
mkdir -p data
mkdir -p results

# Check Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start Docker first."
    exit 1
fi

# Stop any existing monitoring containers
echo "🛑 Stopping any existing monitoring containers..."
docker-compose down 2>/dev/null || true

# Build the monitoring container
echo "🔨 Building oracle monitoring container..."
docker-compose build --no-cache

# Display monitoring configuration
echo ""
echo "📊 MONITORING CONFIGURATION"
echo "=========================="
echo "Container Name: ondo-oracle-monitor-72h"
echo "Duration: 72 hours (3 days)"
echo "Settlement Windows: 15:00-17:00 UTC (high frequency)"
echo "Normal Monitoring: Every 5 minutes"
echo "Real Contracts: OUSGManager, Chainlink USDC/USD"
echo "Evidence Output: logs/, data/, results/"
echo ""

# Start monitoring
echo "▶️  Starting 72-hour oracle monitoring..."
docker-compose up -d

# Wait for containers to start
sleep 5

# Check container status
echo ""
echo "📋 CONTAINER STATUS"
echo "=================="
docker-compose ps

# Display real-time logs initially
echo ""
echo "📊 LIVE MONITORING OUTPUT (first 30 seconds)"
echo "============================================"
timeout 30s docker-compose logs -f ondo-oracle-monitor || true

echo ""
echo "✅ MONITORING STARTED SUCCESSFULLY"
echo "================================="
echo "Container: ondo-oracle-monitor-72h"
echo "End Time: $(date -d '+72 hours')"
echo ""
echo "📊 Monitor Progress:"
echo "docker-compose logs -f ondo-oracle-monitor"
echo ""
echo "📈 View Logs:"
echo "ls -la logs/"
echo ""
echo "🔍 Check Status:"
echo "docker-compose ps"
echo ""
echo "🛑 Stop Monitoring:"
echo "docker-compose down"
echo ""

# Create monitoring status file
cat > monitoring_status.txt << EOF
ONDO FINANCE ORACLE MONITORING STATUS
=====================================
Start Time: $(date)
End Time: $(date -d '+72 hours')
Duration: 72 hours
Container: ondo-oracle-monitor-72h
Purpose: Real oracle price divergence evidence

Status: RUNNING ✅

Commands:
- View logs: docker-compose logs -f ondo-oracle-monitor
- Check status: docker-compose ps
- Stop: docker-compose down
EOF

echo "📄 Status file created: monitoring_status.txt"
echo ""
echo "🎯 NEXT STEPS (After 72 hours):"
echo "1. Stop monitoring: docker-compose down"
echo "2. Package evidence from logs/ and data/ directories"
echo "3. Update Immunefi submission with real price data"
echo "4. Submit with enhanced evidence quality"
echo ""
echo "⏰ SET REMINDER: Check progress in 24, 48, and 72 hours"
echo ""

# Optional: Set system reminder (if at available)
if command -v at >/dev/null 2>&1; then
    echo "docker-compose -f $(pwd)/docker-compose.yml down && echo 'ONDO MONITORING COMPLETE - CHECK RESULTS IN $(pwd)/logs/'" | at now + 72 hours 2>/dev/null || true
    echo "🔔 System reminder set for 72 hours from now"
fi

echo "🚀 MONITORING IS NOW RUNNING - Capturing real oracle price divergence!"