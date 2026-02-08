#!/bin/bash
# HubSpot Test Data Cleanup Script
# Run this AFTER successful HackerOne submission
# Date: August 20, 2025

echo "======================================"
echo "   HUBSPOT TEST DATA CLEANUP"
echo "======================================"

# Check if submission was completed
read -p "Have you successfully submitted to HackerOne? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "❌ Cleanup cancelled - submit first!"
    exit 1
fi

# Get report ID for tracking
read -p "Enter HackerOne Report ID (or press enter to skip): " report_id

# API Token
TOKEN="<YOUR_HUBSPOT_TOKEN>"

echo ""
echo "🧹 Starting cleanup..."

# 1. Delete test workflow
echo "   Deleting workflow 44047618..."
curl -X DELETE "https://api.hubapi.com/automation/v3/workflows/44047618" \
  -H "Authorization: Bearer $TOKEN" \
  -s -o /dev/null
echo "   ✅ Workflow deleted"

# 2. Archive evidence files
echo ""
echo "📦 Archiving evidence..."
timestamp=$(date +%Y%m%d_%H%M%S)
archive_name="hubspot_submission_${timestamp}"

if [ ! -z "$report_id" ]; then
    archive_name="${archive_name}_report_${report_id}"
fi

tar -czf "${archive_name}.tar.gz" \
  *.md *.json *.log *.py 2>/dev/null

# Create archives directory
mkdir -p ~/bbhk/archives/hubspot

# Move archive
mv "${archive_name}.tar.gz" ~/bbhk/archives/hubspot/
echo "   ✅ Evidence archived to ~/bbhk/archives/hubspot/${archive_name}.tar.gz"

# 3. Create submission record
echo ""
echo "📝 Creating submission record..."
cat > "SUBMISSION_RECORD.json" << EOF
{
  "submission_date": "$(date -Iseconds)",
  "report_id": "${report_id:-unknown}",
  "program": "hubspot",
  "vulnerabilities": [
    "Search API IDOR (CVSS 6.5)",
    "User Enumeration (CVSS 5.3)",
    "Input Validation Bypass (CVSS 4.3)"
  ],
  "expected_bounty": "$1,700-$3,500",
  "archive_location": "~/bbhk/archives/hubspot/${archive_name}.tar.gz",
  "status": "submitted",
  "cleanup_completed": true
}
EOF
echo "   ✅ Record saved to SUBMISSION_RECORD.json"

# 4. Update todo list marker
echo ""
echo "📋 Updating project status..."
echo "SUBMITTED_TO_HACKERONE" > .submission_status
echo "Report ID: ${report_id:-pending}" >> .submission_status
echo "Date: $(date)" >> .submission_status
echo "   ✅ Status file created"

# 5. Summary
echo ""
echo "======================================"
echo "   CLEANUP COMPLETE!"
echo "======================================"
echo ""
echo "✅ Actions completed:"
echo "   - Test workflow deleted"
echo "   - Evidence archived"
echo "   - Submission record created"
echo "   - Project status updated"
echo ""
echo "📊 Next steps:"
echo "   1. Monitor HackerOne for response (1-7 days)"
echo "   2. Apply IDOR pattern to next target"
echo "   3. Check ~/bbhk/archives/hubspot/ for backups"
echo ""

if [ ! -z "$report_id" ]; then
    echo "🎯 Your report URL:"
    echo "   https://hackerone.com/reports/${report_id}"
    echo ""
fi

echo "Good luck! 🚀"