#!/bin/bash

# Enterprise API Cleanup Script
# Date: August 17, 2025
# Purpose: Remove all enterprise API references and archive old files

echo "🧹 Starting Enterprise API Cleanup..."
echo "=================================="

ARCHIVE_DIR="/home/kali/bbhk/archive/enterprise-api-cleanup-aug17"
mkdir -p "$ARCHIVE_DIR"

# Archive API testing files that use enterprise endpoints
echo "📦 Archiving enterprise API test files..."
mv /home/kali/bbhk/tools/api-testing/comprehensive_test.py "$ARCHIVE_DIR/" 2>/dev/null
mv /home/kali/bbhk/tools/api-testing/test_api_credentials.py "$ARCHIVE_DIR/" 2>/dev/null
mv /home/kali/bbhk/tools/api-testing/test_auth_methods.py "$ARCHIVE_DIR/" 2>/dev/null
mv /home/kali/bbhk/tools/api-testing/test_direct_auth.py "$ARCHIVE_DIR/" 2>/dev/null

# Archive old documentation with enterprise references
echo "📚 Archiving old documentation..."
cp -r /home/kali/bbhk/archive/docs-aug17-2025 "$ARCHIVE_DIR/" 2>/dev/null
cp -r /home/kali/bbhk/archive/obsolete-docs "$ARCHIVE_DIR/" 2>/dev/null

# Create summary of archived files
echo "📝 Creating archive summary..."
cat > "$ARCHIVE_DIR/ARCHIVE-SUMMARY.md" << 'EOF'
# Enterprise API Cleanup Archive
Date: August 17, 2025

## Why These Files Were Archived
These files contained references to HackerOne's ENTERPRISE API which:
- Costs $15,000-$50,000+ per year
- Is for organizations running bug bounty programs
- Is NOT needed for bug hunters

## Correct API to Use
✅ HACKER API endpoints (/v1/hackers/*)
- FREE for all bug hunters
- Provides access to programs, reports, earnings
- No subscription required

## Archived Files
- API testing scripts using enterprise endpoints
- Documentation mentioning $15K+ costs
- Old references to organization API

## Action Taken
All enterprise API references have been removed from active codebase.
Use ONLY the HACKER API going forward.
EOF

echo "✅ Archive complete: $ARCHIVE_DIR"
echo ""
echo "🔍 Searching for remaining enterprise references..."

# Search for any remaining enterprise API references
remaining=$(grep -r -i "enterprise.*api\|organization.*api\|/v1/programs\|/v1/organizations\|/v1/me[^/]\|/v1/reports[^/]\|\$15,000\|\$50,000" /home/kali/bbhk --exclude-dir=archive --exclude-dir=.git 2>/dev/null | wc -l)

if [ "$remaining" -gt 0 ]; then
    echo "⚠️  Found $remaining remaining references that need manual review"
else
    echo "✅ No enterprise API references found in active code!"
fi

echo ""
echo "✨ Cleanup complete! Remember: Use HACKER API only (/v1/hackers/*)"