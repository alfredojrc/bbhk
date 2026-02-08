#!/bin/bash
# Archive old and unnecessary files - KISS approach

ARCHIVE_DIR="/home/kali/bbhk/archive/docs-aug17-2025"
mkdir -p "$ARCHIVE_DIR"

echo "📦 Archiving old documentation..."

# Move old/redundant docs (keep only essential ones)
KEEP_FILES=(
    "MCP-SIMPLE-GUIDE.md"
    "MCP-COMPLETE-GUIDE.md" 
    "INDEX.md"
    "README.md"
    "SYSTEM-HEALTH-SUMMARY.md"
    "API-REFERENCE.md"
    "HACKER-QUICKSTART.md"
)

# Convert array to grep pattern
KEEP_PATTERN=$(printf "|%s" "${KEEP_FILES[@]}")
KEEP_PATTERN="${KEEP_PATTERN:1}"

# Archive docs that are not in keep list
cd /home/kali/bbhk/docs
for file in *.md; do
    if ! echo "$file" | grep -qE "($KEEP_PATTERN)"; then
        echo "  Archiving: $file"
        mv "$file" "$ARCHIVE_DIR/" 2>/dev/null
    fi
done

# Archive old test/demo scripts
cd /home/kali/bbhk
find . -type f -name "*.old" -o -name "*.backup" -o -name "*.obsolete" | while read -r file; do
    echo "  Archiving: $file"
    mv "$file" "$ARCHIVE_DIR/" 2>/dev/null
done

# Archive enterprise bloat
if [ -d "archive/enterprise-bloat" ]; then
    echo "  Already archived: enterprise-bloat"
fi

# Count results
REMAINING=$(ls /home/kali/bbhk/docs/*.md 2>/dev/null | wc -l)
ARCHIVED=$(ls "$ARCHIVE_DIR"/*.md 2>/dev/null | wc -l)

echo "✅ Archiving complete!"
echo "  📁 Remaining docs: $REMAINING (essential only)"
echo "  📦 Archived files: $ARCHIVED"
echo "  📍 Archive location: $ARCHIVE_DIR"