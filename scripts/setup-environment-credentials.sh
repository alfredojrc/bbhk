#!/bin/bash
# BBHK Environment Configuration Script
# Sets up environment variables for production scripts

echo "🔧 BBHK Environment Configuration"
echo "================================="
echo ""

# Check if credentials file exists
CREDS_FILE="/home/kali/bbhk/.env"

if [ ! -f "$CREDS_FILE" ]; then
    echo "📝 Creating environment configuration file..."
    cat > "$CREDS_FILE" << 'EOF'
# BBHK Production Environment Variables
# Copy this to .env and fill in your actual credentials

# HackerOne API Credentials
HACKERONE_USERNAME=your_username_here
HACKERONE_API_TOKEN=your_api_token_here

# Database Configuration
BBHK_DB_PATH=/home/kali/bbhk/core/database/bbhk.db

# Qdrant Configuration
QDRANT_URL=http://<YOUR_HOSTNAME>:6333
QDRANT_COLLECTION=bbhk_programs

# Application Settings
BBHK_LOG_LEVEL=INFO
BBHK_ENVIRONMENT=production
EOF

    echo "✅ Created .env template at: $CREDS_FILE"
    echo ""
    echo "⚠️  IMPORTANT: Edit $CREDS_FILE with your actual credentials"
    echo ""
else
    echo "✅ Environment file already exists: $CREDS_FILE"
fi

echo "🔍 Environment Setup Instructions:"
echo ""
echo "1. Edit the .env file with your credentials:"
echo "   nano $CREDS_FILE"
echo ""
echo "2. Source the environment before running scripts:"
echo "   source $CREDS_FILE"
echo ""
echo "3. Or export variables directly:"
echo "   export HACKERONE_USERNAME=\"your_username\""
echo "   export HACKERONE_API_TOKEN=\"your_token\""
echo ""
echo "🔒 Security Notes:"
echo "- Never commit .env file to version control"
echo "- Keep credentials secure and rotate regularly"
echo "- Use different tokens for different environments"
echo ""
echo "📋 Scripts requiring credentials:"
echo "- scripts/data/fetch-real-hackerone-data.py"
echo "- scripts/data/get_all_programs.py"
echo "- scripts/api/hackerone-api-explorer.py"
echo "- scripts/data/extract-full-program-data.py"
echo ""
echo "✅ Environment configuration complete!"