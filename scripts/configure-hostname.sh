#!/bin/bash

# BBHK Hostname Configuration Script
# Configures all services to use hostname '<YOUR_HOSTNAME>'

HOSTNAME="<YOUR_HOSTNAME>"
SERVER_IP=$(ip addr show | grep -E "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | cut -d'/' -f1)

echo "🌐 BBHK Hostname Configuration"
echo "================================"
echo ""
echo "📍 Hostname: $HOSTNAME"
echo "📍 Server IP: $SERVER_IP"
echo ""

# 1. Update system hostname if needed
CURRENT_HOSTNAME=$(hostname)
if [ "$CURRENT_HOSTNAME" != "$HOSTNAME" ]; then
    echo "⚠️  Current hostname is '$CURRENT_HOSTNAME', not '$HOSTNAME'"
    echo "   To change it, run: sudo hostnamectl set-hostname $HOSTNAME"
fi

# 2. Create hosts file entry for local resolution
echo "📝 Add this line to /etc/hosts on the server:"
echo "   127.0.0.1    $HOSTNAME"
echo ""

# 3. Create network hosts guide
cat > /home/kali/bbhk/docs/NETWORK-ACCESS.md << EOF
# 🌐 BBHK Network Access Configuration

## Hostname-Based Access

All BBHK services are configured to be accessible via the hostname: **$HOSTNAME**

### For Server (Local Access)

Add to \`/etc/hosts\`:
\`\`\`
127.0.0.1    $HOSTNAME
\`\`\`

### For LAN Devices (Network Access)

On each device that needs to access BBHK services, add to hosts file:

#### Windows (C:\\Windows\\System32\\drivers\\etc\\hosts):
\`\`\`
$SERVER_IP    $HOSTNAME
\`\`\`

#### Linux/Mac (/etc/hosts):
\`\`\`
$SERVER_IP    $HOSTNAME
\`\`\`

#### Mobile Devices:
- Use DNS apps or router configuration
- Or access directly via IP: $SERVER_IP

## Service URLs

Once hostname is configured, access services at:

- 🌐 **Dashboard**: http://$HOSTNAME:3000
- 📖 **API Documentation**: http://$HOSTNAME:8000/docs
- 🧠 **Qdrant Dashboard**: http://$HOSTNAME:6333/dashboard
- 📊 **API Endpoints**: http://$HOSTNAME:8000/api/
- ❤️ **Health Check**: http://$HOSTNAME:8000/health

## Quick Test

Test hostname resolution:
\`\`\`bash
ping $HOSTNAME
curl http://$HOSTNAME:8000/health
\`\`\`

## Alternative Access

If hostname resolution is not configured, use IP directly:
- Dashboard: http://$SERVER_IP:3000
- API: http://$SERVER_IP:8000
- Qdrant: http://$SERVER_IP:6333
EOF

echo "✅ Created /home/kali/bbhk/docs/NETWORK-ACCESS.md"

# 4. Update .env file
if [ -f /home/kali/bbhk/.env ]; then
    cp /home/kali/bbhk/.env /home/kali/bbhk/.env.backup
    sed -i "s|REACT_APP_API_URL=.*|REACT_APP_API_URL=http://$HOSTNAME:8000|" /home/kali/bbhk/.env
    echo "✅ Updated .env file"
fi

# 5. Update docker-compose.override.yml
cat > /home/kali/bbhk/docker-compose.override.yml << EOF
version: '3.8'

services:
  backend:
    environment:
      - HOST=0.0.0.0
      - PORT=8000
      - CORS_ORIGINS=["http://localhost:3000","http://$HOSTNAME:3000","http://$HOSTNAME","http://$SERVER_IP:3000"]
      - PUBLIC_HOSTNAME=$HOSTNAME
    ports:
      - "0.0.0.0:8000:8000"

  frontend:
    environment:
      - REACT_APP_API_URL=http://$HOSTNAME:8000
      - HOST=0.0.0.0
      - PORT=3000
      - PUBLIC_HOSTNAME=$HOSTNAME
    ports:
      - "0.0.0.0:3000:3000"

  nginx:
    ports:
      - "0.0.0.0:80:80"

  qdrant:
    environment:
      - QDRANT__SERVICE__HTTP_PORT=6333
      - QDRANT__SERVICE__HOST=0.0.0.0
    ports:
      - "0.0.0.0:6333:6333"
EOF

echo "✅ Updated docker-compose.override.yml"
echo ""
echo "🎉 Hostname configuration complete!"
echo ""
echo "📋 Next Steps:"
echo "1. Add '$SERVER_IP $HOSTNAME' to /etc/hosts on client devices"
echo "2. Test access: curl http://$HOSTNAME:8000/health"
echo "3. Access dashboard: http://$HOSTNAME:3000"
echo ""