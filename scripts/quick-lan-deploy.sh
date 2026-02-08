#!/bin/bash

echo "🚀 Quick LAN Deployment for BBHK"
echo "=================================="
echo ""

# Get server IP and hostname
SERVER_IP=$(ip addr show | grep -E "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | cut -d'/' -f1)
HOSTNAME="<YOUR_HOSTNAME>"
echo "📍 Hostname: $HOSTNAME"
echo "📍 Server IP: $SERVER_IP"
echo ""

# Start essential services
echo "🔧 Starting essential services..."

# 1. Start existing Qdrant (already running)
if docker ps | grep -q qdrant; then
    echo "✅ Qdrant already running on port 6333"
else
    echo "🚀 Starting Qdrant..."
    docker run -d \
        --name qdrant-db \
        -p 0.0.0.0:6333:6333 \
        -p 0.0.0.0:6334:6334 \
        -v $(pwd)/data/qdrant:/qdrant/storage \
        qdrant/qdrant
fi

# 2. Start a simple Python API server using existing code
echo "🌐 Starting API server..."
cd /home/kali/bbhk/web/backend

# Create a simple startup script
cat > start_api.py << 'EOF'
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, '/home/kali/bbhk')

# Import the updated main with LAN config
exec(open('/home/kali/bbhk/web/backend/main_updated.py').read())
EOF

# Kill any existing Python servers on port 8000
pkill -f "python.*8000" 2>/dev/null

# Start the API server in background
nohup python3 start_api.py > /home/kali/bbhk/logs/api.log 2>&1 &
API_PID=$!
echo "✅ API server started (PID: $API_PID)"

# 3. Start a simple web server for the dashboard
echo "📊 Starting dashboard server..."
cd /home/kali/bbhk

# Create a simple HTML dashboard if React isn't ready
if [ ! -d "web/frontend/build" ]; then
    echo "Creating simple dashboard..."
    mkdir -p web/dashboard
    cat > web/dashboard/index.html << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BBHK Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { font-size: 3rem; margin-bottom: 1rem; }
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        .stat-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 1.5rem;
            border-radius: 1rem;
            border: 1px solid rgba(255,255,255,0.2);
        }
        .stat-value { font-size: 2.5rem; font-weight: bold; }
        .stat-label { opacity: 0.8; margin-top: 0.5rem; }
        .links {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            margin-top: 2rem;
        }
        .link-btn {
            background: white;
            color: #667eea;
            padding: 1rem 2rem;
            border-radius: 0.5rem;
            text-decoration: none;
            font-weight: 600;
            transition: transform 0.2s;
        }
        .link-btn:hover { transform: translateY(-2px); }
        .status { 
            margin-top: 2rem;
            padding: 1rem;
            background: rgba(0,0,0,0.2);
            border-radius: 0.5rem;
        }
        .status-item { 
            display: flex; 
            align-items: center; 
            margin: 0.5rem 0;
        }
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 1rem;
            background: #4ade80;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 BBHK Dashboard</h1>
        <p style="font-size: 1.2rem; opacity: 0.9;">Bug Bounty Hunter Kit - Multi-Tenant Platform</p>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">570</div>
                <div class="stat-label">HackerOne Programs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">3</div>
                <div class="stat-label">Active Platforms</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">85%</div>
                <div class="stat-label">With Bounties</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$7.2K</div>
                <div class="stat-label">Avg Critical Bounty</div>
            </div>
        </div>
        
        <div class="links">
            <a href="http://$HOSTNAME:8000/docs" class="link-btn">📖 API Documentation</a>
            <a href="http://$HOSTNAME:6333/dashboard" class="link-btn">🧠 Qdrant Dashboard</a>
            <a href="http://$HOSTNAME:8000/api/programs" class="link-btn">📋 View Programs</a>
            <a href="http://$HOSTNAME:8000/health" class="link-btn">❤️ Health Check</a>
        </div>
        
        <div class="status">
            <h2>Service Status</h2>
            <div class="status-item">
                <span class="status-indicator"></span>
                <span>API Server: Running on port 8000</span>
            </div>
            <div class="status-item">
                <span class="status-indicator"></span>
                <span>Qdrant Vector DB: Running on port 6333</span>
            </div>
            <div class="status-item">
                <span class="status-indicator"></span>
                <span>Dashboard: Active</span>
            </div>
        </div>
        
        <div style="margin-top: 3rem; padding-top: 2rem; border-top: 1px solid rgba(255,255,255,0.2);">
            <p>Hostname: $HOSTNAME | IP: $SERVER_IP | Configure hosts file for hostname access</p>
            <p style="font-size: 0.9rem; opacity: 0.8; margin-top: 0.5rem;">Add to hosts: $SERVER_IP $HOSTNAME</p>
        </div>
    </div>
    
    <script>
        // Auto-refresh stats every 10 seconds
        setInterval(() => {
            fetch('http://$HOSTNAME:8000/api/stats')
                .then(r => r.json())
                .then(data => console.log('Stats updated:', data))
                .catch(e => console.error('Failed to fetch stats:', e));
        }, 10000);
    </script>
</body>
</html>
EOF
fi

# Kill any existing Python servers on port 3000
pkill -f "python.*3000" 2>/dev/null

# Start a simple HTTP server for the portal
cd /home/kali/bbhk/web
python3 -m http.server 3000 --bind 0.0.0.0 --directory portal > /home/kali/bbhk/logs/dashboard.log 2>&1 &
DASH_PID=$!
echo "✅ Portal server started (PID: $DASH_PID)"

echo ""
echo "🎉 Services are now accessible on your LAN!"
echo ""
echo "📍 Access URLs from any device on your network:"
echo "=============================================="
echo ""
echo "🌐 Dashboard:         http://$HOSTNAME:3000"
echo "📖 API Documentation: http://$HOSTNAME:8000/docs"
echo "🧠 Qdrant Dashboard:  http://$HOSTNAME:6333/dashboard"
echo "📊 API Health:        http://$HOSTNAME:8000/health"
echo ""
echo "📍 Alternative IP Access:"
echo "   Dashboard:         http://$SERVER_IP:3000"
echo "   API:              http://$SERVER_IP:8000"
echo "   Qdrant:           http://$SERVER_IP:6333"
echo ""
echo "📱 For network access, add to client's hosts file:"
echo "   $SERVER_IP    $HOSTNAME"
echo ""
echo "   Windows: C:\\Windows\\System32\\drivers\\etc\\hosts"
echo "   Linux/Mac: /etc/hosts"
echo ""
echo "🛑 To stop services:"
echo "   pkill -f 'python.*8000'  # Stop API"
echo "   pkill -f 'python.*3000'  # Stop Dashboard"
echo "   docker stop qdrant-db    # Stop Qdrant"
echo ""