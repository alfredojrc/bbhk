# 🚀 BBHK QUICK START GUIDE
**Bug Bounty Hunter Kit - Multi-Tab Intelligence Platform**

## ⚡ ONE-COMMAND START

```bash
./scripts/start-all-services.sh
```

## 🌐 ACCESS POINTS

### Main Portal (Multi-Tab Interface)
**URL:** http://<YOUR_HOSTNAME>:8080/index-multitab.html

### API Documentation
**URL:** http://<YOUR_HOSTNAME>:8000/docs

### Database
**Host:** <YOUR_HOSTNAME>:5432
**Database:** bbhk_db
**User:** bbhk_user

## 📱 FEATURES

### 6 Main Tabs:
1. **Dashboard** - Overview & high-value opportunities
2. **Campaigns** - Bug bounty campaign management
3. **Opportunities** - Browse & filter bounties ($50K+, $25K+, etc.)
4. **Programs** - All HackerOne programs
5. **Leaderboard** - Top hackers rankings
6. **Analytics** - Platform statistics

### Key Features:
- ✅ Sort by highest/lowest bounties
- ✅ Filter by bounty amount
- ✅ Campaign detail views
- ✅ Real-time data from PostgreSQL
- ✅ Dark theme with modern UI

## 🛠️ MANAGEMENT

### Check Services Status
```bash
docker ps
ss -tulpn | grep LISTEN
```

### View Logs
```bash
tail -f /tmp/bbhk-api.log
tail -f /tmp/bbhk-portal.log
```

### Stop All Services
```bash
pkill -f 'python.*bbhk'
```

### Restart Services
```bash
./scripts/start-all-services.sh
```

## 📊 DATABASE OPERATIONS

### Add More Programs
```bash
python3 scripts/data/populate-hackerone-data.py
```

### Check Data
```bash
docker exec bbhk-postgres psql -U bbhk_user -d bbhk_db -c "SELECT COUNT(*) FROM programs;"
```

## 🔧 TROUBLESHOOTING

### Port Already in Use?
```bash
pkill -f "python.*8000"
pkill -f "python.*8080"
```

### Database Connection Issues?
```bash
docker restart bbhk-postgres
```

### Can't Access from Remote?
Ensure firewall allows ports 8000, 8080, 5432

## 📁 PROJECT STRUCTURE

```
/home/kali/bbhk/
├── web/
│   ├── portal_enhanced/     # Multi-tab UI
│   │   ├── index-multitab.html
│   │   ├── config.js        # Hostname config
│   │   └── api.js           # API client
│   └── backend/
│       └── api_enhanced.py  # FastAPI backend
├── scripts/
│   ├── start-all-services.sh  # One-click start
│   └── data/
│       └── populate-hackerone-data.py
├── migration/
│   └── schema/              # PostgreSQL schemas
└── docs/                    # Documentation
```

## 🎯 KISS PRINCIPLE APPLIED

- **One Script** starts everything
- **One Config** file for hostnames
- **One Portal** with all features
- **Simple URLs** using <YOUR_HOSTNAME> hostname
- **No complex dependencies**

---
**Working as of:** August 17, 2025
**Hostname:** <YOUR_HOSTNAME> (<YOUR_LAN_IP>)