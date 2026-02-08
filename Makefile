# BBHK Docker Management Makefile
# Simplifies common Docker operations

.PHONY: help setup build start stop restart logs status clean backup restore monitor test

# Default target
help:
	@echo "BBHK Docker Management"
	@echo "====================="
	@echo ""
	@echo "Available targets:"
	@echo "  setup          - Initial setup (install Docker, create config)"
	@echo "  build          - Build Docker images"
	@echo "  start          - Start all services"
	@echo "  start-prod     - Start with PostgreSQL (production)"
	@echo "  start-monitor  - Start with monitoring (Prometheus/Grafana)"
	@echo "  stop           - Stop all services"
	@echo "  restart        - Restart all services"
	@echo "  logs           - Show logs (use SERVICE=name for specific service)"
	@echo "  status         - Show service status"
	@echo "  health         - Quick health check"
	@echo "  monitor        - Start continuous monitoring"
	@echo "  backup         - Create backup"
	@echo "  restore        - Restore from backup (use BACKUP_ID=id)"
	@echo "  clean          - Clean up containers and volumes"
	@echo "  clean-all      - Clean everything including images"
	@echo "  test           - Run tests"
	@echo "  shell-backend  - Open shell in backend container"
	@echo "  shell-frontend - Open shell in frontend container"
	@echo "  db-shell       - Open database shell"
	@echo "  update         - Update and rebuild services"
	@echo ""
	@echo "Examples:"
	@echo "  make setup"
	@echo "  make start"
	@echo "  make logs SERVICE=backend"
	@echo "  make restore BACKUP_ID=20250816_143022"

# Initial setup
setup:
	@echo "🚀 Running initial setup..."
	./scripts/docker-setup.sh

# Build images
build:
	@echo "🔨 Building Docker images..."
	docker-compose build

# Start services (development mode with SQLite)
start:
	@echo "🚀 Starting BBHK services..."
	docker-compose up -d
	@echo "✅ Services started!"
	@echo "   Dashboard: http://localhost:3000"
	@echo "   API: http://localhost:8000"
	@echo "   Nginx: http://localhost:80"

# Start production mode (with PostgreSQL)
start-prod:
	@echo "🚀 Starting BBHK in production mode..."
	docker-compose --profile production up -d
	@echo "✅ Production services started!"

# Start with monitoring
start-monitor:
	@echo "🚀 Starting BBHK with monitoring..."
	docker-compose --profile monitoring up -d
	@echo "✅ Services with monitoring started!"
	@echo "   Prometheus: http://localhost:9090"
	@echo "   Grafana: http://localhost:3001"

# Stop services
stop:
	@echo "🛑 Stopping BBHK services..."
	docker-compose down

# Restart services
restart: stop start

# Show logs
logs:
ifdef SERVICE
	@echo "📋 Showing logs for $(SERVICE)..."
	docker-compose logs -f $(SERVICE)
else
	@echo "📋 Showing all logs..."
	docker-compose logs -f
endif

# Show status
status:
	@echo "📊 Service status:"
	docker-compose ps
	@echo ""
	@echo "📈 Resource usage:"
	docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# Quick health check
health:
	@./scripts/monitor.sh quick

# Continuous monitoring
monitor:
	@./scripts/monitor.sh continuous

# Create backup
backup:
	@echo "💾 Creating backup..."
	./scripts/backup.sh

# Restore from backup
restore:
ifdef BACKUP_ID
	@echo "🔄 Restoring from backup $(BACKUP_ID)..."
	./scripts/restore.sh restore $(BACKUP_ID)
else
	@echo "❌ Please specify BACKUP_ID"
	@echo "Usage: make restore BACKUP_ID=20250816_143022"
	@./scripts/restore.sh list
endif

# Clean up containers and volumes
clean:
	@echo "🧹 Cleaning up containers and volumes..."
	docker-compose down -v --remove-orphans
	docker system prune -f

# Clean everything including images
clean-all:
	@echo "🧹 Cleaning everything..."
	docker-compose down -v --remove-orphans --rmi all
	docker system prune -af --volumes

# Run tests
test:
	@echo "🧪 Running tests..."
	docker-compose exec backend python -m pytest tests/ -v
	@echo "🧪 Running frontend tests..."
	docker-compose exec frontend npm test -- --coverage --watchAll=false

# Open shell in backend container
shell-backend:
	@echo "🐚 Opening shell in backend container..."
	docker-compose exec backend /bin/bash

# Open shell in frontend container  
shell-frontend:
	@echo "🐚 Opening shell in frontend container..."
	docker-compose exec frontend /bin/sh

# Open database shell
db-shell:
	@echo "🗄️ Opening database shell..."
	@if docker-compose ps postgres | grep -q Up; then \
		echo "Opening PostgreSQL shell..."; \
		docker-compose exec postgres psql -U bbhk_user -d bbhk_production; \
	else \
		echo "Opening SQLite shell..."; \
		sqlite3 core/database/bbhk.db; \
	fi

# Update and rebuild services
update:
	@echo "🔄 Updating and rebuilding services..."
	docker-compose pull
	docker-compose build --no-cache
	docker-compose up -d
	@echo "✅ Update completed!"

# Development helpers
dev-setup: setup build start
	@echo "🎉 Development environment ready!"

# Production deployment
prod-deploy: setup build start-prod
	@echo "🎉 Production environment deployed!"

# Full monitoring stack
monitor-deploy: setup build start-monitor
	@echo "🎉 Monitoring stack deployed!"

# Reset everything (destructive)
reset: clean-all setup build start
	@echo "🎉 Complete reset completed!"

# Show configuration
config:
	@echo "📄 Current configuration:"
	@echo "========================"
	@if [ -f .env ]; then \
		echo "Environment file: ✅ Present"; \
		echo "Database: $$(grep DATABASE_URL .env | cut -d= -f2)"; \
		echo "API URL: $$(grep REACT_APP_API_URL .env | cut -d= -f2)"; \
	else \
		echo "Environment file: ❌ Missing"; \
	fi
	@echo ""
	@echo "Docker Compose configuration:"
	docker-compose config --services 2>/dev/null || echo "❌ Docker Compose not available"

# Database operations
db-backup:
	@echo "💾 Creating database backup..."
	./scripts/backup.sh

db-migrate:
	@echo "🔄 Running database migrations..."
	docker-compose exec backend python -c "from src.core.database import init_db; init_db()"

# Security scan
security-scan:
	@echo "🔒 Running security scan..."
	@if command -v trivy >/dev/null 2>&1; then \
		trivy image bbhk-backend:latest; \
		trivy image bbhk-frontend:latest; \
	else \
		echo "⚠️  Trivy not installed. Install with: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"; \
	fi

# Performance test
perf-test:
	@echo "⚡ Running performance tests..."
	@if command -v ab >/dev/null 2>&1; then \
		echo "Testing API endpoint..."; \
		ab -n 100 -c 10 http://localhost:8000/; \
		echo "Testing frontend..."; \
		ab -n 100 -c 10 http://localhost:3000/; \
	else \
		echo "⚠️  Apache Bench not installed. Install with: sudo apt install apache2-utils"; \
	fi

# Show resource usage
resources:
	@echo "📊 Resource usage:"
	@echo "=================="
	@echo "Docker system usage:"
	docker system df
	@echo ""
	@echo "Container resource usage:"
	docker stats --no-stream
	@echo ""
	@echo "Host system usage:"
	df -h /
	free -h