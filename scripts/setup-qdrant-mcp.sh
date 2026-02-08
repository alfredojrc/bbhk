#!/bin/bash

# Setup script for Qdrant MCP integration with Claude Code and Claude-Flow
# This script configures the Qdrant vector database with MCP server for the BBHK project

set -e

echo "========================================="
echo "BBHK Qdrant MCP Integration Setup"
echo "========================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_color $RED "Error: Docker is not installed"
        print_color $YELLOW "Please install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi
    print_color $GREEN "✓ Docker is installed"
}

# Check if Docker Compose is installed
check_docker_compose() {
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_color $RED "Error: Docker Compose is not installed"
        print_color $YELLOW "Please install Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
    print_color $GREEN "✓ Docker Compose is installed"
}

# Create necessary directories
create_directories() {
    print_color $BLUE "Creating necessary directories..."
    
    mkdir -p ./data/qdrant
    mkdir -p ./config/qdrant
    mkdir -p ./memory/mcp
    mkdir -p ./docker/mcp-qdrant
    mkdir -p ./logs
    
    print_color $GREEN "✓ Directories created"
}

# Generate Qdrant configuration
create_qdrant_config() {
    print_color $BLUE "Creating Qdrant configuration..."
    
    cat > ./config/qdrant/config.yaml << 'EOF'
log_level: INFO

service:
  http_port: 6333
  grpc_port: 6334
  # Uncomment for production with authentication
  # api_key: ${QDRANT_API_KEY}

storage:
  storage_path: /qdrant/storage
  # Performance optimizations
  wal:
    wal_capacity_mb: 32
    wal_segments_ahead: 0
  performance:
    max_search_threads: 0
    max_optimization_threads: 1

# Cluster configuration (for future scaling)
cluster:
  enabled: false
  # p2p:
  #   port: 6335
  # consensus:
  #   tick_period_ms: 100
EOF
    
    print_color $GREEN "✓ Qdrant configuration created"
}

# Setup environment variables
setup_env() {
    print_color $BLUE "Setting up environment variables..."
    
    if [ ! -f .env ]; then
        cat > .env << 'EOF'
# Qdrant Configuration
QDRANT_API_KEY=changeme-in-production
QDRANT_URL=http://localhost:6333
QDRANT_COLLECTION=bbhk-project

# MCP Server Configuration
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT=8000
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2

# Logging
LOG_LEVEL=INFO
EOF
        print_color $GREEN "✓ .env file created"
    else
        print_color $YELLOW "⚠ .env file already exists, skipping..."
    fi
}

# Configure Claude Code MCP
configure_claude_mcp() {
    print_color $BLUE "Configuring Claude Code MCP integration..."
    
    # Check if claude command exists
    if command -v claude &> /dev/null; then
        print_color $BLUE "Adding Qdrant MCP server to Claude Code..."
        
        # Add the MCP server configuration
        claude mcp add qdrant-bbhk \
            -e QDRANT_URL="http://localhost:6333" \
            -e COLLECTION_NAME="bbhk-project" \
            -e EMBEDDING_MODEL="sentence-transformers/all-MiniLM-L6-v2" \
            -e TOOL_STORE_DESCRIPTION="Store bug bounty research and vulnerabilities" \
            -e TOOL_FIND_DESCRIPTION="Search bug bounty patterns and vulnerabilities" \
            -- uvx mcp-server-qdrant
        
        print_color $GREEN "✓ MCP server added to Claude Code"
    else
        print_color $YELLOW "⚠ Claude Code CLI not found. Manual configuration required."
        print_color $YELLOW "Add the following to your Claude Code configuration:"
        cat << 'EOF'

{
  "mcpServers": {
    "qdrant-bbhk": {
      "type": "stdio",
      "command": "uvx",
      "args": ["mcp-server-qdrant"],
      "env": {
        "QDRANT_URL": "http://localhost:6333",
        "COLLECTION_NAME": "bbhk-project",
        "EMBEDDING_MODEL": "sentence-transformers/all-MiniLM-L6-v2",
        "TOOL_STORE_DESCRIPTION": "Store bug bounty research and vulnerabilities",
        "TOOL_FIND_DESCRIPTION": "Search bug bounty patterns and vulnerabilities"
      }
    }
  }
}
EOF
    fi
}

# Start the services
start_services() {
    print_color $BLUE "Starting Qdrant and MCP services..."
    
    # Use the appropriate docker-compose command
    if docker compose version &> /dev/null; then
        docker compose -f docker-compose.qdrant.yml up -d
    else
        docker-compose -f docker-compose.qdrant.yml up -d
    fi
    
    print_color $GREEN "✓ Services started"
    
    # Wait for services to be ready
    print_color $BLUE "Waiting for services to be ready..."
    sleep 10
    
    # Check if Qdrant is running
    if curl -f http://localhost:6333/health &> /dev/null; then
        print_color $GREEN "✓ Qdrant is running and healthy"
    else
        print_color $RED "✗ Qdrant is not responding"
        exit 1
    fi
    
    # Check if MCP server is running
    if curl -f http://localhost:8000/health &> /dev/null; then
        print_color $GREEN "✓ MCP server is running and healthy"
    else
        print_color $YELLOW "⚠ MCP server may take a moment to start..."
    fi
}

# Initialize collections
initialize_collections() {
    print_color $BLUE "Initializing Qdrant collections..."
    
    # Create the main collection
    curl -X PUT http://localhost:6333/collections/bbhk-project \
        -H "Content-Type: application/json" \
        -d '{
            "vectors": {
                "size": 384,
                "distance": "Cosine"
            },
            "optimizers_config": {
                "default_segment_number": 2
            },
            "replication_factor": 1
        }' &> /dev/null
    
    print_color $GREEN "✓ Collections initialized"
}

# Print usage instructions
print_usage() {
    print_color $GREEN "\n========================================="
    print_color $GREEN "Setup Complete!"
    print_color $GREEN "========================================="
    
    echo ""
    print_color $BLUE "Service URLs:"
    echo "  • Qdrant UI: http://localhost:6333/dashboard"
    echo "  • MCP Server: http://localhost:8000"
    echo "  • BBHK App: http://localhost:8080"
    echo "  • Dashboard: http://localhost:8081"
    
    echo ""
    print_color $BLUE "Available MCP Tools in Claude Code:"
    echo "  • qdrant-store: Store bug bounty patterns and vulnerabilities"
    echo "  • qdrant-find: Search for relevant patterns and code"
    
    echo ""
    print_color $BLUE "Docker Commands:"
    echo "  • View logs: docker-compose -f docker-compose.qdrant.yml logs -f"
    echo "  • Stop services: docker-compose -f docker-compose.qdrant.yml down"
    echo "  • Restart services: docker-compose -f docker-compose.qdrant.yml restart"
    
    echo ""
    print_color $YELLOW "Note: Restart Claude Code to load the new MCP server configuration"
}

# Main execution
main() {
    print_color $BLUE "Starting BBHK Qdrant MCP setup..."
    
    check_docker
    check_docker_compose
    create_directories
    create_qdrant_config
    setup_env
    configure_claude_mcp
    start_services
    initialize_collections
    print_usage
}

# Run main function
main "$@"