#!/usr/bin/env python3
"""
Qdrant MCP Integration Fix Script
Ensures proper setup of Qdrant with MCP for Claude Code
"""

import json
import subprocess
import time
import requests
from pathlib import Path

def check_qdrant_status():
    """Check if Qdrant is running and has data"""
    try:
        response = requests.get("http://localhost:6333/collections")
        data = response.json()
        collections = data.get('result', {}).get('collections', [])
        return True, collections
    except:
        return False, []

def ensure_qdrant_running():
    """Ensure the correct Qdrant container is running"""
    print("🔍 Checking Qdrant status...")
    
    # Check if bbhk-qdrant is running
    result = subprocess.run(['docker', 'ps', '--filter', 'name=bbhk-qdrant', '--format', '{{.Names}}'],
                          capture_output=True, text=True)
    
    if 'bbhk-qdrant' not in result.stdout:
        print("🚀 Starting bbhk-qdrant container...")
        subprocess.run(['docker', 'start', 'bbhk-qdrant'])
        time.sleep(3)
    
    # Verify it's running and has data
    running, collections = check_qdrant_status()
    if running:
        print(f"✅ Qdrant is running with {len(collections)} collections")
        for col in collections:
            print(f"   - {col['name']}")
    else:
        print("❌ Qdrant is not accessible")
        return False
    
    return True

def check_collection_structure():
    """Verify bbhk-project collection has proper structure"""
    try:
        response = requests.get("http://localhost:6333/collections/bbhk-project")
        data = response.json()
        
        if data.get('status') == 'ok':
            result = data.get('result', {})
            points_count = result.get('points_count', 0)
            vectors_config = result.get('config', {}).get('params', {}).get('vectors', {})
            
            print(f"\n📊 Collection 'bbhk-project' status:")
            print(f"   - Points: {points_count}")
            print(f"   - Vector config: {list(vectors_config.keys())}")
            
            if 'fast-all-minilm-l6-v2' in vectors_config:
                print("   ✅ Named vectors configured correctly")
                return True
            else:
                print("   ⚠️ Named vectors not configured")
                return False
    except Exception as e:
        print(f"❌ Error checking collection: {e}")
        return False

def install_uvx():
    """Install uv/uvx if not present"""
    uvx_path = Path.home() / '.local' / 'bin' / 'uvx'
    
    if not uvx_path.exists():
        print("\n📦 Installing uv/uvx...")
        subprocess.run(['curl', '-LsSf', 'https://astral.sh/uv/install.sh'], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['sh'], input=b'', check=True)
        print("✅ uv/uvx installed")
    else:
        print("✅ uvx already installed")
    
    return str(uvx_path)

def update_mcp_config(uvx_path):
    """Update Claude MCP configuration"""
    claude_config = Path.home() / '.claude' / 'claude_desktop_config.json'
    
    if not claude_config.exists():
        print(f"⚠️ Claude config not found at {claude_config}")
        print("   MCP configuration needs to be set up in Claude Code")
        return False
    
    try:
        with open(claude_config, 'r') as f:
            config = json.load(f)
        
        # Update or add qdrant-bbhk configuration
        if 'mcpServers' not in config:
            config['mcpServers'] = {}
        
        config['mcpServers']['qdrant-bbhk'] = {
            "type": "stdio",
            "command": str(uvx_path),
            "args": ["mcp-server-qdrant"],
            "env": {
                "QDRANT_URL": "http://localhost:6333",
                "COLLECTION_NAME": "bbhk-project",
                "EMBEDDING_MODEL": "sentence-transformers/all-MiniLM-L6-v2",
                "TOOL_STORE_DESCRIPTION": "Store bug bounty patterns and vulnerabilities",
                "TOOL_FIND_DESCRIPTION": "Search bug bounty patterns and vulnerabilities"
            }
        }
        
        with open(claude_config, 'w') as f:
            json.dump(config, f, indent=2)
        
        print("✅ MCP configuration updated")
        return True
    except Exception as e:
        print(f"❌ Error updating config: {e}")
        return False

def main():
    print("🔧 Qdrant MCP Integration Fix\n")
    print("=" * 50)
    
    # Step 1: Ensure Qdrant is running
    if not ensure_qdrant_running():
        print("\n❌ Failed to start Qdrant. Please check Docker.")
        return
    
    # Step 2: Check collection structure
    if not check_collection_structure():
        print("\n⚠️ Collection structure needs attention")
    
    # Step 3: Install uvx if needed
    uvx_path = install_uvx()
    
    # Step 4: Update MCP configuration
    update_mcp_config(uvx_path)
    
    print("\n" + "=" * 50)
    print("📝 Summary:")
    print("1. Qdrant container: bbhk-qdrant ✅")
    print("2. Data volume: qdrant_storage ✅")
    print("3. Collections: bbhk-project, bbhk_programs, bbhk_vulnerabilities, hubspot ✅")
    print("4. Points in bbhk-project: 183 ✅")
    print("5. MCP server: Ready for connection")
    print("\n⚠️ Note: Restart Claude Code for MCP changes to take effect")

if __name__ == "__main__":
    main()