#!/usr/bin/env python3
"""
Install dependencies for BBHK Tools Manager
Handles virtual environment setup for Kali Linux
"""

import subprocess
import sys
import os
from pathlib import Path

def install_dependencies():
    """Install required dependencies in a virtual environment"""
    
    # Create tools virtual environment
    venv_path = Path("/home/kali/bbhk/.venv")
    
    if not venv_path.exists():
        print("🔧 Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)
    
    # Install packages
    pip_path = venv_path / "bin" / "pip"
    python_path = venv_path / "bin" / "python"
    
    packages = [
        "qdrant-client",
        "sentence-transformers",
        "aiohttp",
        "numpy",
        "scikit-learn"
    ]
    
    print("📦 Installing Python packages...")
    for package in packages:
        print(f"  Installing {package}...")
        try:
            subprocess.run([str(pip_path), "install", package], 
                         check=True, capture_output=True, text=True)
            print(f"  ✅ {package} installed")
        except subprocess.CalledProcessError as e:
            print(f"  ❌ Failed to install {package}: {e}")
    
    # Create wrapper script
    wrapper_script = Path("/home/kali/bbhk/tools-cli-venv")
    wrapper_content = f'''#!/bin/bash
# BBHK Tools CLI with virtual environment
export PYTHONPATH="/home/kali/bbhk:$PYTHONPATH"
{python_path} /home/kali/bbhk/tools-cli "$@"
'''
    
    wrapper_script.write_text(wrapper_content)
    wrapper_script.chmod(0o755)
    
    print(f"✅ Created wrapper script: {wrapper_script}")
    print(f"Usage: ./tools-cli-venv discover")
    
    # Test the installation
    print("\n🧪 Testing installation...")
    try:
        result = subprocess.run([
            str(python_path), "-c", 
            "import qdrant_client; import sentence_transformers; print('All packages imported successfully')"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ All dependencies installed and working")
            return True
        else:
            print(f"❌ Import test failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    success = install_dependencies()
    if success:
        print("\n🚀 BBHK Tools Manager is ready!")
        print("Use: ./tools-cli-venv [command] to run with full functionality")
    else:
        print("\n⚠️ Some issues occurred during installation")
        print("You can still use ./tools-cli for basic functionality without embeddings")