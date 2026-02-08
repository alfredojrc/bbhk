#!/usr/bin/env python3
"""
BBHK Architecture Documentation Generator
Generates comprehensive documentation from architecture files.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, List
import argparse
from datetime import datetime


class ArchitectureDocGenerator:
    """Generates documentation from BBHK architecture definitions."""
    
    def __init__(self, bbhk_root: str = "/home/kali/bbhk"):
        self.bbhk_root = Path(bbhk_root)
        self.config_dir = self.bbhk_root / "config"
        self.agents_dir = self.bbhk_root / "agents"
        self.core_dir = self.bbhk_root / "core"
        
    def load_yaml_file(self, file_path: Path) -> Dict[Any, Any]:
        """Load and parse a YAML file."""
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            return {}
    
    def generate_system_overview(self) -> str:
        """Generate system overview documentation."""
        doc = "# BBHK System Architecture Overview\n\n"
        doc += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Directory Structure
        doc += "## Directory Structure\n\n"
        doc += "```\n"
        doc += "bbhk/\n"
        doc += "├── INDEX.md           # Master navigation\n"
        doc += "├── FRAMEWORK.md       # Core principles\n"
        doc += "├── core/             # Core framework\n"
        doc += "│   ├── database/     # Schema and migrations\n"
        doc += "│   ├── api/          # Platform integrations\n"
        doc += "│   ├── engine/       # Automation engine\n"
        doc += "│   └── security/     # Security components\n"
        doc += "├── config/           # Configuration management\n"
        doc += "│   ├── system.yaml   # System configuration\n"
        doc += "│   ├── platforms.yaml# Platform definitions\n"
        doc += "│   ├── rules.yaml    # Rule hierarchy\n"
        doc += "│   └── schemas/      # Validation schemas\n"
        doc += "├── agents/           # Agent system\n"
        doc += "│   ├── registry/     # Agent definitions\n"
        doc += "│   ├── state/        # State persistence\n"
        doc += "│   └── workflows/    # Coordination patterns\n"
        doc += "├── data/             # Generated data (auto-managed)\n"
        doc += "│   ├── programs/     # Program data\n"
        doc += "│   ├── findings/     # Vulnerability findings\n"
        doc += "│   ├── reports/      # Generated reports\n"
        doc += "│   └── cache/        # Temporary data\n"
        doc += "└── tools/            # External tools\n"
        doc += "    ├── scanners/     # Security scanners\n"
        doc += "    ├── utilities/    # Helper scripts\n"
        doc += "    └── integrations/ # Third-party tools\n"
        doc += "```\n\n"
        
        return doc
    
    def generate_database_docs(self) -> str:
        """Generate database schema documentation."""
        doc = "## Database Architecture\n\n"
        
        schema_file = self.core_dir / "database" / "schema.sql"
        if schema_file.exists():
            doc += "### Entity Relationship Overview\n\n"
            doc += "```mermaid\n"
            doc += "erDiagram\n"
            doc += "    PLATFORMS ||--o{ PROGRAMS : hosts\n"
            doc += "    PROGRAMS ||--o{ TARGETS : contains\n"
            doc += "    PROGRAMS ||--o{ FINDINGS : generates\n"
            doc += "    TARGETS ||--o{ FINDINGS : affects\n"
            doc += "    AGENTS ||--o{ TASKS : executes\n"
            doc += "    TASKS ||--o{ FINDINGS : produces\n"
            doc += "    FINDINGS ||--o{ REPORTS : generates\n"
            doc += "    PLATFORMS ||--o{ REPORTS : receives\n"
            doc += "```\n\n"
            
            doc += "### Key Tables\n\n"
            doc += "| Table | Purpose | Scaling |\n"
            doc += "|-------|---------|--------|\n"
            doc += "| platforms | Bug bounty platforms | ~10 rows |\n"
            doc += "| programs | Bug bounty programs | ~100+ rows |\n"
            doc += "| targets | Individual targets | ~1000+ rows |\n"
            doc += "| findings | Security findings | ~1000+ rows |\n"
            doc += "| agents | Agent instances | ~20 rows |\n"
            doc += "| tasks | Agent tasks | ~10000+ rows |\n"
            doc += "| reports | Generated reports | ~1000+ rows |\n\n"
        
        return doc
    
    def generate_agent_docs(self) -> str:
        """Generate agent system documentation."""
        doc = "## Agent System Architecture\n\n"
        
        # Load agent types
        agent_types_file = self.agents_dir / "registry" / "agent_types.yaml"
        if agent_types_file.exists():
            agent_types = self.load_yaml_file(agent_types_file)
            
            doc += "### Available Agent Types\n\n"
            for agent_type, details in agent_types.get('agent_types', {}).items():
                doc += f"#### {agent_type}\n"
                doc += f"**Description**: {details.get('description', 'N/A')}\n\n"
                
                if 'capabilities' in details:
                    doc += "**Capabilities**:\n"
                    for cap in details['capabilities']:
                        doc += f"- {cap}\n"
                    doc += "\n"
                
                if 'tools' in details:
                    doc += "**Tools**:\n"
                    for tool in details['tools']:
                        doc += f"- {tool}\n"
                    doc += "\n"
                
                if 'resources' in details:
                    resources = details['resources']
                    doc += f"**Resources**: CPU: {resources.get('cpu', 'N/A')}, "
                    doc += f"Memory: {resources.get('memory', 'N/A')}, "
                    doc += f"Network: {resources.get('network', 'N/A')}\n\n"
        
        return doc
    
    def generate_flow_docs(self) -> str:
        """Generate information flow documentation."""
        doc = "## Information Flow Architecture\n\n"
        
        flow_file = self.agents_dir / "workflows" / "information_flow.yaml"
        if flow_file.exists():
            flow_data = self.load_yaml_file(flow_file)
            
            doc += "### Core Flow Patterns\n\n"
            for flow_name, flow_details in flow_data.get('flow_patterns', {}).items():
                doc += f"#### {flow_name.replace('_', ' ').title()}\n"
                doc += f"**Trigger**: {flow_details.get('trigger', 'N/A')}\n\n"
                
                if 'steps' in flow_details:
                    doc += "**Steps**:\n"
                    for i, step in enumerate(flow_details['steps'], 1):
                        doc += f"{i}. **{step.get('name', 'Unnamed')}** "
                        doc += f"({step.get('agent', 'No agent')})\n"
                        doc += f"   - Input: {step.get('input', 'N/A')}\n"
                        doc += f"   - Output: {step.get('output', 'N/A')}\n"
                        if 'depends_on' in step:
                            doc += f"   - Depends on: {', '.join(step['depends_on'])}\n"
                    doc += "\n"
        
        return doc
    
    def generate_scaling_docs(self) -> str:
        """Generate scaling patterns documentation."""
        doc = "## Scaling Architecture\n\n"
        
        doc += "### Designed Scale Limits\n\n"
        doc += "| Component | Target Scale | Notes |\n"
        doc += "|-----------|--------------|-------|\n"
        doc += "| Platforms | 10+ | Major bug bounty platforms |\n"
        doc += "| Programs | 100+ | Active programs per platform |\n"
        doc += "| Targets | 1000+ | Individual targets per program |\n"
        doc += "| Findings | 1000+ | Security findings per month |\n"
        doc += "| Concurrent Agents | 10-20 | Configurable based on resources |\n"
        doc += "| Files per Directory | 50 | Prevents file system explosion |\n\n"
        
        doc += "### Scaling Strategies\n\n"
        doc += "#### Horizontal Scaling\n"
        doc += "- Agent pools by platform type\n"
        doc += "- Distributed finding storage\n"
        doc += "- Load-balanced API calls\n"
        doc += "- Sharded data by program ID\n\n"
        
        doc += "#### Vertical Scaling\n"
        doc += "- Program prioritization algorithms\n"
        doc += "- Dynamic resource allocation\n"
        doc += "- Tool optimization and caching\n"
        doc += "- Intelligent task scheduling\n\n"
        
        return doc
    
    def generate_security_docs(self) -> str:
        """Generate security architecture documentation."""
        doc = "## Security Architecture\n\n"
        
        doc += "### Security Boundaries\n\n"
        doc += "#### Isolation Levels\n"
        doc += "1. **Platform APIs** - Isolated credentials per platform\n"
        doc += "2. **Tool Execution** - Sandboxed environment for tools\n"
        doc += "3. **Data Storage** - Encrypted findings and reports\n"
        doc += "4. **Agent Communication** - Validated message passing\n\n"
        
        doc += "#### Validation Gates\n"
        doc += "- Platform rule validation before execution\n"
        doc += "- Finding validation before reporting\n"
        doc += "- Tool safety validation before use\n"
        doc += "- Report validation before submission\n\n"
        
        return doc
    
    def generate_config_docs(self) -> str:
        """Generate configuration documentation."""
        doc = "## Configuration Management\n\n"
        
        # System config
        system_config_file = self.config_dir / "system.yaml"
        if system_config_file.exists():
            config = self.load_yaml_file(system_config_file)
            doc += "### System Configuration\n\n"
            
            if 'limits' in config:
                doc += "#### System Limits\n"
                for key, value in config['limits'].items():
                    doc += f"- **{key.replace('_', ' ').title()}**: {value}\n"
                doc += "\n"
        
        # Platform config
        platforms_file = self.config_dir / "platforms.yaml"
        if platforms_file.exists():
            platforms = self.load_yaml_file(platforms_file)
            doc += "### Supported Platforms\n\n"
            
            for platform_id, platform_data in platforms.get('platforms', {}).items():
                doc += f"#### {platform_data.get('name', platform_id)}\n"
                doc += f"- **API Base**: {platform_data.get('api_base', 'N/A')}\n"
                doc += f"- **Auth Type**: {platform_data.get('auth_type', 'N/A')}\n"
                if 'rate_limit' in platform_data:
                    rate_limit = platform_data['rate_limit']
                    doc += f"- **Rate Limit**: {rate_limit.get('requests_per_minute', 'N/A')} req/min\n"
                doc += "\n"
        
        return doc
    
    def generate_full_documentation(self) -> str:
        """Generate complete architecture documentation."""
        doc = self.generate_system_overview()
        doc += self.generate_database_docs()
        doc += self.generate_agent_docs()
        doc += self.generate_flow_docs()
        doc += self.generate_scaling_docs()
        doc += self.generate_security_docs()
        doc += self.generate_config_docs()
        
        doc += "## Quick Reference\n\n"
        doc += "### Essential Files (Never Delete)\n"
        doc += "- `/INDEX.md` - Master navigation\n"
        doc += "- `/FRAMEWORK.md` - Core principles\n"
        doc += "- `/config/system.yaml` - System configuration\n"
        doc += "- `/config/platforms.yaml` - Platform definitions\n"
        doc += "- `/config/rules.yaml` - Rule hierarchy\n\n"
        
        doc += "### File Limits\n"
        doc += "- Maximum 50 files per `/data` subdirectory\n"
        doc += "- Maximum 3 directory levels\n"
        doc += "- Auto-cleanup of cache files after 1 day\n"
        doc += "- Reports archived after 90 days\n"
        doc += "- Findings archived after 90 days\n\n"
        
        doc += "### Agent Navigation\n"
        doc += "- Start from `INDEX.md`\n"
        doc += "- Check `agents/registry/agent_types.yaml` for capabilities\n"
        doc += "- Store state in `agents/state/{agent-id}/`\n"
        doc += "- Follow workflows in `agents/workflows/`\n\n"
        
        return doc
    
    def save_documentation(self, content: str, output_file: str = None):
        """Save documentation to file."""
        if not output_file:
            output_file = str(self.bbhk_root / "docs" / "ARCHITECTURE.md")
        
        # Create docs directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write(content)
        
        print(f"Architecture documentation generated: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Generate BBHK architecture documentation")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--bbhk-root", default="/home/kali/bbhk", help="BBHK root directory")
    
    args = parser.parse_args()
    
    generator = ArchitectureDocGenerator(args.bbhk_root)
    documentation = generator.generate_full_documentation()
    generator.save_documentation(documentation, args.output)


if __name__ == "__main__":
    main()