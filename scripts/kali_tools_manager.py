#!/usr/bin/env python3
"""
Kali Tools Collection Manager for BBHK v3.0
Optimal schema design and integration with existing vulnerability storage system
Implements mandatory data placement rules and semantic search capabilities
"""

import sqlite3
import json
import subprocess
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
from enum import Enum
from dataclasses import dataclass

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False

# Import existing hybrid manager
try:
    from scripts.hybrid_data_manager import HybridDB
    HYBRID_AVAILABLE = True
except ImportError:
    HYBRID_AVAILABLE = False


class ToolCategory(Enum):
    """Tool categories aligned with BBHK attack vectors"""
    CLOUD_SECURITY = "cloud_security"
    AI_LLM = "ai_llm"
    BUSINESS_LOGIC = "business_logic"
    WEB_SECURITY = "web_security"
    API_TESTING = "api_testing"
    MOBILE_SECURITY = "mobile_security"
    SMART_CONTRACTS = "smart_contracts"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    FORENSICS = "forensics"


class ToolComplexity(Enum):
    """Tool complexity levels for skill matching"""
    BEGINNER = 1
    INTERMEDIATE = 2
    ADVANCED = 3
    EXPERT = 4


@dataclass
class KaliTool:
    """Tool data structure optimized for vulnerability research"""
    name: str
    category: ToolCategory
    description: str
    package_name: str
    installed: bool = False
    complexity: ToolComplexity = ToolComplexity.INTERMEDIATE
    vulnerability_types: List[str] = None
    attack_vectors: List[str] = None
    typical_bounty_range: Tuple[int, int] = (0, 0)
    installation_command: str = ""
    usage_examples: List[str] = None
    integration_commands: List[str] = None
    config_files: List[str] = None
    dependencies: List[str] = None
    version: str = ""
    last_updated: datetime = None
    success_rate: float = 0.0  # Tool effectiveness in finding vulnerabilities
    time_to_results: int = 0  # Minutes to typical results
    
    def __post_init__(self):
        if self.vulnerability_types is None:
            self.vulnerability_types = []
        if self.attack_vectors is None:
            self.attack_vectors = []
        if self.usage_examples is None:
            self.usage_examples = []
        if self.integration_commands is None:
            self.integration_commands = []
        if self.config_files is None:
            self.config_files = []
        if self.dependencies is None:
            self.dependencies = []
        if self.last_updated is None:
            self.last_updated = datetime.now()


class KaliToolsManager:
    """
    Comprehensive tool management system integrated with BBHK architecture
    Implements optimal vector embedding strategy and seamless data flow
    """
    
    def __init__(self, 
                 sqlite_path: str = "/home/kali/bbhk/.swarm/memory.db",
                 qdrant_host: str = "localhost",
                 qdrant_port: int = 6333):
        """Initialize with existing BBHK infrastructure"""
        
        self.sqlite_path = sqlite_path
        self.sqlite_conn = sqlite3.connect(sqlite_path)
        self.sqlite_conn.row_factory = sqlite3.Row
        
        # Initialize Qdrant connection
        self.qdrant_client = None
        if QDRANT_AVAILABLE:
            try:
                self.qdrant_client = QdrantClient(host=qdrant_host, port=qdrant_port)
                self._ensure_collections()
            except Exception as e:
                print(f"⚠️ Qdrant connection failed: {e}")
        
        # Initialize embedding model
        self.embedder = None
        if EMBEDDINGS_AVAILABLE:
            try:
                self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception as e:
                print(f"⚠️ Embedding model failed: {e}")
        
        # Initialize hybrid DB connection
        self.hybrid_db = None
        if HYBRID_AVAILABLE:
            try:
                self.hybrid_db = HybridDB()
            except Exception as e:
                print(f"⚠️ Hybrid DB connection failed: {e}")
        
        self._ensure_sqlite_tables()
    
    def _ensure_collections(self):
        """Create optimized Qdrant collections for tool management"""
        if not self.qdrant_client:
            return
        
        collections = {
            "kali_tools": {
                "size": 384,  # MiniLM embedding dimension
                "description": "Tool descriptions, capabilities, and usage patterns"
            },
            "tool_vulnerabilities": {
                "size": 384,
                "description": "Tool-vulnerability type mappings for smart recommendations"
            },
            "tool_commands": {
                "size": 384,
                "description": "Command examples and usage patterns for contextual help"
            }
        }
        
        existing = [c.name for c in self.qdrant_client.get_collections().collections]
        
        for name, config in collections.items():
            if name not in existing:
                self.qdrant_client.create_collection(
                    collection_name=name,
                    vectors_config=VectorParams(size=config["size"], distance=Distance.COSINE)
                )
                print(f"✅ Created collection: {name} - {config['description']}")
    
    def _ensure_sqlite_tables(self):
        """Create SQLite tables with optimal schema for tool management"""
        cursor = self.sqlite_conn.cursor()
        
        # Main kali_tools table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kali_tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL,
            package_name TEXT,
            description TEXT NOT NULL,
            installed BOOLEAN DEFAULT FALSE,
            complexity INTEGER DEFAULT 2,
            vulnerability_types TEXT,  -- JSON array
            attack_vectors TEXT,       -- JSON array
            bounty_min INTEGER DEFAULT 0,
            bounty_max INTEGER DEFAULT 0,
            installation_command TEXT,
            usage_examples TEXT,       -- JSON array
            integration_commands TEXT, -- JSON array
            config_files TEXT,         -- JSON array
            dependencies TEXT,         -- JSON array
            version TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success_rate REAL DEFAULT 0.0,
            time_to_results INTEGER DEFAULT 0,
            metadata TEXT              -- JSON for extensibility
        )
        """)
        
        # Tool-vulnerability relationships
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tool_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_id INTEGER,
            vulnerability_type TEXT,
            effectiveness_score REAL DEFAULT 0.5,
            typical_time_minutes INTEGER,
            success_cases INTEGER DEFAULT 0,
            total_attempts INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tool_id) REFERENCES kali_tools(id),
            UNIQUE(tool_id, vulnerability_type)
        )
        """)
        
        # Tool usage analytics
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tool_usage_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_id INTEGER,
            used_for_program TEXT,
            vulnerability_found TEXT,
            time_spent_minutes INTEGER,
            success BOOLEAN DEFAULT FALSE,
            bounty_earned INTEGER DEFAULT 0,
            usage_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (tool_id) REFERENCES kali_tools(id)
        )
        """)
        
        # Create indices for optimal performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tools_category ON kali_tools(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tools_installed ON kali_tools(installed)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tools_complexity ON kali_tools(complexity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_vulns_type ON tool_vulnerabilities(vulnerability_type)")
        
        self.sqlite_conn.commit()
        print("✅ SQLite tables created/verified")
    
    def discover_installed_tools(self) -> List[KaliTool]:
        """
        Discover installed Kali tools automatically
        Integrates with existing package management and dpkg
        """
        tools = []
        
        # Comprehensive tool definitions optimized for bug bounty hunting
        tool_definitions = {
            # Cloud Security Tools
            "cloudsplaining": KaliTool(
                name="cloudsplaining",
                category=ToolCategory.CLOUD_SECURITY,
                package_name="cloudsplaining",
                description="AWS IAM security assessment tool for identifying overprivileged permissions and misconfigurations",
                vulnerability_types=["privilege_escalation", "iam_misconfiguration", "cloud_security"],
                attack_vectors=["aws_exploitation", "permission_abuse", "cloud_lateral_movement"],
                typical_bounty_range=(5000, 25000),
                installation_command="pipx install cloudsplaining",
                usage_examples=[
                    "cloudsplaining download --profile myprofile",
                    "cloudsplaining scan --input-file iam-data.json --output output/",
                    "cloudsplaining scan-policy-file --input-file policy.json"
                ],
                complexity=ToolComplexity.INTERMEDIATE,
                time_to_results=30,
                success_rate=0.7
            ),
            "scoutsuite": KaliTool(
                name="scoutsuite",
                category=ToolCategory.CLOUD_SECURITY,
                package_name="scoutsuite",
                description="Multi-cloud security auditing tool for AWS, GCP, Azure, and Oracle Cloud",
                vulnerability_types=["cloud_misconfiguration", "storage_exposure", "network_security"],
                attack_vectors=["cloud_enumeration", "service_discovery", "configuration_abuse"],
                typical_bounty_range=(3000, 15000),
                installation_command="pipx install scoutsuite",
                usage_examples=[
                    "scout aws --profile myprofile",
                    "scout gcp --project-id myproject",
                    "scout azure --cli"
                ],
                complexity=ToolComplexity.BEGINNER,
                time_to_results=45,
                success_rate=0.6
            ),
            
            # AI/LLM Security Tools
            "garak": KaliTool(
                name="garak",
                category=ToolCategory.AI_LLM,
                package_name="garak",
                description="LLM vulnerability scanner for prompt injection, jailbreaking, and model manipulation",
                vulnerability_types=["prompt_injection", "model_manipulation", "data_extraction"],
                attack_vectors=["llm_jailbreak", "system_prompt_extraction", "training_data_leak"],
                typical_bounty_range=(10000, 50000),
                installation_command="pipx install garak",
                usage_examples=[
                    "garak -m openai -g promptinject -p chat",
                    "garak -m huggingface -g jailbreak -t malicious_use",
                    "garak --report-prefix my_scan"
                ],
                complexity=ToolComplexity.ADVANCED,
                time_to_results=60,
                success_rate=0.4
            ),
            
            # Web Security Tools  
            "dirb": KaliTool(
                name="dirb",
                category=ToolCategory.WEB_SECURITY,
                package_name="dirb",
                description="Web content scanner for discovering hidden directories and files",
                vulnerability_types=["directory_traversal", "information_disclosure", "backup_files"],
                attack_vectors=["path_enumeration", "file_discovery", "admin_panel_discovery"],
                typical_bounty_range=(500, 3000),
                installation_command="sudo apt install dirb",
                usage_examples=[
                    "dirb https://example.com/",
                    "dirb https://example.com/ /usr/share/dirb/wordlists/big.txt",
                    "dirb https://example.com/ -X .php,.jsp,.asp"
                ],
                complexity=ToolComplexity.BEGINNER,
                time_to_results=20,
                success_rate=0.8
            ),
            "gobuster": KaliTool(
                name="gobuster",
                category=ToolCategory.WEB_SECURITY,
                package_name="gobuster",
                description="Fast directory/file & DNS busting tool written in Go",
                vulnerability_types=["directory_traversal", "subdomain_takeover", "information_disclosure"],
                attack_vectors=["content_discovery", "subdomain_enumeration", "virtual_host_discovery"],
                typical_bounty_range=(500, 5000),
                installation_command="sudo apt install gobuster",
                usage_examples=[
                    "gobuster dir -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/big.txt",
                    "gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                    "gobuster vhost -u https://example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                ],
                complexity=ToolComplexity.BEGINNER,
                time_to_results=15,
                success_rate=0.9
            ),
            
            # API Testing Tools
            "ffuf": KaliTool(
                name="ffuf",
                category=ToolCategory.API_TESTING,
                package_name="ffuf",
                description="Fast web fuzzer written in Go for discovering APIs, parameters, and endpoints",
                vulnerability_types=["api_abuse", "parameter_pollution", "mass_assignment"],
                attack_vectors=["endpoint_discovery", "parameter_fuzzing", "method_enumeration"],
                typical_bounty_range=(2000, 10000),
                installation_command="sudo apt install ffuf",
                usage_examples=[
                    "ffuf -w wordlist.txt -u https://example.com/FUZZ",
                    "ffuf -w params.txt -u https://example.com/api?FUZZ=test -mc 200",
                    "ffuf -X POST -d 'FUZZ=test' -H 'Content-Type: application/json' -w payloads.txt -u https://api.example.com/endpoint"
                ],
                complexity=ToolComplexity.INTERMEDIATE,
                time_to_results=25,
                success_rate=0.7
            ),
            
            # Smart Contract Tools
            "slither": KaliTool(
                name="slither",
                category=ToolCategory.SMART_CONTRACTS,
                package_name="slither-analyzer",
                description="Static analysis framework for Solidity smart contracts",
                vulnerability_types=["smart_contract_bug", "reentrancy", "integer_overflow"],
                attack_vectors=["contract_analysis", "vulnerability_detection", "code_review"],
                typical_bounty_range=(15000, 100000),
                installation_command="pipx install slither-analyzer",
                usage_examples=[
                    "slither contract.sol",
                    "slither . --print human-summary",
                    "slither . --detect reentrancy-eth,reentrancy-no-eth"
                ],
                complexity=ToolComplexity.EXPERT,
                time_to_results=40,
                success_rate=0.6
            ),
            "mythril": KaliTool(
                name="mythril",
                category=ToolCategory.SMART_CONTRACTS,
                package_name="mythril",
                description="Security analysis tool for Ethereum smart contracts using symbolic execution",
                vulnerability_types=["smart_contract_bug", "logic_bomb", "access_control"],
                attack_vectors=["symbolic_execution", "formal_verification", "exploit_generation"],
                typical_bounty_range=(20000, 150000),
                installation_command="pipx install mythril",
                usage_examples=[
                    "myth analyze contract.sol",
                    "myth analyze -a 0x1234567890123456789012345678901234567890",
                    "myth analyze contract.sol --execution-timeout 300"
                ],
                complexity=ToolComplexity.EXPERT,
                time_to_results=60,
                success_rate=0.5
            ),
            
            # Business Logic Tools
            "jwt-tool": KaliTool(
                name="jwt-tool",
                category=ToolCategory.BUSINESS_LOGIC,
                package_name="jwt-tool",
                description="Toolkit for validating, forging, scanning and tampering JWTs",
                vulnerability_types=["jwt_bypass", "authentication_bypass", "privilege_escalation"],
                attack_vectors=["token_manipulation", "algorithm_confusion", "key_confusion"],
                typical_bounty_range=(5000, 20000),
                installation_command="git clone https://github.com/ticarpi/jwt_tool",
                usage_examples=[
                    "python3 jwt_tool.py -t eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                    "python3 jwt_tool.py -T",
                    "python3 jwt_tool.py -C -d dictionary.txt"
                ],
                complexity=ToolComplexity.INTERMEDIATE,
                time_to_results=35,
                success_rate=0.6
            ),
            
            # Mobile Security
            "mobsf": KaliTool(
                name="mobsf",
                category=ToolCategory.MOBILE_SECURITY,
                package_name="mobsf",
                description="Mobile Security Framework for mobile app security testing",
                vulnerability_types=["mobile_app_bug", "data_storage", "crypto_implementation"],
                attack_vectors=["static_analysis", "dynamic_analysis", "api_analysis"],
                typical_bounty_range=(3000, 15000),
                installation_command="git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF",
                usage_examples=[
                    "python3 manage.py runserver",
                    "Upload APK/IPA through web interface",
                    "mobsf-cli.py -f app.apk -s"
                ],
                complexity=ToolComplexity.ADVANCED,
                time_to_results=90,
                success_rate=0.5
            )
        }
        
        # Check installation status and gather metadata
        for tool_name, tool_def in tool_definitions.items():
            try:
                # Check if tool is installed
                result = subprocess.run(['which', tool_name], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    tool_def.installed = True
                    # Try to get version
                    try:
                        version_result = subprocess.run([tool_name, '--version'], 
                                                      capture_output=True, text=True, timeout=5)
                        if version_result.stdout:
                            tool_def.version = version_result.stdout.strip()[:100]
                    except:
                        pass
                
                # Check package installation via dpkg
                if not tool_def.installed and tool_def.package_name:
                    dpkg_result = subprocess.run(['dpkg', '-l', tool_def.package_name],
                                                capture_output=True, text=True)
                    if dpkg_result.returncode == 0 and 'ii' in dpkg_result.stdout:
                        tool_def.installed = True
                
                tools.append(tool_def)
            except Exception as e:
                print(f"⚠️ Error checking tool {tool_name}: {e}")
                continue
        
        return tools
    
    def store_tools(self, tools: List[KaliTool]) -> bool:
        """
        Store tools in both SQLite and Qdrant with optimal data placement
        """
        try:
            cursor = self.sqlite_conn.cursor()
            stored_count = 0
            
            for tool in tools:
                # Store in SQLite (structured data)
                cursor.execute("""
                INSERT OR REPLACE INTO kali_tools (
                    name, category, package_name, description, installed, complexity,
                    vulnerability_types, attack_vectors, bounty_min, bounty_max,
                    installation_command, usage_examples, integration_commands,
                    config_files, dependencies, version, success_rate, time_to_results,
                    metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tool.name,
                    tool.category.value,
                    tool.package_name,
                    tool.description,
                    tool.installed,
                    tool.complexity.value,
                    json.dumps(tool.vulnerability_types),
                    json.dumps(tool.attack_vectors),
                    tool.typical_bounty_range[0],
                    tool.typical_bounty_range[1],
                    tool.installation_command,
                    json.dumps(tool.usage_examples),
                    json.dumps(tool.integration_commands),
                    json.dumps(tool.config_files),
                    json.dumps(tool.dependencies),
                    tool.version,
                    tool.success_rate,
                    tool.time_to_results,
                    json.dumps({
                        "last_updated": tool.last_updated.isoformat(),
                        "discovery_method": "auto_discovery"
                    })
                ))
                
                tool_id = cursor.lastrowid
                
                # Store tool-vulnerability relationships
                for vuln_type in tool.vulnerability_types:
                    cursor.execute("""
                    INSERT OR REPLACE INTO tool_vulnerabilities (
                        tool_id, vulnerability_type, effectiveness_score
                    ) VALUES (?, ?, ?)
                    """, (tool_id, vuln_type, tool.success_rate))
                
                # Store in Qdrant (embeddings for semantic search)
                if self.qdrant_client and self.embedder:
                    self._store_tool_embeddings(tool_id, tool)
                
                stored_count += 1
            
            self.sqlite_conn.commit()
            print(f"✅ Stored {stored_count} tools in SQLite")
            
            # Integrate with existing vulnerability storage system
            if self.hybrid_db:
                self._sync_with_vulnerability_system(tools)
            
            return True
            
        except Exception as e:
            print(f"❌ Error storing tools: {e}")
            return False
    
    def _store_tool_embeddings(self, tool_id: int, tool: KaliTool):
        """Store tool embeddings in Qdrant collections"""
        try:
            # Main tool description embedding
            desc_embedding = self.embedder.encode(
                f"{tool.name} {tool.description} {' '.join(tool.vulnerability_types)}"
            ).tolist()
            
            self.qdrant_client.upsert(
                collection_name="kali_tools",
                points=[
                    PointStruct(
                        id=tool_id,
                        vector=desc_embedding,
                        payload={
                            "tool_id": tool_id,
                            "name": tool.name,
                            "category": tool.category.value,
                            "description": tool.description,
                            "installed": tool.installed,
                            "complexity": tool.complexity.value,
                            "bounty_range": tool.typical_bounty_range,
                            "success_rate": tool.success_rate,
                            "time_to_results": tool.time_to_results
                        }
                    )
                ]
            )
            
            # Store vulnerability type mappings
            for vuln_type in tool.vulnerability_types:
                vuln_embedding = self.embedder.encode(
                    f"{vuln_type} {tool.name} {tool.description}"
                ).tolist()
                
                self.qdrant_client.upsert(
                    collection_name="tool_vulnerabilities",
                    points=[
                        PointStruct(
                            id=hash(f"{tool_id}_{vuln_type}") % 2**32,
                            vector=vuln_embedding,
                            payload={
                                "tool_id": tool_id,
                                "tool_name": tool.name,
                                "vulnerability_type": vuln_type,
                                "effectiveness": tool.success_rate
                            }
                        )
                    ]
                )
            
            # Store command examples
            for i, example in enumerate(tool.usage_examples):
                cmd_embedding = self.embedder.encode(
                    f"{tool.name} {example} {tool.description}"
                ).tolist()
                
                self.qdrant_client.upsert(
                    collection_name="tool_commands",
                    points=[
                        PointStruct(
                            id=hash(f"{tool_id}_{i}_{example}") % 2**32,
                            vector=cmd_embedding,
                            payload={
                                "tool_id": tool_id,
                                "tool_name": tool.name,
                                "command": example,
                                "category": tool.category.value
                            }
                        )
                    ]
                )
        
        except Exception as e:
            print(f"⚠️ Error storing embeddings for {tool.name}: {e}")
    
    def _sync_with_vulnerability_system(self, tools: List[KaliTool]):
        """Integrate tool data with existing vulnerability storage system"""
        try:
            # Store tool recommendations in claude-flow memory
            tool_recommendations = {}
            for tool in tools:
                for vuln_type in tool.vulnerability_types:
                    if vuln_type not in tool_recommendations:
                        tool_recommendations[vuln_type] = []
                    
                    tool_recommendations[vuln_type].append({
                        "name": tool.name,
                        "category": tool.category.value,
                        "effectiveness": tool.success_rate,
                        "time_to_results": tool.time_to_results,
                        "bounty_potential": tool.typical_bounty_range,
                        "complexity": tool.complexity.value,
                        "installation": tool.installation_command,
                        "examples": tool.usage_examples[:3]  # Top 3 examples
                    })
            
            # Store in claude-flow memory for retrieval by other agents
            self.hybrid_db.store_memory(
                key="kali_tools_vulnerability_mapping",
                value=json.dumps(tool_recommendations),
                namespace="bbhk_tools"
            )
            
            # Create attack vector to tool mapping
            attack_vector_tools = {}
            for tool in tools:
                for vector in tool.attack_vectors:
                    if vector not in attack_vector_tools:
                        attack_vector_tools[vector] = []
                    attack_vector_tools[vector].append({
                        "name": tool.name,
                        "description": tool.description,
                        "success_rate": tool.success_rate
                    })
            
            self.hybrid_db.store_memory(
                key="kali_tools_attack_vector_mapping",
                value=json.dumps(attack_vector_tools),
                namespace="bbhk_tools"
            )
            
            print("✅ Synced tool data with vulnerability storage system")
            
        except Exception as e:
            print(f"⚠️ Error syncing with vulnerability system: {e}")
    
    def recommend_tools_for_vulnerability(self, vuln_type: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Recommend best tools for a specific vulnerability type
        Uses both exact matching, fuzzy matching, and semantic similarity
        """
        recommendations = []
        
        try:
            # First, get exact matches from SQLite
            cursor = self.sqlite_conn.cursor()
            cursor.execute("""
            SELECT t.*, tv.effectiveness_score
            FROM kali_tools t
            JOIN tool_vulnerabilities tv ON t.id = tv.tool_id
            WHERE tv.vulnerability_type = ?
            ORDER BY tv.effectiveness_score DESC, t.success_rate DESC
            LIMIT ?
            """, (vuln_type, limit))
            
            exact_matches = cursor.fetchall()
            
            # If no exact matches, try fuzzy matching on vulnerability types
            if not exact_matches:
                vuln_type_lower = vuln_type.lower()
                cursor.execute("""
                SELECT t.*, tv.effectiveness_score
                FROM kali_tools t
                JOIN tool_vulnerabilities tv ON t.id = tv.tool_id
                WHERE LOWER(tv.vulnerability_type) LIKE ? 
                   OR LOWER(tv.vulnerability_type) LIKE ?
                   OR LOWER(tv.vulnerability_type) LIKE ?
                ORDER BY tv.effectiveness_score DESC, t.success_rate DESC
                LIMIT ?
                """, (f"%{vuln_type_lower}%", f"%{vuln_type_lower.replace('_', ' ')}%", 
                      f"%{vuln_type_lower.replace(' ', '_')}%", limit))
                
                exact_matches = cursor.fetchall()
            
            # If still no matches, try broader category matching
            if not exact_matches:
                category_keywords = {
                    'input': ['input_validation', 'validation', 'injection', 'xss', 'sqli'],
                    'validation': ['input_validation', 'bypass', 'filter'],
                    'bypass': ['authentication', 'authorization', 'validation', 'filter'],
                    'injection': ['xss', 'sqli', 'command_injection', 'ldap_injection'],
                    'logic': ['business_logic', 'race_condition', 'toctou'],
                    'race': ['race_condition', 'concurrency', 'toctou'],
                    'overflow': ['buffer_overflow', 'integer_overflow', 'heap_overflow']
                }
                
                vuln_words = vuln_type_lower.replace('_', ' ').split()
                matching_categories = []
                
                for word in vuln_words:
                    for category, keywords in category_keywords.items():
                        if word in category or any(keyword in word for keyword in keywords):
                            matching_categories.extend(keywords)
                
                if matching_categories:
                    # Create placeholders for the IN clause
                    placeholders = ','.join('?' for _ in matching_categories)
                    cursor.execute(f"""
                    SELECT t.*, tv.effectiveness_score
                    FROM kali_tools t
                    JOIN tool_vulnerabilities tv ON t.id = tv.tool_id
                    WHERE tv.vulnerability_type IN ({placeholders})
                    ORDER BY tv.effectiveness_score DESC, t.success_rate DESC
                    LIMIT ?
                    """, matching_categories + [limit])
                    
                    exact_matches = cursor.fetchall()
            for match in exact_matches:
                recommendations.append({
                    "tool_name": match["name"],
                    "category": match["category"],
                    "description": match["description"],
                    "effectiveness": match["effectiveness_score"],
                    "installed": match["installed"],
                    "complexity": match["complexity"],
                    "time_to_results": match["time_to_results"],
                    "installation": match["installation_command"],
                    "examples": json.loads(match["usage_examples"] or "[]")[:2],
                    "match_type": "exact"
                })
            
            # If still no matches, get general-purpose tools as fallback
            if not recommendations:
                cursor.execute("""
                SELECT * FROM kali_tools 
                WHERE category IN ('web_security', 'api_testing', 'reconnaissance')
                   AND installed = TRUE
                ORDER BY success_rate DESC
                LIMIT ?
                """, (min(limit, 3),))
                
                fallback_tools = cursor.fetchall()
                for tool in fallback_tools:
                    recommendations.append({
                        "tool_name": tool["name"],
                        "category": tool["category"],
                        "description": tool["description"],
                        "effectiveness": tool["success_rate"],
                        "installed": tool["installed"],
                        "complexity": tool["complexity"],
                        "time_to_results": tool["time_to_results"],
                        "installation": tool["installation_command"],
                        "examples": json.loads(tool["usage_examples"] or "[]")[:2],
                        "match_type": "fallback"
                    })
            
            # If we need more recommendations, use semantic search
            if len(recommendations) < limit and self.qdrant_client and self.embedder:
                remaining = limit - len(recommendations)
                semantic_matches = self._semantic_tool_search(vuln_type, remaining)
                
                # Filter out duplicates
                existing_tools = {r["tool_name"] for r in recommendations}
                for match in semantic_matches:
                    if match["tool_name"] not in existing_tools:
                        match["match_type"] = "semantic"
                        recommendations.append(match)
            
            return recommendations[:limit]
            
        except Exception as e:
            print(f"❌ Error getting tool recommendations: {e}")
            return []
    
    def _semantic_tool_search(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Perform semantic search for tools using Qdrant"""
        try:
            query_embedding = self.embedder.encode(query).tolist()
            
            results = self.qdrant_client.search(
                collection_name="tool_vulnerabilities",
                query_vector=query_embedding,
                limit=limit * 2  # Get more to filter
            )
            
            recommendations = []
            seen_tools = set()
            
            for hit in results:
                payload = hit.payload
                tool_name = payload.get("tool_name")
                
                if tool_name in seen_tools:
                    continue
                seen_tools.add(tool_name)
                
                # Get full tool details from SQLite
                cursor = self.sqlite_conn.cursor()
                cursor.execute("SELECT * FROM kali_tools WHERE name = ?", (tool_name,))
                tool_data = cursor.fetchone()
                
                if tool_data:
                    recommendations.append({
                        "tool_name": tool_name,
                        "category": tool_data["category"],
                        "description": tool_data["description"],
                        "effectiveness": payload.get("effectiveness", 0.5),
                        "installed": tool_data["installed"],
                        "complexity": tool_data["complexity"],
                        "time_to_results": tool_data["time_to_results"],
                        "installation": tool_data["installation_command"],
                        "examples": json.loads(tool_data["usage_examples"] or "[]")[:2],
                        "semantic_score": hit.score
                    })
                
                if len(recommendations) >= limit:
                    break
            
            return recommendations
            
        except Exception as e:
            print(f"❌ Error in semantic tool search: {e}")
            return []
    
    def get_tools_by_category(self, category: ToolCategory) -> List[Dict[str, Any]]:
        """Get all tools in a specific category"""
        try:
            cursor = self.sqlite_conn.cursor()
            cursor.execute("""
            SELECT * FROM kali_tools 
            WHERE category = ? 
            ORDER BY success_rate DESC, name ASC
            """, (category.value,))
            
            tools = []
            for row in cursor.fetchall():
                tool_dict = dict(row)
                tool_dict["vulnerability_types"] = json.loads(tool_dict["vulnerability_types"] or "[]")
                tool_dict["attack_vectors"] = json.loads(tool_dict["attack_vectors"] or "[]")
                tool_dict["usage_examples"] = json.loads(tool_dict["usage_examples"] or "[]")
                tools.append(tool_dict)
            
            return tools
            
        except Exception as e:
            print(f"❌ Error getting tools by category: {e}")
            return []
    
    def install_tool(self, tool_name: str) -> bool:
        """Install a tool and update its status"""
        try:
            cursor = self.sqlite_conn.cursor()
            cursor.execute("SELECT installation_command FROM kali_tools WHERE name = ?", (tool_name,))
            result = cursor.fetchone()
            
            if not result or not result["installation_command"]:
                print(f"❌ No installation command found for {tool_name}")
                return False
            
            install_cmd = result["installation_command"]
            print(f"Installing {tool_name}: {install_cmd}")
            
            # Execute installation command
            process = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
            
            if process.returncode == 0:
                # Update installation status
                cursor.execute("""
                UPDATE kali_tools 
                SET installed = TRUE, last_updated = CURRENT_TIMESTAMP 
                WHERE name = ?
                """, (tool_name,))
                self.sqlite_conn.commit()
                print(f"✅ Successfully installed {tool_name}")
                return True
            else:
                print(f"❌ Failed to install {tool_name}: {process.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error installing {tool_name}: {e}")
            return False
    
    def generate_tool_report(self) -> Dict[str, Any]:
        """Generate comprehensive tool inventory report"""
        try:
            cursor = self.sqlite_conn.cursor()
            
            # Overall statistics
            cursor.execute("SELECT COUNT(*) as total FROM kali_tools")
            total_tools = cursor.fetchone()["total"]
            
            cursor.execute("SELECT COUNT(*) as installed FROM kali_tools WHERE installed = TRUE")
            installed_count = cursor.fetchone()["installed"]
            
            # Category breakdown
            cursor.execute("""
            SELECT category, COUNT(*) as count, AVG(success_rate) as avg_success
            FROM kali_tools 
            GROUP BY category
            ORDER BY count DESC
            """)
            categories = cursor.fetchall()
            
            # Top tools by success rate
            cursor.execute("""
            SELECT name, category, success_rate, bounty_max, time_to_results
            FROM kali_tools 
            WHERE success_rate > 0
            ORDER BY success_rate DESC
            LIMIT 10
            """)
            top_tools = cursor.fetchall()
            
            # Missing high-value tools (not installed but high bounty potential)
            cursor.execute("""
            SELECT name, category, bounty_max, installation_command
            FROM kali_tools 
            WHERE installed = FALSE AND bounty_max > 10000
            ORDER BY bounty_max DESC
            LIMIT 5
            """)
            missing_high_value = cursor.fetchall()
            
            report = {
                "summary": {
                    "total_tools": total_tools,
                    "installed_tools": installed_count,
                    "installation_rate": round(installed_count / total_tools * 100, 1) if total_tools > 0 else 0
                },
                "categories": [dict(cat) for cat in categories],
                "top_tools": [dict(tool) for tool in top_tools],
                "missing_high_value": [dict(tool) for tool in missing_high_value],
                "generated_at": datetime.now().isoformat()
            }
            
            return report
            
        except Exception as e:
            print(f"❌ Error generating tool report: {e}")
            return {}
    
    def close(self):
        """Close all connections"""
        if self.sqlite_conn:
            self.sqlite_conn.close()


def main():
    """Main function to initialize and populate the kali_tools collection"""
    print("🚀 Initializing Kali Tools Manager for BBHK v3.0")
    print("=" * 60)
    
    # Initialize manager
    manager = KaliToolsManager()
    
    # Discover installed tools
    print("🔍 Discovering installed tools...")
    tools = manager.discover_installed_tools()
    print(f"Found {len(tools)} tool definitions")
    
    # Store tools in databases
    print("💾 Storing tools in hybrid database system...")
    success = manager.store_tools(tools)
    
    if success:
        print("✅ Tool storage successful!")
        
        # Generate report
        print("📊 Generating tool inventory report...")
        report = manager.generate_tool_report()
        
        if report:
            print(f"\n📈 TOOL INVENTORY SUMMARY:")
            print(f"Total Tools: {report['summary']['total_tools']}")
            print(f"Installed: {report['summary']['installed_tools']} ({report['summary']['installation_rate']}%)")
            print(f"\nTop Categories:")
            for cat in report['categories'][:5]:
                print(f"  • {cat['category']}: {cat['count']} tools (avg success: {cat['avg_success']:.1%})")
            
            print(f"\nTop Tools by Success Rate:")
            for tool in report['top_tools'][:5]:
                print(f"  • {tool['name']}: {tool['success_rate']:.1%} success, ${tool['bounty_max']:,} max bounty")
            
            if report['missing_high_value']:
                print(f"\n⚠️ Missing High-Value Tools:")
                for tool in report['missing_high_value']:
                    print(f"  • {tool['name']}: ${tool['bounty_max']:,} potential")
                    print(f"    Install: {tool['installation_command']}")
    
    # Test semantic search
    print("\n🧠 Testing semantic tool recommendations...")
    test_vulns = ["prompt_injection", "cloud_misconfiguration", "jwt_bypass"]
    
    for vuln in test_vulns:
        recommendations = manager.recommend_tools_for_vulnerability(vuln, 3)
        if recommendations:
            print(f"\n🎯 Tools for '{vuln}':")
            for rec in recommendations:
                print(f"  • {rec['tool_name']} ({rec['match_type']} match)")
                print(f"    Effectiveness: {rec['effectiveness']:.1%}, Time: {rec['time_to_results']}min")
    
    manager.close()
    print("\n✅ Kali Tools Manager initialization complete!")


if __name__ == "__main__":
    main()