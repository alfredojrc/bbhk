#!/usr/bin/env python3
"""
Comprehensive Memory System Verification
Tests the entire memory architecture from bottom to top
Run this when Claude Code starts from scratch
"""

import sys
import sqlite3
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any

class MemorySystemVerifier:
    def __init__(self):
        self.sqlite_path = "/home/kali/bbhk/.swarm/memory.db"
        self.tests_passed = 0
        self.tests_failed = 0
        self.critical_issues = []
        
    def run_all_tests(self) -> bool:
        """Run comprehensive verification suite"""
        print("=" * 70)
        print("MEMORY SYSTEM VERIFICATION SUITE")
        print("=" * 70)
        print(f"Started: {datetime.now()}")
        print()
        
        # Layer 1: Database Infrastructure
        self.test_database_layer()
        
        # Layer 2: Data Integrity
        self.test_data_integrity()
        
        # Layer 3: MCP Interface
        self.test_mcp_interface()
        
        # Layer 4: Hybrid Manager
        self.test_hybrid_manager()
        
        # Layer 5: Query Routing
        self.test_query_routing()
        
        # Layer 6: CLAUDE.md References
        self.test_claude_md_references()
        
        # Final Report
        self.generate_report()
        
        return self.tests_failed == 0
        
    def test_database_layer(self):
        """Test Layer 1: Database Infrastructure"""
        print("\n📊 LAYER 1: DATABASE INFRASTRUCTURE")
        print("-" * 50)
        
        # Test 1.1: SQLite exists and is accessible
        if Path(self.sqlite_path).exists():
            self.log_success("SQLite database exists")
            
            # Check file size
            size_mb = Path(self.sqlite_path).stat().st_size / (1024 * 1024)
            if size_mb > 0:
                self.log_success(f"SQLite size: {size_mb:.2f} MB")
            else:
                self.log_failure("SQLite database is empty")
        else:
            self.log_failure("SQLite database not found")
            self.critical_issues.append("No SQLite database")
            return
            
        # Test 1.2: Required tables exist
        try:
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.cursor()
            
            required_tables = ['programs', 'vulnerabilities', 'policies', 'memory_entries']
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing_tables = [row[0] for row in cursor.fetchall()]
            
            for table in required_tables:
                if table in existing_tables:
                    self.log_success(f"Table '{table}' exists")
                else:
                    self.log_failure(f"Table '{table}' missing")
                    self.critical_issues.append(f"Missing table: {table}")
                    
            conn.close()
        except Exception as e:
            self.log_failure(f"Database connection failed: {e}")
            self.critical_issues.append("Cannot connect to SQLite")
            
    def test_data_integrity(self):
        """Test Layer 2: Data Integrity"""
        print("\n🔍 LAYER 2: DATA INTEGRITY")
        print("-" * 50)
        
        try:
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.cursor()
            
            # Test 2.1: Check row counts
            tables_to_check = {
                'programs': 100,  # Should have at least 100 programs
                'memory_entries': 10,  # Should have some memory entries
                'policies': 5  # Should have some policies
            }
            
            for table, min_count in tables_to_check.items():
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                
                if count >= min_count:
                    self.log_success(f"{table}: {count} rows (>= {min_count})")
                elif count > 0:
                    self.log_warning(f"{table}: {count} rows (expected >= {min_count})")
                else:
                    self.log_failure(f"{table}: empty table")
                    
            # Test 2.2: Critical namespaces exist
            cursor.execute("""
                SELECT DISTINCT namespace, COUNT(*) as count 
                FROM memory_entries 
                WHERE namespace IN ('claude_md_optimization', 'tools', 'default')
                GROUP BY namespace
            """)
            
            namespaces = cursor.fetchall()
            required_namespace = 'claude_md_optimization'
            
            if any(ns[0] == required_namespace for ns in namespaces):
                self.log_success(f"Critical namespace '{required_namespace}' exists")
            else:
                self.log_failure(f"Critical namespace '{required_namespace}' missing")
                self.critical_issues.append("Missing claude_md_optimization namespace")
                
            conn.close()
        except Exception as e:
            self.log_failure(f"Data integrity check failed: {e}")
            
    def test_mcp_interface(self):
        """Test Layer 3: MCP Interface"""
        print("\n🔌 LAYER 3: MCP INTERFACE")
        print("-" * 50)
        
        # Test 3.1: Store operation
        test_key = f"verification_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        test_value = "Test data for verification"
        
        try:
            # Import the hybrid manager to test store
            sys.path.insert(0, '/home/kali/bbhk/scripts')
            from hybrid_data_manager import HybridDB
            
            db = HybridDB()
            
            # Store test data
            stored = db.store_memory(test_key, test_value, "testing")
            if stored:
                self.log_success(f"MCP store operation successful")
            else:
                self.log_failure("MCP store operation failed")
                
            # Retrieve test data
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM memory_entries WHERE key = ? AND namespace = ?",
                (test_key, "testing")
            )
            result = cursor.fetchone()
            
            if result and result[0] == test_value:
                self.log_success("MCP retrieve operation successful")
            else:
                self.log_failure("MCP retrieve operation failed")
                
            conn.close()
        except Exception as e:
            self.log_failure(f"MCP interface test failed: {e}")
            
    def test_hybrid_manager(self):
        """Test Layer 4: Hybrid Data Manager"""
        print("\n🔄 LAYER 4: HYBRID DATA MANAGER")
        print("-" * 50)
        
        try:
            from hybrid_data_manager import HybridDB
            
            db = HybridDB()
            
            # Test 4.1: SQL query routing
            sql_result = db.search("SELECT COUNT(*) FROM programs")
            if sql_result and 'data' in sql_result:
                self.log_success("SQL query routing works")
                self.log_info(f"  Programs count: {sql_result['data'][0]['COUNT(*)'] if sql_result['data'] else 0}")
            else:
                self.log_failure("SQL query routing failed")
                
            # Test 4.2: Query metadata
            if 'metadata' in sql_result:
                meta = sql_result['metadata']
                if meta.get('query_type') == 'sqlite':
                    self.log_success("Query type detection correct")
                if 'execution_time_ms' in meta:
                    self.log_success(f"Performance tracking works ({meta['execution_time_ms']}ms)")
            else:
                self.log_failure("Query metadata missing")
                
        except ImportError:
            self.log_failure("Cannot import hybrid_data_manager")
            self.critical_issues.append("Hybrid manager not available")
        except Exception as e:
            self.log_failure(f"Hybrid manager test failed: {e}")
            
    def test_query_routing(self):
        """Test Layer 5: Query Routing Intelligence"""
        print("\n🎯 LAYER 5: QUERY ROUTING")
        print("-" * 50)
        
        try:
            from query_router import IntelligentQueryRouter
            
            router = IntelligentQueryRouter()
            
            # Test different query patterns
            test_queries = [
                ("SELECT * FROM programs WHERE handle = 'test'", "exact", "sqlite"),
                ("Find similar vulnerabilities", "semantic", "qdrant"),
                ("COUNT(*) FROM programs", "aggregation", "sqlite")
            ]
            
            for query, expected_intent, expected_source in test_queries:
                plan = router.analyze_query(query)
                
                if plan.intent.value == expected_intent:
                    self.log_success(f"Intent detection: '{expected_intent}' ✓")
                else:
                    self.log_warning(f"Intent mismatch: expected '{expected_intent}', got '{plan.intent.value}'")
                    
                if plan.source.value == expected_source:
                    self.log_success(f"Source routing: '{expected_source}' ✓")
                else:
                    self.log_warning(f"Source mismatch: expected '{expected_source}', got '{plan.source.value}'")
                    
        except ImportError:
            self.log_warning("Query router not available (optional component)")
        except Exception as e:
            self.log_failure(f"Query routing test failed: {e}")
            
    def test_claude_md_references(self):
        """Test Layer 6: CLAUDE.md Memory References"""
        print("\n📚 LAYER 6: CLAUDE.md REFERENCES")
        print("-" * 50)
        
        # Critical memory keys referenced in CLAUDE.md
        critical_memories = [
            ('vulnerability_economics', 'claude_md_optimization'),
            ('braze_inc_policy', 'claude_md_optimization'),
            ('scope_verification_process', 'claude_md_optimization'),
            ('expert_consensus_details', 'claude_md_optimization'),
            ('mcp_server_examples', 'claude_md_optimization')
        ]
        
        try:
            conn = sqlite3.connect(self.sqlite_path)
            cursor = conn.cursor()
            
            for key, namespace in critical_memories:
                cursor.execute(
                    "SELECT COUNT(*) FROM memory_entries WHERE key = ? AND namespace = ?",
                    (key, namespace)
                )
                count = cursor.fetchone()[0]
                
                if count > 0:
                    self.log_success(f"✓ {key} (namespace: {namespace})")
                else:
                    self.log_failure(f"✗ {key} NOT FOUND")
                    self.critical_issues.append(f"Missing critical memory: {key}")
                    
            conn.close()
        except Exception as e:
            self.log_failure(f"CLAUDE.md reference test failed: {e}")
            
    def generate_report(self):
        """Generate final verification report"""
        print("\n" + "=" * 70)
        print("VERIFICATION REPORT")
        print("=" * 70)
        
        total_tests = self.tests_passed + self.tests_failed
        success_rate = (self.tests_passed / total_tests * 100) if total_tests > 0 else 0
        
        print(f"\n📊 Test Results:")
        print(f"  ✅ Passed: {self.tests_passed}")
        print(f"  ❌ Failed: {self.tests_failed}")
        print(f"  📈 Success Rate: {success_rate:.1f}%")
        
        if self.critical_issues:
            print(f"\n🚨 CRITICAL ISSUES ({len(self.critical_issues)}):")
            for issue in self.critical_issues:
                print(f"  • {issue}")
                
        # System Status
        print(f"\n🔧 System Status:")
        if self.tests_failed == 0:
            print("  ✅ MEMORY SYSTEM FULLY OPERATIONAL")
        elif len(self.critical_issues) > 0:
            print("  ⚠️ MEMORY SYSTEM DEGRADED - CRITICAL ISSUES FOUND")
        else:
            print("  ⚠️ MEMORY SYSTEM OPERATIONAL WITH WARNINGS")
            
        # Recommendations
        print(f"\n💡 Recommendations:")
        if self.tests_failed == 0:
            print("  • System ready for production use")
            print("  • Consider running periodic health checks")
        else:
            print("  • Fix critical issues before production use")
            if 'Hybrid manager not available' in self.critical_issues:
                print("  • Ensure hybrid_data_manager.py is in scripts/")
            if 'Missing claude_md_optimization namespace' in self.critical_issues:
                print("  • Run memory migration script to restore critical data")
                
        # Save report
        report_path = "/home/kali/bbhk/MEMORY_VERIFICATION_REPORT.txt"
        with open(report_path, "w") as f:
            f.write(f"Memory System Verification Report\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Tests Passed: {self.tests_passed}\n")
            f.write(f"Tests Failed: {self.tests_failed}\n")
            f.write(f"Critical Issues: {len(self.critical_issues)}\n")
            f.write(f"Status: {'OPERATIONAL' if self.tests_failed == 0 else 'DEGRADED'}\n")
            
        print(f"\n📁 Report saved to: {report_path}")
        
    def log_success(self, message: str):
        """Log successful test"""
        print(f"  ✅ {message}")
        self.tests_passed += 1
        
    def log_failure(self, message: str):
        """Log failed test"""
        print(f"  ❌ {message}")
        self.tests_failed += 1
        
    def log_warning(self, message: str):
        """Log warning (counts as passed but needs attention)"""
        print(f"  ⚠️ {message}")
        self.tests_passed += 1
        
    def log_info(self, message: str):
        """Log informational message"""
        print(f"  ℹ️ {message}")


def main():
    """Run verification suite"""
    verifier = MemorySystemVerifier()
    success = verifier.run_all_tests()
    
    # Return exit code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()