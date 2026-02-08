#!/usr/bin/env python3
"""
Integration script to connect ./vuln command with tools management
Adds 'tools' subcommand to existing vulnerability management system
"""

import sys
import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

try:
    from scripts.kali_tools_manager import KaliToolsManager
    from scripts.integrate_tools_with_vulns import ToolVulnerabilityIntegrator
    INTEGRATION_AVAILABLE = True
except ImportError as e:
    print(f"❌ Integration not available: {e}")
    INTEGRATION_AVAILABLE = False


class VulnToolsIntegration:
    """
    Extends the ./vuln command with intelligent tool recommendations
    Seamlessly integrates with existing vulnerability workflow
    """
    
    def __init__(self, vuln_db_path: str = "/home/kali/bbhk/.swarm/memory.db"):
        self.vuln_db_path = vuln_db_path
        self.tools_manager = KaliToolsManager() if INTEGRATION_AVAILABLE else None
        self.integrator = ToolVulnerabilityIntegrator() if INTEGRATION_AVAILABLE else None
    
    def recommend_tools_for_vulnerability(self, vuln_id: int) -> List[Dict[str, Any]]:
        """Get tool recommendations for a specific vulnerability"""
        if not INTEGRATION_AVAILABLE:
            return []
        
        try:
            # Get vulnerability details from existing database
            conn = sqlite3.connect(self.vuln_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
            vuln = cursor.fetchone()
            
            if not vuln:
                return []
            
            # Get tool recommendations based on vulnerability type
            vuln_type = vuln["type"]
            recommendations = self.tools_manager.recommend_tools_for_vulnerability(vuln_type, 5)
            
            # Enrich with context from vulnerability
            program_handle = vuln["program_handle"] if vuln["program_handle"] else ""
            severity = vuln["severity"] if vuln["severity"] else "MEDIUM"
            
            for rec in recommendations:
                # Add contextual information
                rec["vulnerability_id"] = vuln_id
                rec["vulnerability_type"] = vuln_type
                rec["target_program"] = program_handle
                rec["priority_boost"] = 1.2 if severity in ["CRITICAL", "HIGH"] else 1.0
                rec["estimated_bounty"] = vuln["payout_max"] if vuln["payout_max"] else 0
            
            conn.close()
            return recommendations
            
        except Exception as e:
            print(f"❌ Error getting tool recommendations: {e}")
            return []
    
    def create_research_plan(self, vuln_id: int) -> Dict[str, Any]:
        """Create complete research plan for vulnerability"""
        if not INTEGRATION_AVAILABLE:
            return {"error": "Integration not available"}
        
        try:
            # Get vulnerability details
            conn = sqlite3.connect(self.vuln_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
            vuln = cursor.fetchone()
            
            if not vuln:
                return {"error": f"Vulnerability {vuln_id} not found"}
            
            # Create workflow
            workflow = self.integrator.create_vulnerability_workflow(
                vuln["type"],
                vuln["program_handle"] if vuln["program_handle"] else "unknown",
                complexity_level=2
            )
            
            if "error" in workflow:
                return workflow
            
            # Enhance with vulnerability context
            workflow["vulnerability_id"] = vuln_id
            workflow["vulnerability_details"] = {
                "type": vuln["type"],
                "severity": vuln["severity"] if vuln["severity"] else "MEDIUM",
                "program": vuln["program_handle"] if vuln["program_handle"] else "unknown",
                "bounty_potential": {
                    "min": vuln["payout_min"] if vuln["payout_min"] else 0,
                    "max": vuln["payout_max"] if vuln["payout_max"] else 0
                },
                "status": vuln["status"] if vuln["status"] else "new"
            }
            
            # Add installation checks
            for phase in workflow.get("phases", []):
                for tool in phase.get("tools", []):
                    if not tool.get("installed", False):
                        tool["install_priority"] = "high" if tool.get("effectiveness", 0) > 0.6 else "medium"
            
            conn.close()
            return workflow
            
        except Exception as e:
            return {"error": f"Failed to create research plan: {e}"}
    
    def start_vuln_research(self, vuln_id: int) -> int:
        """Start research session for specific vulnerability"""
        if not INTEGRATION_AVAILABLE:
            return -1
        
        research_plan = self.create_research_plan(vuln_id)
        if "error" in research_plan:
            print(f"❌ {research_plan['error']}")
            return -1
        
        # Start session
        vuln_details = research_plan["vulnerability_details"]
        session_id = self.integrator.start_research_session(
            vuln_details["program"],
            vuln_details["type"],
            research_plan
        )
        
        if session_id > 0:
            # Store association in vulnerability database
            try:
                conn = sqlite3.connect(self.vuln_db_path)
                cursor = conn.cursor()
                
                # Update vulnerability with research session info
                cursor.execute("""
                UPDATE vulnerabilities 
                SET data = json_set(COALESCE(data, '{}'), '$.research_session_id', ?)
                WHERE id = ?
                """, (session_id, vuln_id))
                
                conn.commit()
                conn.close()
                
                print(f"✅ Started research session {session_id} for vulnerability {vuln_id}")
                
            except Exception as e:
                print(f"⚠️ Session started but failed to link: {e}")
        
        return session_id
    
    def get_vuln_research_status(self, vuln_id: int) -> Dict[str, Any]:
        """Get research status for vulnerability"""
        if not INTEGRATION_AVAILABLE:
            return {"error": "Integration not available"}
        
        try:
            # Get vulnerability with research session info
            conn = sqlite3.connect(self.vuln_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
            vuln = cursor.fetchone()
            
            if not vuln:
                return {"error": f"Vulnerability {vuln_id} not found"}
            
            # Extract research session ID if exists
            data = json.loads(vuln["data"] if vuln["data"] else "{}")
            session_id = data.get("research_session_id")
            
            status = {
                "vulnerability_id": vuln_id,
                "type": vuln["type"],
                "program": vuln["program_handle"] if vuln["program_handle"] else "unknown",
                "status": vuln["status"] if vuln["status"] else "new",
                "research_session_id": session_id
            }
            
            if session_id:
                # Get session details
                cursor.execute("""
                SELECT * FROM research_sessions WHERE id = ?
                """, (session_id,))
                
                session = cursor.fetchone()
                if session:
                    status["research_status"] = {
                        "session_status": session["status"],
                        "tools_planned": json.loads(session["tools_planned"] or "[]"),
                        "tools_completed": json.loads(session["tools_completed"] or "[]"),
                        "time_spent": session["time_spent_minutes"],
                        "findings": len(json.loads(session["findings"] or "[]")),
                        "progress_percent": (
                            len(json.loads(session["tools_completed"] or "[]")) / 
                            max(len(json.loads(session["tools_planned"] or "[]")), 1) * 100
                        )
                    }
            
            conn.close()
            return status
            
        except Exception as e:
            return {"error": f"Failed to get research status: {e}"}
    
    def get_installed_tools_summary(self) -> Dict[str, Any]:
        """Get summary of installed tools for vulnerability research"""
        if not INTEGRATION_AVAILABLE:
            return {"error": "Integration not available"}
        
        try:
            report = self.tools_manager.generate_tool_report()
            
            summary = {
                "total_tools": report["summary"]["total_tools"],
                "installed_tools": report["summary"]["installed_tools"],
                "installation_rate": report["summary"]["installation_rate"],
                "categories": report["categories"],
                "missing_high_value": report.get("missing_high_value", [])
            }
            
            return summary
            
        except Exception as e:
            return {"error": f"Failed to get tools summary: {e}"}


def main():
    """Test the integration functionality"""
    print("🔗 Testing Vuln-Tools Integration")
    print("=" * 40)
    
    integration = VulnToolsIntegration()
    
    if not INTEGRATION_AVAILABLE:
        print("❌ Integration modules not available")
        return
    
    # Test with a sample vulnerability
    print("🧪 Testing tool recommendations...")
    
    # First, let's see what vulnerabilities exist
    conn = sqlite3.connect("/home/kali/bbhk/.swarm/memory.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, type, program_handle FROM vulnerabilities LIMIT 3")
    vulns = cursor.fetchall()
    conn.close()
    
    if vulns:
        vuln_id, vuln_type, program = vulns[0]
        print(f"Testing with vulnerability: {vuln_id} ({vuln_type} on {program})")
        
        # Get tool recommendations
        recommendations = integration.recommend_tools_for_vulnerability(vuln_id)
        if recommendations:
            print(f"\n🎯 Tool recommendations ({len(recommendations)}):")
            for rec in recommendations[:3]:
                status = "✅" if rec.get("installed") else "❌"
                print(f"  {status} {rec['tool_name']}: {rec['effectiveness']:.1%} effective")
        
        # Create research plan
        print(f"\n📋 Creating research plan...")
        plan = integration.create_research_plan(vuln_id)
        if "error" not in plan:
            print(f"  Phases: {len(plan.get('phases', []))}")
            print(f"  Estimated time: {plan.get('total_estimated_time', 0)} minutes")
            print(f"  Success probability: {plan.get('success_probability', 0):.1%}")
        else:
            print(f"  ❌ {plan['error']}")
    else:
        print("No vulnerabilities found in database for testing")
    
    # Show tools summary
    print(f"\n📊 Tools installation status...")
    summary = integration.get_installed_tools_summary()
    if "error" not in summary:
        print(f"  Installed: {summary['installed_tools']}/{summary['total_tools']} ({summary['installation_rate']:.1f}%)")
        if summary.get('missing_high_value'):
            print(f"  High-value missing: {len(summary['missing_high_value'])} tools")
    
    print("\n✅ Integration test complete!")


if __name__ == "__main__":
    main()