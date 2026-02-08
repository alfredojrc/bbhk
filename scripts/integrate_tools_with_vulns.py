#!/usr/bin/env python3
"""
Tool-Vulnerability Integration Script for BBHK v3.0
Connects Kali tools with vulnerability patterns for intelligent recommendations
Implements seamless workflow integration with existing systems
"""

import sqlite3
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

try:
    from scripts.kali_tools_manager import KaliToolsManager, ToolCategory
    from scripts.hybrid_data_manager import HybridDB
    INTEGRATION_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Integration modules not available: {e}")
    INTEGRATION_AVAILABLE = False


class ToolVulnerabilityIntegrator:
    """
    Integration layer between tools and vulnerabilities
    Provides intelligent tool recommendations based on vulnerability patterns
    """
    
    def __init__(self, 
                 sqlite_path: str = "/home/kali/bbhk/.swarm/memory.db",
                 tools_manager: Optional[KaliToolsManager] = None,
                 hybrid_db: Optional[HybridDB] = None):
        
        self.sqlite_path = sqlite_path
        self.sqlite_conn = sqlite3.connect(sqlite_path)
        self.sqlite_conn.row_factory = sqlite3.Row
        
        self.tools_manager = tools_manager or KaliToolsManager()
        self.hybrid_db = hybrid_db or HybridDB()
        
        self._ensure_integration_tables()
    
    def _ensure_integration_tables(self):
        """Create integration tables for tool-vulnerability workflows"""
        cursor = self.sqlite_conn.cursor()
        
        # Vulnerability-Tool success tracking
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vuln_tool_success (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id INTEGER,
            tool_name TEXT,
            program_handle TEXT,
            success BOOLEAN DEFAULT FALSE,
            time_spent_minutes INTEGER,
            bounty_earned INTEGER DEFAULT 0,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
        )
        """)
        
        # Tool recommendation workflows
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tool_workflows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow_name TEXT NOT NULL,
            vulnerability_types TEXT,  -- JSON array
            tool_sequence TEXT,        -- JSON array of tools in order
            estimated_time_hours REAL,
            success_rate REAL,
            typical_bounty_range TEXT, -- JSON with min/max
            difficulty_level INTEGER,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Active research sessions
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS research_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_handle TEXT,
            vulnerability_target TEXT,
            tools_planned TEXT,        -- JSON array
            tools_completed TEXT,      -- JSON array
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            estimated_completion TIMESTAMP,
            status TEXT DEFAULT 'active',
            findings TEXT,             -- JSON array
            time_spent_minutes INTEGER DEFAULT 0
        )
        """)
        
        self.sqlite_conn.commit()
        print("✅ Integration tables created/verified")
    
    def create_vulnerability_workflow(self, 
                                    vuln_type: str,
                                    target_program: str,
                                    complexity_level: int = 2) -> Dict[str, Any]:
        """
        Create intelligent workflow for vulnerability research
        Returns ordered tool sequence with time estimates
        """
        try:
            # Get tool recommendations
            recommendations = self.tools_manager.recommend_tools_for_vulnerability(vuln_type)
            
            if not recommendations:
                return {"error": f"No tools found for vulnerability type: {vuln_type}"}
            
            # Filter by complexity level and installation status
            suitable_tools = []
            for rec in recommendations:
                if rec.get("complexity", 3) <= complexity_level + 1:  # Allow slightly higher complexity
                    suitable_tools.append(rec)
            
            if not suitable_tools:
                suitable_tools = recommendations[:3]  # Fallback to top 3
            
            # Create workflow phases
            workflow = {
                "vulnerability_type": vuln_type,
                "target_program": target_program,
                "complexity_level": complexity_level,
                "phases": [],
                "total_estimated_time": 0,
                "tools_needed": [],
                "success_probability": 0.0,
                "created_at": datetime.now().isoformat()
            }
            
            # Phase 1: Reconnaissance (always first)
            recon_tools = [t for t in suitable_tools if "reconnaissance" in t.get("category", "")]
            if not recon_tools:
                recon_tools = [t for t in suitable_tools if t.get("time_to_results", 60) < 30][:2]
            
            if recon_tools:
                phase1 = {
                    "phase": "reconnaissance",
                    "tools": recon_tools[:2],
                    "estimated_time": sum(t.get("time_to_results", 30) for t in recon_tools[:2]),
                    "description": "Initial target reconnaissance and surface mapping"
                }
                workflow["phases"].append(phase1)
                workflow["total_estimated_time"] += phase1["estimated_time"]
            
            # Phase 2: Vulnerability Detection
            detection_tools = [t for t in suitable_tools if t not in recon_tools][:2]
            if detection_tools:
                phase2 = {
                    "phase": "detection",
                    "tools": detection_tools,
                    "estimated_time": sum(t.get("time_to_results", 45) for t in detection_tools),
                    "description": f"Targeted {vuln_type} detection and validation"
                }
                workflow["phases"].append(phase2)
                workflow["total_estimated_time"] += phase2["estimated_time"]
            
            # Phase 3: Exploitation (if applicable)
            exploit_tools = [t for t in suitable_tools if "exploitation" in t.get("category", "")]
            if exploit_tools:
                phase3 = {
                    "phase": "exploitation",
                    "tools": exploit_tools[:1],
                    "estimated_time": exploit_tools[0].get("time_to_results", 60),
                    "description": "Proof of concept development and impact validation"
                }
                workflow["phases"].append(phase3)
                workflow["total_estimated_time"] += phase3["estimated_time"]
            
            # Calculate overall success probability
            avg_effectiveness = sum(t.get("effectiveness", 0.5) for t in suitable_tools) / len(suitable_tools)
            workflow["success_probability"] = min(avg_effectiveness * 0.8, 0.95)  # Cap at 95%
            
            # Collect all unique tools
            all_tools = set()
            for phase in workflow["phases"]:
                for tool in phase["tools"]:
                    all_tools.add(tool["tool_name"])
            workflow["tools_needed"] = list(all_tools)
            
            return workflow
            
        except Exception as e:
            return {"error": f"Failed to create workflow: {e}"}
    
    def start_research_session(self, 
                             program_handle: str,
                             vulnerability_target: str,
                             workflow: Optional[Dict[str, Any]] = None) -> int:
        """
        Start a new research session with tool tracking
        Returns session ID for tracking progress
        """
        try:
            cursor = self.sqlite_conn.cursor()
            
            # Create workflow if not provided
            if not workflow:
                workflow = self.create_vulnerability_workflow(
                    vulnerability_target,
                    program_handle
                )
            
            if "error" in workflow:
                raise Exception(workflow["error"])
            
            # Calculate estimated completion time
            from datetime import timedelta
            estimated_completion = datetime.now() + timedelta(minutes=workflow["total_estimated_time"])
            
            cursor.execute("""
            INSERT INTO research_sessions (
                program_handle, vulnerability_target, tools_planned, 
                estimated_completion, status
            ) VALUES (?, ?, ?, ?, ?)
            """, (
                program_handle,
                vulnerability_target,
                json.dumps(workflow["tools_needed"]),
                estimated_completion.isoformat(),
                "active"
            ))
            
            session_id = cursor.lastrowid
            self.sqlite_conn.commit()
            
            # Store workflow in memory for agent access
            self.hybrid_db.store_memory(
                key=f"research_session_{session_id}_workflow",
                value=json.dumps(workflow),
                namespace="active_research"
            )
            
            print(f"✅ Started research session {session_id}")
            print(f"   Target: {vulnerability_target} on {program_handle}")
            print(f"   Estimated time: {workflow['total_estimated_time']} minutes")
            print(f"   Tools needed: {', '.join(workflow['tools_needed'])}")
            
            return session_id
            
        except Exception as e:
            print(f"❌ Failed to start research session: {e}")
            return -1
    
    def update_session_progress(self, 
                              session_id: int,
                              completed_tool: str,
                              time_spent: int,
                              findings: List[str] = None) -> bool:
        """Update research session with completed tool and findings"""
        try:
            cursor = self.sqlite_conn.cursor()
            
            # Get current session data
            cursor.execute("SELECT * FROM research_sessions WHERE id = ?", (session_id,))
            session = cursor.fetchone()
            
            if not session:
                print(f"❌ Session {session_id} not found")
                return False
            
            # Update completed tools
            completed_tools = json.loads(session["tools_completed"] or "[]")
            if completed_tool not in completed_tools:
                completed_tools.append(completed_tool)
            
            # Update findings
            current_findings = json.loads(session["findings"] or "[]")
            if findings:
                current_findings.extend(findings)
            
            # Update time spent
            total_time = (session["time_spent_minutes"] or 0) + time_spent
            
            # Check if session is complete
            planned_tools = json.loads(session["tools_planned"] or "[]")
            status = "completed" if len(completed_tools) >= len(planned_tools) else "active"
            
            cursor.execute("""
            UPDATE research_sessions SET
                tools_completed = ?,
                findings = ?,
                time_spent_minutes = ?,
                status = ?
            WHERE id = ?
            """, (
                json.dumps(completed_tools),
                json.dumps(current_findings),
                total_time,
                status,
                session_id
            ))
            
            self.sqlite_conn.commit()
            
            print(f"✅ Updated session {session_id}: {completed_tool} completed in {time_spent}min")
            if findings:
                print(f"   Findings: {len(findings)} new items")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to update session progress: {e}")
            return False
    
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get all active research sessions"""
        try:
            cursor = self.sqlite_conn.cursor()
            cursor.execute("""
            SELECT * FROM research_sessions 
            WHERE status = 'active'
            ORDER BY start_time DESC
            """)
            
            sessions = []
            for row in cursor.fetchall():
                session_dict = dict(row)
                session_dict["tools_planned"] = json.loads(row["tools_planned"] or "[]")
                session_dict["tools_completed"] = json.loads(row["tools_completed"] or "[]")
                session_dict["findings"] = json.loads(row["findings"] or "[]")
                
                # Calculate progress
                planned_count = len(session_dict["tools_planned"])
                completed_count = len(session_dict["tools_completed"])
                session_dict["progress_percent"] = (completed_count / planned_count * 100) if planned_count > 0 else 0
                
                sessions.append(session_dict)
            
            return sessions
            
        except Exception as e:
            print(f"❌ Error getting active sessions: {e}")
            return []
    
    def analyze_tool_effectiveness(self, program_handle: Optional[str] = None) -> Dict[str, Any]:
        """Analyze which tools are most effective for different vulnerability types"""
        try:
            cursor = self.sqlite_conn.cursor()
            
            # Base query
            where_clause = ""
            params = []
            if program_handle:
                where_clause = "WHERE program_handle = ?"
                params = [program_handle]
            
            # Get tool success rates
            cursor.execute(f"""
            SELECT 
                tool_name,
                COUNT(*) as total_uses,
                SUM(CASE WHEN success THEN 1 ELSE 0 END) as successes,
                AVG(time_spent_minutes) as avg_time,
                SUM(bounty_earned) as total_bounty
            FROM vuln_tool_success 
            {where_clause}
            GROUP BY tool_name
            HAVING total_uses >= 2
            ORDER BY (successes * 1.0 / total_uses) DESC
            """, params)
            
            tool_stats = []
            for row in cursor.fetchall():
                success_rate = row["successes"] / row["total_uses"]
                tool_stats.append({
                    "tool_name": row["tool_name"],
                    "total_uses": row["total_uses"],
                    "success_rate": success_rate,
                    "avg_time_minutes": round(row["avg_time"] or 0, 1),
                    "total_bounty": row["total_bounty"] or 0,
                    "roi_per_hour": (row["total_bounty"] or 0) / ((row["avg_time"] or 60) / 60) if row["avg_time"] else 0
                })
            
            # Get vulnerability type performance
            cursor.execute(f"""
            SELECT 
                v.type as vulnerability_type,
                COUNT(vts.*) as attempts,
                SUM(CASE WHEN vts.success THEN 1 ELSE 0 END) as successes,
                AVG(vts.time_spent_minutes) as avg_time
            FROM vulnerabilities v
            LEFT JOIN vuln_tool_success vts ON v.id = vts.vulnerability_id
            {"WHERE v.program_handle = ?" if program_handle else ""}
            GROUP BY v.type
            HAVING attempts > 0
            ORDER BY (successes * 1.0 / attempts) DESC
            """, params if program_handle else [])
            
            vuln_type_stats = []
            for row in cursor.fetchall():
                if row["attempts"] > 0:
                    success_rate = row["successes"] / row["attempts"]
                    vuln_type_stats.append({
                        "vulnerability_type": row["vulnerability_type"],
                        "attempts": row["attempts"],
                        "success_rate": success_rate,
                        "avg_time_minutes": round(row["avg_time"] or 0, 1)
                    })
            
            return {
                "program_handle": program_handle or "all_programs",
                "tool_performance": tool_stats,
                "vulnerability_type_performance": vuln_type_stats,
                "analysis_date": datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"❌ Error analyzing tool effectiveness: {e}")
            return {}
    
    def get_next_recommended_action(self, session_id: int) -> Dict[str, Any]:
        """Get next recommended action for an active research session"""
        try:
            cursor = self.sqlite_conn.cursor()
            cursor.execute("SELECT * FROM research_sessions WHERE id = ?", (session_id,))
            session = cursor.fetchone()
            
            if not session or session["status"] != "active":
                return {"error": "Session not found or not active"}
            
            # Get workflow from memory
            workflow_data = self.hybrid_db.retrieve_memory(
                f"research_session_{session_id}_workflow",
                "active_research"
            )
            
            if not workflow_data:
                return {"error": "Workflow data not found"}
            
            workflow = json.loads(workflow_data)
            completed_tools = json.loads(session["tools_completed"] or "[]")
            
            # Find next tool in sequence
            next_action = None
            for phase in workflow["phases"]:
                for tool in phase["tools"]:
                    if tool["tool_name"] not in completed_tools:
                        next_action = {
                            "phase": phase["phase"],
                            "tool_name": tool["tool_name"],
                            "tool_description": tool.get("description", ""),
                            "estimated_time": tool.get("time_to_results", 30),
                            "complexity": tool.get("complexity", 2),
                            "installation_required": not tool.get("installed", False),
                            "installation_command": tool.get("installation", ""),
                            "usage_examples": tool.get("examples", []),
                            "effectiveness": tool.get("effectiveness", 0.5)
                        }
                        break
                if next_action:
                    break
            
            if not next_action:
                return {
                    "message": "All planned tools completed",
                    "recommendation": "Review findings and consider submission"
                }
            
            return {
                "session_id": session_id,
                "next_action": next_action,
                "progress": {
                    "completed": len(completed_tools),
                    "total": len(workflow.get("tools_needed", [])),
                    "time_spent": session["time_spent_minutes"] or 0
                }
            }
            
        except Exception as e:
            print(f"❌ Error getting next action: {e}")
            return {"error": str(e)}
    
    def record_tool_success(self, 
                          vulnerability_id: int,
                          tool_name: str,
                          program_handle: str,
                          success: bool,
                          time_spent: int,
                          bounty_earned: int = 0,
                          notes: str = "") -> bool:
        """Record tool usage outcome for learning and optimization"""
        try:
            cursor = self.sqlite_conn.cursor()
            cursor.execute("""
            INSERT INTO vuln_tool_success (
                vulnerability_id, tool_name, program_handle, success,
                time_spent_minutes, bounty_earned, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                vulnerability_id, tool_name, program_handle, success,
                time_spent, bounty_earned, notes
            ))
            
            self.sqlite_conn.commit()
            
            # Update tool effectiveness in tools database
            cursor.execute("""
            SELECT COUNT(*) as total, SUM(CASE WHEN success THEN 1 ELSE 0 END) as successes
            FROM vuln_tool_success WHERE tool_name = ?
            """, (tool_name,))
            
            result = cursor.fetchone()
            new_success_rate = result["successes"] / result["total"] if result["total"] > 0 else 0
            
            # Update tool success rate
            cursor.execute("""
            UPDATE kali_tools SET success_rate = ? WHERE name = ?
            """, (new_success_rate, tool_name))
            
            self.sqlite_conn.commit()
            
            print(f"✅ Recorded tool usage: {tool_name} ({'success' if success else 'failure'})")
            return True
            
        except Exception as e:
            print(f"❌ Error recording tool success: {e}")
            return False
    
    def close(self):
        """Close all connections"""
        if self.sqlite_conn:
            self.sqlite_conn.close()
        if self.tools_manager:
            self.tools_manager.close()
        if self.hybrid_db:
            self.hybrid_db.close()


def main():
    """Demonstration of tool-vulnerability integration"""
    print("🔗 Tool-Vulnerability Integration System")
    print("=" * 50)
    
    if not INTEGRATION_AVAILABLE:
        print("❌ Integration modules not available")
        return
    
    integrator = ToolVulnerabilityIntegrator()
    
    # Test workflow creation
    print("🎯 Creating vulnerability research workflow...")
    workflow = integrator.create_vulnerability_workflow(
        "prompt_injection",
        "openai",
        complexity_level=2
    )
    
    if "error" not in workflow:
        print(f"✅ Workflow created:")
        print(f"   Phases: {len(workflow['phases'])}")
        print(f"   Total time: {workflow['total_estimated_time']} minutes")
        print(f"   Success probability: {workflow['success_probability']:.1%}")
        print(f"   Tools needed: {', '.join(workflow['tools_needed'])}")
        
        # Start a test session
        session_id = integrator.start_research_session("openai", "prompt_injection", workflow)
        
        if session_id > 0:
            # Get next action
            next_action = integrator.get_next_recommended_action(session_id)
            if "error" not in next_action and "next_action" in next_action:
                action = next_action["next_action"]
                print(f"\n🎯 Next recommended action:")
                print(f"   Phase: {action['phase']}")
                print(f"   Tool: {action['tool_name']}")
                print(f"   Estimated time: {action['estimated_time']} minutes")
                if action.get("installation_required"):
                    print(f"   ⚠️ Installation needed: {action['installation_command']}")
                
                # Simulate tool completion
                print(f"\n🔧 Simulating tool usage...")
                integrator.update_session_progress(
                    session_id,
                    action['tool_name'],
                    25,  # 25 minutes spent
                    ["Found interesting endpoint", "Potential XSS vector identified"]
                )
    
    # Show active sessions
    active_sessions = integrator.get_active_sessions()
    print(f"\n📊 Active research sessions: {len(active_sessions)}")
    for session in active_sessions:
        print(f"   • Session {session['id']}: {session['vulnerability_target']} on {session['program_handle']}")
        print(f"     Progress: {session['progress_percent']:.1f}% ({session['time_spent_minutes']}min spent)")
    
    # Analyze effectiveness
    print(f"\n📈 Analyzing tool effectiveness...")
    analysis = integrator.analyze_tool_effectiveness()
    if analysis and "tool_performance" in analysis:
        print("Top performing tools:")
        for tool in analysis["tool_performance"][:3]:
            print(f"   • {tool['tool_name']}: {tool['success_rate']:.1%} success rate, ${tool['total_bounty']:,} earned")
    
    integrator.close()
    print("\n✅ Integration system test complete!")


if __name__ == "__main__":
    main()