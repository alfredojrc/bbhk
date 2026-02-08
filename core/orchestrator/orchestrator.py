#!/usr/bin/env python3
"""
BBHK Orchestrator - Coordinates all agent activities
Simple implementation following KISS principle
"""

import time
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from queue import Queue, Empty
from enum import Enum

class AgentState(Enum):
    """Agent lifecycle states"""
    IDLE = "idle"
    RUNNING = "running"
    ROTATING = "rotating"
    ERROR = "error"
    COMPLETED = "completed"

class MessageType(Enum):
    """Inter-agent message types"""
    TASK = "task"
    RESULT = "result"
    STATUS = "status"
    ERROR = "error"
    CONTROL = "control"

class Agent:
    """Simple agent representation"""
    
    def __init__(self, agent_id: str, agent_type: str):
        self.id = agent_id
        self.type = agent_type
        self.state = AgentState.IDLE
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.tasks_completed = 0
        self.current_task = None
        
    def should_rotate(self) -> bool:
        """Check if agent should rotate (3-hour lifecycle)"""
        age = datetime.now() - self.created_at
        return age > timedelta(hours=3)

class Orchestrator:
    """Coordinates all BBHK agent activities"""
    
    def __init__(self, db_path: str = "/home/kali/bbhk/data/bbhk.db"):
        self.db_path = db_path
        self.agents = {}  # agent_id -> Agent
        self.message_queue = Queue()
        self.task_queue = Queue()
        self.running = False
        self.max_agents = 10  # Claude Max plan constraint
        
        # Agent type to module mapping
        self.agent_modules = {
            "platform_manager": "platforms",
            "knowledge_expert": "core.database",
            "recon_specialist": "src.scanner",
            "pattern_analyst": "core.researcher",
            "hacker": "src.scanner.vulnerability",
            "validator": "src.scanner.base",
            "reporter": "src.reporting",
            "monitor": "src.monitor",
            "scope_manager": "src.compliance",
            "evidence_collector": "src.scanner",
            "orchestrator": "core.orchestrator",
            "learning_agent": "src.analytics"
        }
        
    def start(self):
        """Start the orchestrator"""
        self.running = True
        print("🎼 Orchestrator started")
        
        # Start message processor thread
        message_thread = threading.Thread(target=self._process_messages)
        message_thread.daemon = True
        message_thread.start()
        
        # Start task scheduler thread
        scheduler_thread = threading.Thread(target=self._schedule_tasks)
        scheduler_thread.daemon = True
        scheduler_thread.start()
        
        # Start agent lifecycle manager
        lifecycle_thread = threading.Thread(target=self._manage_lifecycle)
        lifecycle_thread.daemon = True
        lifecycle_thread.start()
        
    def stop(self):
        """Stop the orchestrator"""
        self.running = False
        print("🛑 Orchestrator stopped")
        
    def spawn_agent(self, agent_type: str, capabilities: List[str] = None) -> str:
        """Spawn a new agent"""
        if len(self.agents) >= self.max_agents:
            # Rotate oldest agent if at max capacity
            self._rotate_oldest_agent()
            
        agent_id = f"{agent_type}_{int(time.time())}"
        agent = Agent(agent_id, agent_type)
        self.agents[agent_id] = agent
        
        print(f"✨ Spawned {agent_type} agent: {agent_id}")
        self._log_event("agent_spawned", {"agent_id": agent_id, "type": agent_type})
        
        return agent_id
        
    def dispatch_task(self, task: Dict) -> str:
        """Dispatch a task to appropriate agent"""
        task_id = f"task_{int(time.time() * 1000)}"
        task["id"] = task_id
        task["status"] = "queued"
        task["created_at"] = datetime.now().isoformat()
        
        self.task_queue.put(task)
        print(f"📋 Task queued: {task_id}")
        
        return task_id
        
    def coordinate_workflow(self, workflow: Dict) -> str:
        """Coordinate a multi-agent workflow"""
        workflow_id = f"workflow_{int(time.time())}"
        
        print(f"🔄 Starting workflow: {workflow_id}")
        
        # Execute workflow steps in sequence
        for step in workflow.get("steps", []):
            agent_type = step.get("agent")
            task = step.get("task")
            
            # Ensure agent exists
            agent_id = self._get_or_create_agent(agent_type)
            
            # Dispatch task to agent
            task_data = {
                "workflow_id": workflow_id,
                "agent_id": agent_id,
                "action": task,
                "params": step.get("params", {})
            }
            
            self.dispatch_task(task_data)
            
            # Wait for completion if sequential
            if workflow.get("mode") == "sequential":
                self._wait_for_task_completion(task_data["id"])
                
        return workflow_id
        
    def get_agent_status(self, agent_id: str) -> Optional[Dict]:
        """Get current status of an agent"""
        agent = self.agents.get(agent_id)
        if not agent:
            return None
            
        return {
            "id": agent.id,
            "type": agent.type,
            "state": agent.state.value,
            "created_at": agent.created_at.isoformat(),
            "last_activity": agent.last_activity.isoformat(),
            "tasks_completed": agent.tasks_completed,
            "should_rotate": agent.should_rotate()
        }
        
    def list_agents(self) -> List[Dict]:
        """List all active agents"""
        return [self.get_agent_status(aid) for aid in self.agents.keys()]
        
    def send_message(self, source: str, target: str, message_type: MessageType, payload: Any):
        """Send message between agents"""
        message = {
            "id": f"msg_{int(time.time() * 1000)}",
            "source": source,
            "target": target,
            "type": message_type.value,
            "payload": payload,
            "timestamp": datetime.now().isoformat()
        }
        
        self.message_queue.put(message)
        
    def _process_messages(self):
        """Process inter-agent messages"""
        while self.running:
            try:
                message = self.message_queue.get(timeout=1)
                
                # Route message to target agent
                target = message.get("target")
                if target in self.agents:
                    agent = self.agents[target]
                    agent.last_activity = datetime.now()
                    
                    # Process based on message type
                    if message["type"] == MessageType.TASK.value:
                        self._assign_task_to_agent(agent, message["payload"])
                    elif message["type"] == MessageType.RESULT.value:
                        self._process_agent_result(agent, message["payload"])
                        
            except Empty:
                continue
            except Exception as e:
                print(f"Error processing message: {e}")
                
    def _schedule_tasks(self):
        """Schedule tasks to available agents"""
        while self.running:
            try:
                task = self.task_queue.get(timeout=1)
                
                # Find suitable agent
                agent_type = task.get("agent_type")
                agent = self._find_available_agent(agent_type)
                
                if agent:
                    self._assign_task_to_agent(agent, task)
                else:
                    # Re-queue task if no agent available
                    self.task_queue.put(task)
                    time.sleep(1)
                    
            except Empty:
                continue
            except Exception as e:
                print(f"Error scheduling task: {e}")
                
    def _manage_lifecycle(self):
        """Manage agent lifecycle and rotation"""
        while self.running:
            try:
                # Check for agents needing rotation
                for agent_id, agent in list(self.agents.items()):
                    if agent.should_rotate():
                        print(f"🔄 Rotating agent: {agent_id}")
                        self._rotate_agent(agent_id)
                        
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                print(f"Error in lifecycle management: {e}")
                
    def _get_or_create_agent(self, agent_type: str) -> str:
        """Get existing agent or create new one"""
        # Check for existing agent of this type
        for agent_id, agent in self.agents.items():
            if agent.type == agent_type and agent.state == AgentState.IDLE:
                return agent_id
                
        # Create new agent
        return self.spawn_agent(agent_type)
        
    def _find_available_agent(self, agent_type: str) -> Optional[Agent]:
        """Find an available agent of specified type"""
        for agent in self.agents.values():
            if agent.type == agent_type and agent.state == AgentState.IDLE:
                return agent
        return None
        
    def _assign_task_to_agent(self, agent: Agent, task: Dict):
        """Assign a task to an agent"""
        agent.state = AgentState.RUNNING
        agent.current_task = task
        agent.last_activity = datetime.now()
        
        print(f"▶️ Agent {agent.id} executing task: {task.get('id')}")
        self._log_event("task_assigned", {"agent_id": agent.id, "task_id": task.get("id")})
        
    def _process_agent_result(self, agent: Agent, result: Dict):
        """Process result from an agent"""
        agent.state = AgentState.IDLE
        agent.tasks_completed += 1
        agent.current_task = None
        
        print(f"✅ Agent {agent.id} completed task")
        self._log_event("task_completed", {"agent_id": agent.id, "result": result})
        
    def _rotate_agent(self, agent_id: str):
        """Rotate an agent (3-hour lifecycle)"""
        old_agent = self.agents.get(agent_id)
        if not old_agent:
            return
            
        # Create new agent of same type
        new_agent_id = self.spawn_agent(old_agent.type)
        
        # Remove old agent
        del self.agents[agent_id]
        
        self._log_event("agent_rotated", {
            "old_agent": agent_id,
            "new_agent": new_agent_id
        })
        
    def _rotate_oldest_agent(self):
        """Rotate the oldest agent when at capacity"""
        if not self.agents:
            return
            
        oldest = min(self.agents.values(), key=lambda a: a.created_at)
        self._rotate_agent(oldest.id)
        
    def _wait_for_task_completion(self, task_id: str, timeout: int = 300):
        """Wait for a task to complete"""
        start = time.time()
        while time.time() - start < timeout:
            # Check if task is complete
            # In real implementation, would check task status
            time.sleep(1)
            
    def _log_event(self, event_type: str, data: Dict):
        """Log orchestrator events to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Ensure logs table exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS orchestrator_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type VARCHAR(50),
                    data TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute(
                "INSERT INTO orchestrator_logs (event_type, data) VALUES (?, ?)",
                (event_type, json.dumps(data))
            )
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Error logging event: {e}")


def main():
    """Test the orchestrator"""
    orchestrator = Orchestrator()
    orchestrator.start()
    
    # Spawn some agents
    orchestrator.spawn_agent("recon_specialist")
    orchestrator.spawn_agent("pattern_analyst")
    orchestrator.spawn_agent("hacker")
    
    # Create a workflow
    workflow = {
        "name": "vulnerability_discovery",
        "mode": "sequential",
        "steps": [
            {"agent": "recon_specialist", "task": "enumerate_subdomains", "params": {"target": "example.com"}},
            {"agent": "pattern_analyst", "task": "generate_variants", "params": {"pattern": "sqli"}},
            {"agent": "hacker", "task": "test_vulnerabilities", "params": {"variants": 10}}
        ]
    }
    
    workflow_id = orchestrator.coordinate_workflow(workflow)
    print(f"Started workflow: {workflow_id}")
    
    # List agents
    agents = orchestrator.list_agents()
    print(f"Active agents: {len(agents)}")
    for agent in agents:
        print(f"  - {agent['type']}: {agent['state']}")
    
    # Keep running for demo
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        orchestrator.stop()


if __name__ == "__main__":
    main()