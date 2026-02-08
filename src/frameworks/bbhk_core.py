#!/usr/bin/env python3
"""
BBHK Core Framework - Personal Bug Bounty Hunting System
Modular, compliant, AI-powered hunting framework
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

@dataclass
class Program:
    """Bug bounty program representation"""
    name: str
    platform: str
    max_bounty: int
    scope: List[str] 
    rules: Dict[str, bool]
    allows_automation: bool
    response_time_avg: int
    acceptance_rate: float

@dataclass
class Target:
    """Target for hunting"""
    url: str
    program: str
    priority_score: float
    last_tested: Optional[datetime]
    findings_count: int

class ComplianceEngine:
    """Ensures all activities comply with program rules"""
    
    def __init__(self):
        self.rate_limits = {}
        self.blocked_actions = {}
    
    def check_compliance(self, program: Program, action: str) -> bool:
        """Check if action is allowed for program"""
        if not program.allows_automation and action in ['scan', 'brute']:
            return False
        
        if program.name in self.rate_limits:
            # Implement rate limiting logic
            pass
            
        return True
    
    def get_safe_delay(self, program: str) -> int:
        """Get safe delay between requests"""
        return self.rate_limits.get(program, 5)  # Default 5 seconds

class TargetPrioritizer:
    """AI-powered target prioritization"""
    
    def calculate_priority(self, program: Program) -> float:
        """Calculate target priority score"""
        factors = {
            'max_payout': min(program.max_bounty / 50000, 1.0),
            'response_time': max(0, 1 - (program.response_time_avg / 30)),
            'acceptance_rate': program.acceptance_rate,
            'allows_automation': 1.2 if program.allows_automation else 0.8,
        }
        
        # Weighted scoring
        score = (
            factors['max_payout'] * 0.3 +
            factors['response_time'] * 0.2 +
            factors['acceptance_rate'] * 0.3 +
            factors['allows_automation'] * 0.2
        )
        
        return min(score, 1.0)

class BBHKCore:
    """Main BBHK hunting framework"""
    
    def __init__(self):
        self.compliance = ComplianceEngine()
        self.prioritizer = TargetPrioritizer()
        self.programs = []
        self.targets = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/home/kali/bbhk/logs/bbhk_core.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def load_programs(self, programs_file: str) -> None:
        """Load bug bounty programs from config"""
        try:
            with open(programs_file, 'r') as f:
                data = json.load(f)
                self.programs = [Program(**p) for p in data['programs']]
            self.logger.info(f"Loaded {len(self.programs)} programs")
        except Exception as e:
            self.logger.error(f"Failed to load programs: {e}")
    
    async def discover_targets(self, program: Program) -> List[Target]:
        """Discover and prioritize targets for a program"""
        targets = []
        
        if not self.compliance.check_compliance(program, 'discovery'):
            self.logger.warning(f"Discovery not allowed for {program.name}")
            return targets
        
        # Passive discovery only
        for scope_item in program.scope:
            target = Target(
                url=scope_item,
                program=program.name,
                priority_score=self.prioritizer.calculate_priority(program),
                last_tested=None,
                findings_count=0
            )
            targets.append(target)
        
        return targets
    
    async def hunt_target(self, target: Target) -> Dict:
        """Hunt a specific target (compliance-aware)"""
        program = next(p for p in self.programs if p.name == target.program)
        
        if not self.compliance.check_compliance(program, 'hunt'):
            return {'status': 'blocked', 'reason': 'compliance'}
        
        self.logger.info(f"Hunting target: {target.url}")
        
        # Implement hunting logic here
        # This is where agents would be spawned for specific tasks
        
        result = {
            'status': 'completed',
            'target': target.url,
            'findings': [],
            'timestamp': datetime.now().isoformat()
        }
        
        return result

# Example usage
async def main():
    bbhk = BBHKCore()
    await bbhk.load_programs('/home/kali/bbhk/configs/programs.json')
    
    for program in bbhk.programs:
        targets = await bbhk.discover_targets(program)
        for target in targets[:3]:  # Limit to top 3 targets
            result = await bbhk.hunt_target(target)
            print(f"Hunt result: {result}")

if __name__ == "__main__":
    asyncio.run(main())