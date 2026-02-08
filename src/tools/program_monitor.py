#!/usr/bin/env python3
"""
Program Monitor - Tracks new bug bounty programs and changes
Passive monitoring system for program discovery
"""

import requests
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class ProgramMonitor:
    """Monitor bug bounty platforms for new programs and changes"""
    
    def __init__(self):
        self.platforms = {
            'hackerone': 'https://hackerone.com/programs.json',
            'bugcrowd': 'https://bugcrowd.com/programs.json',
            'intigriti': 'https://api.intigriti.com/core/program'
        }
        self.known_programs = self.load_known_programs()
        
    def load_known_programs(self) -> Dict:
        """Load previously discovered programs"""
        try:
            with open('/home/kali/bbhk/data/known_programs.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def save_known_programs(self):
        """Save current program state"""
        with open('/home/kali/bbhk/data/known_programs.json', 'w') as f:
            json.dump(self.known_programs, f, indent=2)
    
    def check_hackerone(self) -> List[Dict]:
        """Check HackerOne for new programs"""
        new_programs = []
        
        try:
            # Rate limited request
            time.sleep(2)
            response = requests.get(self.platforms['hackerone'], timeout=10)
            response.raise_for_status()
            
            programs = response.json().get('results', [])
            
            for program in programs:
                program_id = program.get('id')
                program_name = program.get('attributes', {}).get('handle')
                
                if program_id not in self.known_programs.get('hackerone', {}):
                    # New program found
                    new_program = {
                        'platform': 'hackerone',
                        'id': program_id,
                        'name': program_name,
                        'discovered': datetime.now().isoformat(),
                        'max_bounty': program.get('attributes', {}).get('currency', 'USD'),
                        'submission_state': program.get('attributes', {}).get('submission_state'),
                        'allows_automation': self.check_automation_allowed(program)
                    }
                    new_programs.append(new_program)
                    
                    # Add to known programs
                    if 'hackerone' not in self.known_programs:
                        self.known_programs['hackerone'] = {}
                    self.known_programs['hackerone'][program_id] = new_program
        
        except Exception as e:
            print(f"Error checking HackerOne: {e}")
        
        return new_programs
    
    def check_automation_allowed(self, program: Dict) -> bool:
        """Analyze program policy for automation permission"""
        # This would need to parse the actual program policy
        # For now, return False as default (safer)
        policy = program.get('attributes', {}).get('policy', '')
        
        # Look for keywords that might indicate automation is allowed
        automation_keywords = [
            'automated tools allowed',
            'scanning permitted',
            'tools are allowed'
        ]
        
        policy_lower = policy.lower()
        for keyword in automation_keywords:
            if keyword in policy_lower:
                return True
        
        # Look for explicit prohibitions
        prohibition_keywords = [
            'no automated',
            'automated scanning prohibited',
            'no scanning tools',
            'manual testing only'
        ]
        
        for keyword in prohibition_keywords:
            if keyword in policy_lower:
                return False
        
        # Default to False for safety
        return False
    
    def monitor_new_programs(self) -> List[Dict]:
        """Main monitoring function - returns new programs"""
        all_new_programs = []
        
        print(f"[{datetime.now()}] Checking for new programs...")
        
        # Check each platform
        new_h1_programs = self.check_hackerone()
        all_new_programs.extend(new_h1_programs)
        
        # Log new discoveries
        if all_new_programs:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'new_programs_count': len(all_new_programs),
                'programs': all_new_programs
            }
            
            # Log to file
            with open('/home/kali/bbhk/logs/recon/new_programs.log', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            print(f"Found {len(all_new_programs)} new programs!")
            for program in all_new_programs:
                print(f"  - {program['name']} on {program['platform']}")
        
        # Save updated state
        self.save_known_programs()
        
        return all_new_programs
    
    def calculate_priority_score(self, program: Dict) -> float:
        """Calculate hunting priority for a program"""
        score = 0.0
        
        # New programs get priority boost
        discovered = datetime.fromisoformat(program['discovered'])
        days_old = (datetime.now() - discovered).days
        if days_old < 7:
            score += 0.3  # New program boost
        
        # Automation allowed is a big factor
        if program.get('allows_automation', False):
            score += 0.4
        
        # Active submission state
        if program.get('submission_state') == 'open':
            score += 0.2
        
        # Platform preference (HackerOne tends to pay more)
        if program['platform'] == 'hackerone':
            score += 0.1
        
        return min(score, 1.0)

def main():
    """Run the program monitor"""
    monitor = ProgramMonitor()
    
    # Check for new programs
    new_programs = monitor.monitor_new_programs()
    
    # Priority ranking
    if new_programs:
        print("\nPriority Ranking:")
        sorted_programs = sorted(
            new_programs, 
            key=monitor.calculate_priority_score, 
            reverse=True
        )
        
        for i, program in enumerate(sorted_programs, 1):
            score = monitor.calculate_priority_score(program)
            print(f"{i}. {program['name']} (Score: {score:.2f})")

if __name__ == "__main__":
    main()