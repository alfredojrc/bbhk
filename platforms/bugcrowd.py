#!/usr/bin/env python3
"""
Bugcrowd Platform API Client
Simple implementation for personal bug hunting
"""

import requests
import json
import time
from typing import Dict, List, Optional
from datetime import datetime

class BugcrowdAPI:
    """Simple Bugcrowd API client for personal use"""
    
    def __init__(self, api_token: str):
        self.api_token = api_token
        self.base_url = "https://api.bugcrowd.com"
        self.headers = {
            "Authorization": f"Token {api_token}",
            "Accept": "application/vnd.bugcrowd.v3+json",
            "Content-Type": "application/json"
        }
        self.rate_limit_delay = 1  # 1 second between requests
        
    def authenticate(self) -> bool:
        """Test authentication with Bugcrowd API"""
        try:
            response = requests.get(
                f"{self.base_url}/user",
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False
    
    def fetch_programs(self, limit: int = 100) -> List[Dict]:
        """Fetch available bug bounty programs"""
        programs = []
        try:
            response = requests.get(
                f"{self.base_url}/programs",
                headers=self.headers,
                params={"limit": limit, "offset": 0},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                for program in data.get("programs", []):
                    programs.append({
                        "id": program.get("code"),
                        "name": program.get("name"),
                        "url": program.get("program_url"),
                        "scope": self._extract_scope(program),
                        "max_reward": program.get("max_reward"),
                        "targets_count": program.get("targets_count", 0),
                        "accepting_submissions": program.get("accepting_submissions", False)
                    })
            
            time.sleep(self.rate_limit_delay)
            return programs
            
        except Exception as e:
            print(f"Error fetching programs: {e}")
            return []
    
    def submit_report(self, program_id: str, report_data: Dict) -> Optional[str]:
        """Submit a vulnerability report to a program"""
        try:
            payload = {
                "submission": {
                    "title": report_data.get("title"),
                    "description": report_data.get("description"),
                    "vulnerability_type": report_data.get("vulnerability_type"),
                    "severity": self._map_severity(report_data.get("severity", "P3")),
                    "proof_of_concept": report_data.get("poc", ""),
                    "impact": report_data.get("impact", ""),
                    "remediation": report_data.get("remediation", "")
                }
            }
            
            response = requests.post(
                f"{self.base_url}/programs/{program_id}/submissions",
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 201:
                submission = response.json()
                return submission.get("submission", {}).get("reference")
            else:
                print(f"Report submission failed: {response.text}")
                return None
                
        except Exception as e:
            print(f"Error submitting report: {e}")
            return None
        finally:
            time.sleep(self.rate_limit_delay)
    
    def check_status(self, submission_reference: str) -> Optional[Dict]:
        """Check the status of a submitted report"""
        try:
            response = requests.get(
                f"{self.base_url}/submissions/{submission_reference}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                submission = response.json().get("submission", {})
                return {
                    "reference": submission_reference,
                    "state": submission.get("state"),
                    "severity": submission.get("severity"),
                    "reward": submission.get("reward_amount"),
                    "currency": submission.get("reward_currency"),
                    "last_updated": submission.get("updated_at")
                }
            return None
            
        except Exception as e:
            print(f"Error checking status: {e}")
            return None
        finally:
            time.sleep(self.rate_limit_delay)
    
    def get_disclosed_reports(self, limit: int = 100) -> List[Dict]:
        """Fetch disclosed vulnerability reports for pattern analysis"""
        reports = []
        try:
            response = requests.get(
                f"{self.base_url}/submissions",
                headers=self.headers,
                params={
                    "filter[state]": "resolved",
                    "filter[disclosed]": "true",
                    "limit": limit
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                for submission in data.get("submissions", []):
                    reports.append({
                        "reference": submission.get("reference"),
                        "title": submission.get("title"),
                        "description": submission.get("description"),
                        "vulnerability_type": submission.get("vulnerability_type"),
                        "severity": submission.get("severity"),
                        "reward": submission.get("reward_amount"),
                        "disclosed_at": submission.get("disclosed_at")
                    })
            
            return reports
            
        except Exception as e:
            print(f"Error fetching disclosed reports: {e}")
            return []
        finally:
            time.sleep(self.rate_limit_delay)
    
    def get_program_targets(self, program_id: str) -> List[Dict]:
        """Get in-scope targets for a specific program"""
        targets = []
        try:
            response = requests.get(
                f"{self.base_url}/programs/{program_id}/targets",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                for target in data.get("targets", []):
                    targets.append({
                        "name": target.get("name"),
                        "category": target.get("category"),
                        "uri": target.get("uri"),
                        "description": target.get("description")
                    })
            
            return targets
            
        except Exception as e:
            print(f"Error fetching targets: {e}")
            return []
        finally:
            time.sleep(self.rate_limit_delay)
    
    def _extract_scope(self, program: Dict) -> List[str]:
        """Extract in-scope targets from program data"""
        scope = []
        try:
            targets = program.get("target_groups", [])
            for target_group in targets:
                for target in target_group.get("targets", []):
                    if target.get("uri"):
                        scope.append(target.get("uri"))
        except:
            pass
        return scope
    
    def _map_severity(self, severity: str) -> str:
        """Map severity ratings between different formats"""
        severity_map = {
            "critical": "P1",
            "high": "P2", 
            "medium": "P3",
            "low": "P4",
            "informational": "P5"
        }
        return severity_map.get(severity.lower(), severity)


def main():
    """Test the Bugcrowd API client"""
    import os
    
    api_token = os.getenv("BUGCROWD_API_TOKEN", "")
    if not api_token:
        print("Please set BUGCROWD_API_TOKEN environment variable")
        return
    
    client = BugcrowdAPI(api_token)
    
    if client.authenticate():
        print("✓ Authentication successful")
        
        programs = client.fetch_programs(limit=5)
        print(f"✓ Found {len(programs)} programs")
        
        for program in programs[:3]:
            print(f"  - {program['name']} (Max reward: ${program.get('max_reward', 0)})")
    else:
        print("✗ Authentication failed")


if __name__ == "__main__":
    main()