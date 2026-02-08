#!/usr/bin/env python3
"""
HackerOne Platform API Client
Simple implementation for personal bug hunting
"""

import requests
import json
import time
from typing import Dict, List, Optional
from datetime import datetime

class HackerOneAPI:
    """Simple HackerOne API client for personal use"""
    
    def __init__(self, api_token: str):
        self.api_token = api_token
        self.base_url = "https://api.hackerone.com/v1"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.rate_limit_delay = 1  # 1 second between requests
        
    def authenticate(self) -> bool:
        """Test authentication with HackerOne API"""
        try:
            response = requests.get(
                f"{self.base_url}/me",
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
                params={"page[size]": limit},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                for program in data.get("data", []):
                    programs.append({
                        "id": program.get("id"),
                        "name": program.get("attributes", {}).get("name"),
                        "handle": program.get("attributes", {}).get("handle"),
                        "scope": self._extract_scope(program),
                        "max_bounty": program.get("attributes", {}).get("max_bounty"),
                        "submission_state": program.get("attributes", {}).get("submission_state")
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
                "data": {
                    "type": "report",
                    "attributes": {
                        "title": report_data.get("title"),
                        "vulnerability_information": report_data.get("description"),
                        "impact": report_data.get("impact"),
                        "severity_rating": report_data.get("severity", "medium"),
                        "weakness_id": report_data.get("weakness_id")
                    },
                    "relationships": {
                        "program": {
                            "data": {
                                "id": program_id,
                                "type": "program"
                            }
                        }
                    }
                }
            }
            
            response = requests.post(
                f"{self.base_url}/reports",
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 201:
                report = response.json()
                return report.get("data", {}).get("id")
            else:
                print(f"Report submission failed: {response.text}")
                return None
                
        except Exception as e:
            print(f"Error submitting report: {e}")
            return None
        finally:
            time.sleep(self.rate_limit_delay)
    
    def check_status(self, report_id: str) -> Optional[Dict]:
        """Check the status of a submitted report"""
        try:
            response = requests.get(
                f"{self.base_url}/reports/{report_id}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                report = response.json()
                return {
                    "id": report_id,
                    "state": report.get("data", {}).get("attributes", {}).get("state"),
                    "severity": report.get("data", {}).get("attributes", {}).get("severity_rating"),
                    "bounty_amount": report.get("data", {}).get("attributes", {}).get("bounty_amount"),
                    "last_activity": report.get("data", {}).get("attributes", {}).get("last_activity_at")
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
                f"{self.base_url}/reports",
                headers=self.headers,
                params={
                    "filter[state]": "resolved",
                    "filter[disclosed_at][gt]": "2024-01-01",
                    "page[size]": limit
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                for report in data.get("data", []):
                    if report.get("attributes", {}).get("disclosed_at"):
                        reports.append({
                            "id": report.get("id"),
                            "title": report.get("attributes", {}).get("title"),
                            "vulnerability_information": report.get("attributes", {}).get("vulnerability_information"),
                            "severity": report.get("attributes", {}).get("severity_rating"),
                            "weakness": report.get("attributes", {}).get("weakness"),
                            "disclosed_at": report.get("attributes", {}).get("disclosed_at")
                        })
            
            return reports
            
        except Exception as e:
            print(f"Error fetching disclosed reports: {e}")
            return []
        finally:
            time.sleep(self.rate_limit_delay)
    
    def _extract_scope(self, program: Dict) -> List[str]:
        """Extract in-scope targets from program data"""
        scope = []
        try:
            for asset in program.get("relationships", {}).get("structured_scopes", {}).get("data", []):
                if asset.get("attributes", {}).get("eligible_for_bounty"):
                    scope.append(asset.get("attributes", {}).get("asset_identifier"))
        except:
            pass
        return scope


def main():
    """Test the HackerOne API client"""
    import os
    
    api_token = os.getenv("HACKERONE_API_TOKEN", "")
    if not api_token:
        print("Please set HACKERONE_API_TOKEN environment variable")
        return
    
    client = HackerOneAPI(api_token)
    
    if client.authenticate():
        print("✓ Authentication successful")
        
        programs = client.fetch_programs(limit=5)
        print(f"✓ Found {len(programs)} programs")
        
        for program in programs[:3]:
            print(f"  - {program['name']} (Max bounty: ${program.get('max_bounty', 0)})")
    else:
        print("✗ Authentication failed")


if __name__ == "__main__":
    main()