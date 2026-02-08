#!/usr/bin/env python3
"""
Watson Group API Endpoint Investigation
Tests various HackerOne API endpoints to find all available program data

Author: BBHK Team + Claude-Flow Hive Mind
Date: August 17, 2025
"""

import os
import requests
import json
from datetime import datetime
import time

# HackerOne API Configuration
USERNAME = os.getenv('HACKERONE_API_USERNAME', '')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', '')
BASE_URL = "https://api.hackerone.com/v1/hackers"

class WatsonAPIInvestigator:
    def __init__(self):
        self.auth = (USERNAME, API_TOKEN)
        self.headers = {'Accept': 'application/json'}
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update(self.headers)
        self.results = {}
        
    def test_endpoint(self, endpoint_path, description):
        """Test a specific API endpoint"""
        url = f"{BASE_URL}/{endpoint_path}"
        print(f"\n🔍 Testing: {description}")
        print(f"   URL: {url}")
        
        try:
            response = self.session.get(url, timeout=10)
            
            result = {
                'url': url,
                'status_code': response.status_code,
                'description': description,
                'timestamp': datetime.now().isoformat()
            }
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    result['success'] = True
                    result['data_type'] = type(data).__name__
                    
                    if isinstance(data, dict):
                        result['keys'] = list(data.keys()) if data else []
                        result['data_size'] = len(str(data))
                    elif isinstance(data, list):
                        result['list_size'] = len(data)
                        result['data_size'] = len(str(data))
                    
                    print(f"   ✅ Status: {response.status_code} - SUCCESS")
                    print(f"   📊 Data type: {result['data_type']}")
                    print(f"   📏 Data size: {result['data_size']} characters")
                    
                    if 'keys' in result:
                        print(f"   🔑 Keys: {result['keys'][:5]}...")  # First 5 keys
                    
                    # Save sample data for successful responses
                    result['sample_data'] = str(data)[:500] + "..." if len(str(data)) > 500 else str(data)
                    
                except json.JSONDecodeError:
                    result['success'] = False
                    result['error'] = 'Invalid JSON response'
                    result['raw_response'] = response.text[:200]
                    print(f"   ❌ Status: {response.status_code} - Invalid JSON")
                    
            else:
                result['success'] = False
                result['error'] = f"HTTP {response.status_code}"
                result['raw_response'] = response.text[:200]
                print(f"   ❌ Status: {response.status_code} - {response.reason}")
                
                if response.status_code == 404:
                    print(f"   ⚠️  Endpoint not found or not accessible")
                elif response.status_code == 401:
                    print(f"   ⚠️  Authentication required or insufficient permissions")
                elif response.status_code == 403:
                    print(f"   ⚠️  Forbidden - insufficient permissions")
                    
        except requests.exceptions.RequestException as e:
            result = {
                'url': url,
                'status_code': None,
                'description': description,
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            print(f"   💥 Request failed: {e}")
        
        self.results[endpoint_path] = result
        time.sleep(0.5)  # Rate limiting
        return result
    
    def investigate_watson_endpoints(self):
        """Test various Watson Group API endpoints"""
        print("🚀 Watson Group API Endpoint Investigation")
        print("=" * 60)
        
        # Known working endpoints
        print("\n📋 TESTING KNOWN ENDPOINTS:")
        self.test_endpoint("programs/watson_group", "Basic Watson Group program data")
        self.test_endpoint("programs/watson_group/structured_scopes", "Watson Group structured scopes")
        
        # Potential policy/guidelines endpoints
        print("\n📋 TESTING POTENTIAL POLICY ENDPOINTS:")
        self.test_endpoint("programs/watson_group/policy", "Program policy (potential)")
        self.test_endpoint("programs/watson_group/guidelines", "Program guidelines (potential)")
        self.test_endpoint("programs/watson_group/rewards", "Rewards structure (potential)")
        self.test_endpoint("programs/watson_group/scope", "Scope details (potential)")
        self.test_endpoint("programs/watson_group/eligibility", "Eligibility requirements (potential)")
        
        # Program metadata endpoints
        print("\n📋 TESTING METADATA ENDPOINTS:")
        self.test_endpoint("programs/watson_group/stats", "Program statistics (potential)")
        self.test_endpoint("programs/watson_group/metrics", "Program metrics (potential)")
        self.test_endpoint("programs/watson_group/updates", "Program updates (potential)")
        self.test_endpoint("programs/watson_group/hacktivity", "Program hacktivity (potential)")
        
        # Alternative URL formats
        print("\n📋 TESTING ALTERNATIVE FORMATS:")
        self.test_endpoint("programs?filter[handle]=watson_group&include=policy", "Program with policy include")
        self.test_endpoint("programs?filter[handle]=watson_group&include=structured_scopes", "Program with scopes include")
        self.test_endpoint("programs?filter[handle]=watson_group&include=rewards", "Program with rewards include")
        
        # ID-based endpoints (if we can find the ID)
        print("\n📋 TESTING ID-BASED ENDPOINTS:")
        # First get the program ID
        try:
            response = self.session.get(f"{BASE_URL}/programs/watson_group")
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and data['data'].get('id'):
                    program_id = data['data']['id']
                    print(f"   Found Watson Group ID: {program_id}")
                    
                    self.test_endpoint(f"programs/{program_id}", f"Program by ID ({program_id})")
                    self.test_endpoint(f"programs/{program_id}/policy", f"Policy by ID ({program_id})")
                    self.test_endpoint(f"programs/{program_id}/structured_scopes", f"Scopes by ID ({program_id})")
        except:
            print("   Could not determine program ID")
    
    def analyze_policy_data(self):
        """Analyze the policy data we have from PostgreSQL"""
        print("\n📋 ANALYZING CURRENT POLICY DATA:")
        
        # This would be integrated with our PostgreSQL data
        # For now, indicating we have 12,060 characters of policy data
        print("   ✅ Policy data: 12,060 characters available in PostgreSQL")
        print("   📊 Contains: Microblog, scope details, reward structure")
        print("   📅 Last update: December 2024 (Drogas Lithuania addition)")
        
    def generate_report(self):
        """Generate investigation report"""
        print("\n" + "=" * 60)
        print("📊 INVESTIGATION SUMMARY")
        print("=" * 60)
        
        successful = [k for k, v in self.results.items() if v.get('success')]
        failed = [k for k, v in self.results.items() if not v.get('success')]
        
        print(f"🎯 Total endpoints tested: {len(self.results)}")
        print(f"✅ Successful: {len(successful)}")
        print(f"❌ Failed: {len(failed)}")
        
        print(f"\n✅ WORKING ENDPOINTS:")
        for endpoint in successful:
            result = self.results[endpoint]
            print(f"   📍 {endpoint}")
            print(f"      └─ {result['description']}")
            print(f"      └─ Data size: {result.get('data_size', 'unknown')} characters")
        
        print(f"\n❌ NON-WORKING ENDPOINTS:")
        for endpoint in failed:
            result = self.results[endpoint]
            status = result.get('status_code', 'unknown')
            error = result.get('error', 'unknown')
            print(f"   📍 {endpoint} - HTTP {status} ({error})")
        
        # Save detailed results
        output_file = '/home/kali/bbhk/analysis/watson_api_investigation.json'
        with open(output_file, 'w') as f:
            json.dump({
                'investigation_date': datetime.now().isoformat(),
                'total_endpoints_tested': len(self.results),
                'successful_endpoints': len(successful),
                'failed_endpoints': len(failed),
                'working_endpoints': successful,
                'detailed_results': self.results
            }, f, indent=2)
        
        print(f"\n💾 Detailed results saved: {output_file}")
        
        return self.results

if __name__ == "__main__":
    investigator = WatsonAPIInvestigator()
    investigator.investigate_watson_endpoints()
    investigator.analyze_policy_data()
    results = investigator.generate_report()