#!/usr/bin/env python3
"""
Get ALL HackerOne Programs using the WORKING API endpoint
100% REAL DATA - No fakes!
"""

import asyncio
import aiohttp
import base64
import json
from typing import List, Dict, Any
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import os

# PRODUCTION: Use environment variables for credentials
USERNAME = os.getenv('HACKERONE_USERNAME', 'your_username')
API_TOKEN = os.getenv('HACKERONE_API_TOKEN', 'your_api_token')

# Validate credentials are provided
if USERNAME == 'your_username' or API_TOKEN == 'your_api_token':
    raise ValueError("CRITICAL: Set HACKERONE_USERNAME and HACKERONE_API_TOKEN environment variables")


class HackerOneProgramFetcher:
    """Fetches ALL programs from HackerOne using the working endpoint"""
    
    def __init__(self):
        self.base_url = "https://api.hackerone.com/v1"
        self.auth = base64.b64encode(f"{USERNAME}:{API_TOKEN}".encode()).decode()
        self.all_programs = []
        
    async def fetch_all_programs(self, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """Fetch ALL programs with pagination"""
        headers = {
            'Authorization': f'Basic {self.auth}',
            'Accept': 'application/json',
            'User-Agent': 'BBHK-Discovery/1.0'
        }
        
        programs = []
        page = 1
        page_size = 100  # Max page size
        
        while True:
            # Working endpoint: /v1/hackers/programs
            url = f"{self.base_url}/hackers/programs"
            params = {
                'page[number]': page,
                'page[size]': page_size
            }
            
            logger.info(f"Fetching page {page}...")
            
            try:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Extract programs from response
                        if 'data' in data:
                            page_programs = data['data']
                            programs.extend(page_programs)
                            logger.info(f"  Got {len(page_programs)} programs on page {page}")
                            
                            # Check if there are more pages
                            if len(page_programs) < page_size:
                                break  # No more programs
                            
                            page += 1
                            
                            # Small delay to respect rate limits
                            await asyncio.sleep(0.2)
                        else:
                            logger.warning(f"Unexpected response structure: {data.keys()}")
                            break
                    else:
                        logger.error(f"Failed to fetch page {page}: Status {response.status}")
                        break
                        
            except Exception as e:
                logger.error(f"Error fetching page {page}: {e}")
                break
        
        return programs
    
    def extract_program_details(self, program: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant details from program data"""
        attrs = program.get('attributes', {})
        
        return {
            'id': program.get('id', ''),
            'handle': attrs.get('handle', ''),
            'name': attrs.get('name', ''),
            'currency': attrs.get('currency', 'USD'),
            'offers_bounties': attrs.get('offers_bounties', False),
            'offers_swag': attrs.get('offers_swag', False),
            'managed': attrs.get('managed_program', False),
            'submission_state': attrs.get('submission_state', ''),
            'url': f"https://hackerone.com/{attrs.get('handle', '')}",
            'profile_picture': attrs.get('profile_picture', ''),
            'response_efficiency_percentage': attrs.get('response_efficiency_percentage', 0),
            'bounty_earned': attrs.get('bounty_earned', 0),
            'average_bounty': attrs.get('average_bounty', 0),
            'top_bounty': attrs.get('top_bounty', 0),
            'total_reports': attrs.get('total_reports_for_user', 0),
            'valid_reports': attrs.get('valid_reports_for_user', 0),
        }
    
    async def run(self):
        """Main execution"""
        logger.info("=" * 70)
        logger.info("FETCHING ALL HACKERONE PROGRAMS - 100% REAL DATA")
        logger.info("=" * 70)
        
        async with aiohttp.ClientSession() as session:
            # Fetch all programs
            raw_programs = await self.fetch_all_programs(session)
            
            # Process and extract details
            for prog in raw_programs:
                details = self.extract_program_details(prog)
                self.all_programs.append(details)
            
            logger.info(f"\n✅ Successfully fetched {len(self.all_programs)} REAL programs!")
            
            # Sort by top bounty
            self.all_programs.sort(key=lambda x: x.get('top_bounty', 0), reverse=True)
            
            return self.all_programs


async def main():
    """Run the fetcher and display results"""
    fetcher = HackerOneProgramFetcher()
    programs = await fetcher.run()
    
    # Display all programs
    print("\n" + "=" * 70)
    print("ALL HACKERONE PROGRAMS (REAL DATA)")
    print("=" * 70)
    
    for i, prog in enumerate(programs, 1):
        print(f"\n{i}. {prog['name']} (@{prog['handle']})")
        print(f"   URL: https://hackerone.com/{prog['handle']}")
        
        if prog['offers_bounties']:
            print(f"   💰 Offers Bounties: Yes")
            if prog['top_bounty'] > 0:
                print(f"   💵 Top Bounty: ${prog['top_bounty']:,.0f}")
            if prog['average_bounty'] > 0:
                print(f"   💵 Avg Bounty: ${prog['average_bounty']:,.0f}")
        
        if prog['managed']:
            print(f"   🏢 Managed Program: Yes")
        
        if prog['response_efficiency_percentage'] > 0:
            print(f"   ⚡ Response Rate: {prog['response_efficiency_percentage']:.1f}%")
        
        print(f"   📊 State: {prog['submission_state']}")
    
    # Save to JSON
    output = {
        'timestamp': datetime.now().isoformat(),
        'total_programs': len(programs),
        'programs': programs
    }
    
    with open('reports/all_hackerone_programs.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n" + "=" * 70)
    print(f"SUMMARY:")
    print(f"  Total Programs: {len(programs)}")
    print(f"  Programs with Bounties: {sum(1 for p in programs if p['offers_bounties'])}")
    print(f"  Managed Programs: {sum(1 for p in programs if p['managed'])}")
    print(f"  Programs with Swag: {sum(1 for p in programs if p['offers_swag'])}")
    print(f"\n📄 Full list saved to: reports/all_hackerone_programs.json")
    print("=" * 70)
    
    return programs


if __name__ == "__main__":
    programs = asyncio.run(main())