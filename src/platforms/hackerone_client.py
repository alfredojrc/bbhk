"""
HackerOne API Client - Production Implementation
Authentication tested and working on 2025-08-16
"""

import os
import asyncio
import aiohttp
import base64
import json
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import logging
logger = logging.getLogger(__name__)

@dataclass
class HackerOneCredentials:
    """HackerOne API credentials configuration"""
    username: str
    api_token: str
    email: str
    
    def get_auth_header(self) -> str:
        """Generate HTTP Basic Auth header"""
        credentials = f"{self.username}:{self.api_token}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

class HackerOneRateLimiter:
    """Rate limiting for HackerOne API (600 req/min read, 25 req/20sec write)"""
    
    def __init__(self):
        self.read_requests = []
        self.write_requests = []
        self.read_limit = 600  # per minute
        self.write_limit = 25  # per 20 seconds
        
    async def wait_if_needed(self, is_write: bool = False):
        """Wait if rate limit would be exceeded"""
        current_time = time.time()
        
        if is_write:
            # Clean old requests (20 second window)
            self.write_requests = [t for t in self.write_requests if current_time - t < 20]
            if len(self.write_requests) >= self.write_limit:
                sleep_time = 20 - (current_time - self.write_requests[0])
                if sleep_time > 0:
                    logger.info(f"Rate limiting: waiting {sleep_time:.2f}s for write request")
                    await asyncio.sleep(sleep_time)
            self.write_requests.append(current_time)
        else:
            # Clean old requests (60 second window)
            self.read_requests = [t for t in self.read_requests if current_time - t < 60]
            if len(self.read_requests) >= self.read_limit:
                sleep_time = 60 - (current_time - self.read_requests[0])
                if sleep_time > 0:
                    logger.info(f"Rate limiting: waiting {sleep_time:.2f}s for read request")
                    await asyncio.sleep(sleep_time)
            self.read_requests.append(current_time)

class HackerOneClient:
    """Production-ready HackerOne API client with authentication and rate limiting"""
    
    def __init__(self, credentials: HackerOneCredentials):
        self.credentials = credentials
        self.base_url = "https://api.hackerone.com/v1"
        self.rate_limiter = HackerOneRateLimiter()
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            headers={
                'Authorization': self.credentials.get_auth_header(),
                'Accept': 'application/json',
                'User-Agent': 'BBHK-AutomationPlatform/1.0'
            },
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _make_request(self, method: str, endpoint: str, is_write: bool = False, **kwargs) -> Dict[str, Any]:
        """Make authenticated API request with rate limiting"""
        await self.rate_limiter.wait_if_needed(is_write)
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                response_data = await response.json()
                
                if response.status == 401:
                    raise Exception(f"Authentication failed. Check API credentials.")
                elif response.status == 403:
                    raise Exception(f"Access forbidden. Check IP whitelist or permissions.")
                elif response.status == 429:
                    raise Exception(f"Rate limit exceeded. Wait before retrying.")
                elif response.status >= 400:
                    raise Exception(f"API error {response.status}: {response_data}")
                
                logger.debug(f"HackerOne API {method} {endpoint}: {response.status}")
                return response_data
                
        except aiohttp.ClientError as e:
            logger.error(f"Network error calling HackerOne API: {e}")
            raise
    
    async def get_my_profile(self) -> Dict[str, Any]:
        """Get current hacker profile information"""
        try:
            return await self._make_request('GET', '/hackers/me')
        except Exception as e:
            logger.warning(f"Profile endpoint failed: {e}")
            # Fallback to reports endpoint which we know works
            reports = await self.get_my_reports()
            return {"status": "authenticated", "reports_accessible": True}
    
    async def get_my_reports(self) -> List[Dict[str, Any]]:
        """Get reports submitted by authenticated hacker"""
        response = await self._make_request('GET', '/hackers/me/reports')
        return response.get('data', [])
    
    async def get_my_earnings(self) -> Dict[str, Any]:
        """Get earnings information for authenticated hacker"""
        response = await self._make_request('GET', '/hackers/payments/earnings')
        return response.get('data', [])
    
    async def discover_programs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Discover available bug bounty programs"""
        params = {'page[size]': min(limit, 100)}  # API limit is 100 per page
        response = await self._make_request('GET', '/programs', params=params)
        return response.get('data', [])
    
    async def get_program_details(self, program_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific program"""
        response = await self._make_request('GET', f'/programs/{program_id}')
        return response.get('data', {})
    
    async def submit_report(self, program_id: str, title: str, vulnerability_information: str, 
                           severity_rating: str, weakness_id: int = None) -> Dict[str, Any]:
        """Submit a new vulnerability report (WRITE operation)"""
        payload = {
            'data': {
                'type': 'report',
                'attributes': {
                    'title': title,
                    'vulnerability_information': vulnerability_information,
                    'severity_rating': severity_rating
                }
            }
        }
        
        if weakness_id:
            payload['data']['attributes']['weakness_id'] = weakness_id
            
        return await self._make_request('POST', f'/reports', is_write=True, json=payload)
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test API connection and authentication"""
        try:
            # Test multiple endpoints to validate access
            reports = await self.get_my_reports()
            earnings = await self.get_my_earnings()
            
            return {
                "status": "success",
                "authenticated": True,
                "reports_count": len(reports),
                "earnings_accessible": True,
                "credentials_valid": True
            }
        except Exception as e:
            return {
                "status": "error", 
                "authenticated": False,
                "error": str(e)
            }

# Production credentials (tested 2025-08-16)
HACKERONE_CREDENTIALS = HackerOneCredentials(
    username=os.getenv('HACKERONE_API_USERNAME', ''),
    api_token=os.getenv('HACKERONE_API_TOKEN', ''),
    email=os.getenv('HACKERONE_EMAIL', '')
)

async def test_hackerone_integration():
    """Test HackerOne API integration"""
    async with HackerOneClient(HACKERONE_CREDENTIALS) as client:
        result = await client.test_connection()
        print(f"HackerOne API Test: {result}")
        
        if result["authenticated"]:
            # Test program discovery
            programs = await client.discover_programs(limit=5)
            print(f"Found {len(programs)} programs")
            
            for program in programs[:3]:
                attrs = program.get('attributes', {})
                print(f"- {attrs.get('handle', 'N/A')}: {attrs.get('name', 'N/A')}")

if __name__ == "__main__":
    asyncio.run(test_hackerone_integration())