"""HackerOne platform monitor."""

import re
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from loguru import logger

from .base import BasePlatformMonitor, ProgramInfo
from ..core.utils import clean_html, parse_severity

class HackerOneMonitor(BasePlatformMonitor):
    """Monitor for HackerOne platform."""
    
    def __init__(self):
        """Initialize HackerOne monitor."""
        super().__init__('hackerone', rate_limit=30)  # Conservative rate limiting
        self.base_url = 'https://hackerone.com'
        self.api_base = 'https://hackerone.com/graphql'
    
    async def fetch_programs(self) -> List[ProgramInfo]:
        """Fetch current programs from HackerOne."""
        programs = []
        
        try:
            # Use HackerOne's directory API
            query = '''
            query DirectoryQuery($first: Int, $orderBy: HackeroneDirectoryOrderFieldEnum) {
              hackerone_directory(first: $first, order_by: $orderBy) {
                edges {
                  node {
                    id
                    name
                    handle
                    url
                    offers_bounties
                    average_bounty_lower_amount
                    average_bounty_upper_amount
                    submission_state
                    triage_active
                    response_efficiency_percentage
                    resolved_report_count
                    total_awarded_amount
                    company_handle
                    company_name
                  }
                }
              }
            }
            '''
            
            variables = {
                'first': 100,  # Adjust as needed
                'orderBy': 'LAUNCHED_AT'
            }
            
            response = await self._make_graphql_request(query, variables)
            
            if response and 'data' in response:
                for edge in response['data']['hackerone_directory']['edges']:
                    node = edge['node']
                    
                    # Skip non-bounty programs if focusing on bounties
                    if not node.get('offers_bounties'):
                        continue
                    
                    program_info = await self._parse_program_node(node)
                    if program_info:
                        programs.append(program_info)
            
        except Exception as e:
            logger.error(f"Failed to fetch HackerOne programs: {e}")
        
        return programs
    
    async def fetch_program_details(self, program_url: str) -> Optional[ProgramInfo]:
        """Fetch detailed information for a specific program."""
        try:
            # Extract handle from URL
            handle = program_url.split('/')[-1]
            
            query = '''
            query TeamProfile($handle: String!) {
              team(handle: $handle) {
                id
                handle
                name
                about
                website
                submission_state
                offers_bounties
                average_bounty_lower_amount
                average_bounty_upper_amount
                resolved_report_count
                policy
                in_scope_assets {
                  edges {
                    node {
                      asset_type
                      asset_identifier
                      instruction
                    }
                  }
                }
                out_of_scope_assets {
                  edges {
                    node {
                      asset_type
                      asset_identifier
                      instruction
                    }
                  }
                }
              }
            }
            '''
            
            variables = {'handle': handle}
            response = await self._make_graphql_request(query, variables)
            
            if response and 'data' in response and response['data']['team']:
                return await self._parse_team_details(response['data']['team'])
                
        except Exception as e:
            logger.error(f"Failed to fetch program details for {program_url}: {e}")
        
        return None
    
    async def check_program_updates(self, program) -> Optional[Dict[str, Any]]:
        """Check for updates to existing program."""
        try:
            current_info = await self.fetch_program_details(program.url)
            if not current_info:
                return None
            
            updates = {}
            
            # Check bounty changes
            if current_info.max_bounty != program.max_bounty:
                updates['max_bounty'] = {
                    'old': program.max_bounty,
                    'new': current_info.max_bounty
                }
            
            # Check status changes
            if current_info.status != program.status:
                updates['status'] = {
                    'old': program.status,
                    'new': current_info.status
                }
            
            # Check scope changes
            if set(current_info.scope) != set(program.scope or []):
                updates['scope'] = {
                    'added': list(set(current_info.scope) - set(program.scope or [])),
                    'removed': list(set(program.scope or []) - set(current_info.scope))
                }
            
            return updates if updates else None
            
        except Exception as e:
            logger.error(f"Failed to check updates for {program.name}: {e}")
            return None
    
    async def _make_graphql_request(self, query: str, variables: Dict[str, Any]) -> Optional[Dict]:
        """Make GraphQL request to HackerOne API."""
        payload = {
            'query': query,
            'variables': variables
        }
        
        headers = {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        return await self._make_request(
            self.api_base,
            method='POST',
            headers=headers,
            json=payload
        )
    
    async def _parse_program_node(self, node: Dict[str, Any]) -> Optional[ProgramInfo]:
        """Parse program node from GraphQL response."""
        try:
            return ProgramInfo(
                name=node.get('name', ''),
                platform='hackerone',
                url=f"https://hackerone.com/{node.get('handle', '')}",
                company=node.get('company_name', ''),
                description='',  # Not available in directory listing
                scope=[],  # Need to fetch details for scope
                out_of_scope=[],
                min_bounty=float(node.get('average_bounty_lower_amount', 0) or 0),
                max_bounty=float(node.get('average_bounty_upper_amount', 0) or 0),
                avg_bounty=float((node.get('average_bounty_lower_amount', 0) or 0 + 
                                node.get('average_bounty_upper_amount', 0) or 0) / 2),
                reports_resolved=int(node.get('resolved_report_count', 0) or 0),
                reports_submitted=0,  # Not available
                response_time_avg=None,
                status=self._parse_submission_state(node.get('submission_state', ''))
            )
        except Exception as e:
            logger.error(f"Failed to parse program node: {e}")
            return None
    
    async def _parse_team_details(self, team: Dict[str, Any]) -> Optional[ProgramInfo]:
        """Parse detailed team information."""
        try:
            # Parse scope
            scope = []
            for edge in team.get('in_scope_assets', {}).get('edges', []):
                asset = edge['node']
                scope.append(f"{asset.get('asset_type', '')}: {asset.get('asset_identifier', '')}")
            
            # Parse out of scope
            out_of_scope = []
            for edge in team.get('out_of_scope_assets', {}).get('edges', []):
                asset = edge['node']
                out_of_scope.append(f"{asset.get('asset_type', '')}: {asset.get('asset_identifier', '')}")
            
            return ProgramInfo(
                name=team.get('name', ''),
                platform='hackerone',
                url=f"https://hackerone.com/{team.get('handle', '')}",
                company=team.get('name', ''),
                description=clean_html(team.get('about', '')),
                scope=scope,
                out_of_scope=out_of_scope,
                min_bounty=float(team.get('average_bounty_lower_amount', 0) or 0),
                max_bounty=float(team.get('average_bounty_upper_amount', 0) or 0),
                avg_bounty=float((team.get('average_bounty_lower_amount', 0) or 0 + 
                                team.get('average_bounty_upper_amount', 0) or 0) / 2),
                reports_resolved=int(team.get('resolved_report_count', 0) or 0),
                reports_submitted=0,
                response_time_avg=None,
                status=self._parse_submission_state(team.get('submission_state', ''))
            )
        except Exception as e:
            logger.error(f"Failed to parse team details: {e}")
            return None
    
    def _parse_submission_state(self, state: str) -> str:
        """Parse HackerOne submission state to standard status."""
        state_map = {
            'open': 'active',
            'paused': 'paused',
            'closed': 'closed',
            'disabled': 'closed'
        }
        return state_map.get(state.lower(), 'active')