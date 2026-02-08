"""Bugcrowd platform monitor."""

import re
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from loguru import logger

from .base import BasePlatformMonitor, ProgramInfo
from ..core.utils import clean_html, parse_severity

class BugcrowdMonitor(BasePlatformMonitor):
    """Monitor for Bugcrowd platform."""
    
    def __init__(self):
        """Initialize Bugcrowd monitor."""
        super().__init__('bugcrowd', rate_limit=20)  # Conservative rate limiting
        self.base_url = 'https://bugcrowd.com'
    
    async def fetch_programs(self) -> List[ProgramInfo]:
        """Fetch current programs from Bugcrowd."""
        programs = []
        
        try:
            # Fetch programs page
            url = f"{self.base_url}/programs"
            response = await self._make_request(url)
            
            if not response or 'text' not in response:
                logger.error("Failed to fetch Bugcrowd programs page")
                return programs
            
            soup = BeautifulSoup(response['text'], 'html.parser')
            
            # Find program cards/listings
            program_elements = soup.find_all('div', class_=re.compile(r'program-card|program-item'))
            
            if not program_elements:
                # Try alternative selectors
                program_elements = soup.find_all('a', href=re.compile(r'/programs/[^/]+$'))
            
            for element in program_elements:
                program_info = await self._parse_program_element(element)
                if program_info:
                    programs.append(program_info)
            
            logger.info(f"Found {len(programs)} programs on Bugcrowd")
            
        except Exception as e:
            logger.error(f"Failed to fetch Bugcrowd programs: {e}")
        
        return programs
    
    async def fetch_program_details(self, program_url: str) -> Optional[ProgramInfo]:
        """Fetch detailed information for a specific program."""
        try:
            response = await self._make_request(program_url)
            
            if not response or 'text' not in response:
                logger.error(f"Failed to fetch program details for {program_url}")
                return None
            
            soup = BeautifulSoup(response['text'], 'html.parser')
            return await self._parse_program_details(soup, program_url)
            
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
    
    async def _parse_program_element(self, element) -> Optional[ProgramInfo]:
        """Parse program element from listing page."""
        try:
            # Extract program URL
            link_elem = element.find('a') if element.name != 'a' else element
            if not link_elem:
                return None
            
            program_url = urljoin(self.base_url, link_elem.get('href', ''))
            
            # Extract basic information
            name_elem = element.find(class_=re.compile(r'program-name|title'))
            name = name_elem.get_text(strip=True) if name_elem else ''
            
            # Extract company
            company_elem = element.find(class_=re.compile(r'company|organization'))
            company = company_elem.get_text(strip=True) if company_elem else name
            
            # Extract bounty info if available
            bounty_elem = element.find(class_=re.compile(r'bounty|reward'))
            max_bounty = 0.0
            if bounty_elem:
                bounty_text = bounty_elem.get_text(strip=True)
                max_bounty = self._extract_bounty_amount(bounty_text)
            
            # Basic program info - will need to fetch details later
            return ProgramInfo(
                name=name,
                platform='bugcrowd',
                url=program_url,
                company=company,
                description='',  # Fetch from details page
                scope=[],  # Fetch from details page
                out_of_scope=[],
                min_bounty=0.0,
                max_bounty=max_bounty,
                avg_bounty=max_bounty / 2 if max_bounty else 0.0,
                reports_resolved=0,
                reports_submitted=0,
                response_time_avg=None,
                status='active'  # Default, will be updated from details
            )
            
        except Exception as e:
            logger.error(f"Failed to parse program element: {e}")
            return None
    
    async def _parse_program_details(self, soup: BeautifulSoup, program_url: str) -> Optional[ProgramInfo]:
        """Parse detailed program information from program page."""
        try:
            # Extract program name
            name_elem = soup.find('h1') or soup.find(class_=re.compile(r'program-title|program-name'))
            name = name_elem.get_text(strip=True) if name_elem else ''
            
            # Extract description
            desc_elem = soup.find(class_=re.compile(r'description|about'))
            description = clean_html(str(desc_elem)) if desc_elem else ''
            
            # Extract scope
            scope = []
            scope_section = soup.find(id=re.compile(r'scope|targets')) or \
                           soup.find(class_=re.compile(r'scope|targets'))
            
            if scope_section:
                scope_items = scope_section.find_all(['li', 'div', 'p'])
                for item in scope_items:
                    scope_text = item.get_text(strip=True)
                    if scope_text and len(scope_text) > 5:  # Filter out empty/short items
                        scope.append(scope_text)
            
            # Extract out of scope
            out_of_scope = []
            oos_section = soup.find(id=re.compile(r'out-of-scope|exclusions')) or \
                         soup.find(class_=re.compile(r'out-of-scope|exclusions'))
            
            if oos_section:
                oos_items = oos_section.find_all(['li', 'div', 'p'])
                for item in oos_items:
                    oos_text = item.get_text(strip=True)
                    if oos_text and len(oos_text) > 5:
                        out_of_scope.append(oos_text)
            
            # Extract bounty information
            bounty_info = self._extract_bounty_info(soup)
            
            # Extract stats
            stats_info = self._extract_stats_info(soup)
            
            return ProgramInfo(
                name=name,
                platform='bugcrowd',
                url=program_url,
                company=stats_info.get('company', name),
                description=description,
                scope=scope,
                out_of_scope=out_of_scope,
                min_bounty=bounty_info.get('min_bounty', 0.0),
                max_bounty=bounty_info.get('max_bounty', 0.0),
                avg_bounty=bounty_info.get('avg_bounty', 0.0),
                reports_resolved=stats_info.get('reports_resolved', 0),
                reports_submitted=stats_info.get('reports_submitted', 0),
                response_time_avg=stats_info.get('response_time_avg'),
                status=stats_info.get('status', 'active')
            )
            
        except Exception as e:
            logger.error(f"Failed to parse program details: {e}")
            return None
    
    def _extract_bounty_info(self, soup: BeautifulSoup) -> Dict[str, float]:
        """Extract bounty information from soup."""
        bounty_info = {'min_bounty': 0.0, 'max_bounty': 0.0, 'avg_bounty': 0.0}
        
        try:
            # Look for bounty information
            bounty_elements = soup.find_all(text=re.compile(r'\$\d+'))
            amounts = []
            
            for elem in bounty_elements:
                amount = self._extract_bounty_amount(elem)
                if amount > 0:
                    amounts.append(amount)
            
            if amounts:
                bounty_info['min_bounty'] = min(amounts)
                bounty_info['max_bounty'] = max(amounts)
                bounty_info['avg_bounty'] = sum(amounts) / len(amounts)
            
        except Exception as e:
            logger.debug(f"Failed to extract bounty info: {e}")
        
        return bounty_info
    
    def _extract_stats_info(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract statistics information from soup."""
        stats_info = {}
        
        try:
            # Look for various statistics
            stats_elements = soup.find_all(class_=re.compile(r'stat|metric|count'))
            
            for elem in stats_elements:
                text = elem.get_text(strip=True).lower()
                
                # Extract numbers from text
                numbers = re.findall(r'\d+', text)
                if numbers:
                    number = int(numbers[0])
                    
                    if 'resolved' in text or 'submissions' in text:
                        stats_info['reports_resolved'] = number
                    elif 'response' in text and 'time' in text:
                        stats_info['response_time_avg'] = float(number)
            
            # Look for status indicators
            status_elem = soup.find(class_=re.compile(r'status|state'))
            if status_elem:
                status_text = status_elem.get_text(strip=True).lower()
                if 'closed' in status_text or 'ended' in status_text:
                    stats_info['status'] = 'closed'
                elif 'paused' in status_text:
                    stats_info['status'] = 'paused'
                else:
                    stats_info['status'] = 'active'
            
        except Exception as e:
            logger.debug(f"Failed to extract stats info: {e}")
        
        return stats_info
    
    def _extract_bounty_amount(self, text: str) -> float:
        """Extract bounty amount from text."""
        try:
            # Remove common currency symbols and formatting
            clean_text = re.sub(r'[,$]', '', str(text))
            
            # Find numbers
            matches = re.findall(r'\d+(?:\.\d+)?', clean_text)
            if matches:
                amount = float(matches[0])
                
                # Handle K/M suffixes
                if 'k' in text.lower():
                    amount *= 1000
                elif 'm' in text.lower():
                    amount *= 1000000
                
                return amount
        except (ValueError, IndexError, TypeError):
            pass

        return 0.0