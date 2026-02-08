"""Base classes for program monitoring."""

import asyncio
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timezone
from loguru import logger

from ..core.database import Program, get_async_db
from ..core.utils import RateLimiter, generate_user_agent, async_random_delay

@dataclass
class ProgramInfo:
    """Program information structure."""
    name: str
    platform: str
    url: str
    company: str
    description: str
    scope: List[str]
    out_of_scope: List[str]
    min_bounty: float
    max_bounty: float
    avg_bounty: float
    reports_resolved: int
    reports_submitted: int
    response_time_avg: Optional[float]
    status: str = 'active'

class BasePlatformMonitor(ABC):
    """Base class for platform-specific monitors."""
    
    def __init__(self, platform_name: str, rate_limit: int = 60):
        """Initialize base monitor.
        
        Args:
            platform_name: Name of the platform (e.g., 'hackerone')
            rate_limit: Max requests per minute
        """
        self.platform_name = platform_name
        self.rate_limiter = RateLimiter(rate_limit, 60)  # requests per minute
        self.session = None
        self.known_programs: Set[str] = set()
        self.running = False
        
    @abstractmethod
    async def fetch_programs(self) -> List[ProgramInfo]:
        """Fetch current programs from platform."""
        pass
    
    @abstractmethod
    async def fetch_program_details(self, program_url: str) -> Optional[ProgramInfo]:
        """Fetch detailed information for a specific program."""
        pass
    
    @abstractmethod
    async def check_program_updates(self, program: Program) -> Optional[Dict[str, Any]]:
        """Check for updates to existing program."""
        pass
    
    async def start_monitoring(self, check_interval: int = 300):
        """Start monitoring for program changes."""
        self.running = True
        logger.info(f"Starting {self.platform_name} monitor with {check_interval}s interval")
        
        while self.running:
            try:
                await self._monitor_cycle()
                await asyncio.sleep(check_interval)
            except Exception as e:
                logger.error(f"Monitor cycle failed for {self.platform_name}: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def stop_monitoring(self):
        """Stop monitoring."""
        self.running = False
        if self.session:
            await self.session.close()
        logger.info(f"Stopped {self.platform_name} monitor")
    
    async def _monitor_cycle(self):
        """Execute one monitoring cycle."""
        logger.debug(f"Running monitor cycle for {self.platform_name}")
        
        # Fetch current programs
        try:
            programs = await self.fetch_programs()
            logger.info(f"Found {len(programs)} programs on {self.platform_name}")
            
            # Process each program
            for program_info in programs:
                await self._process_program(program_info)
                await async_random_delay(0.5, 1.5)  # Be respectful
                
        except Exception as e:
            logger.error(f"Failed to fetch programs from {self.platform_name}: {e}")
    
    async def _process_program(self, program_info: ProgramInfo):
        """Process a single program."""
        async with get_async_db() as db:
            # Check if program exists
            existing = await db.query(Program).filter(
                Program.platform == self.platform_name,
                Program.url == program_info.url
            ).first()
            
            if existing:
                # Update existing program
                await self._update_program(db, existing, program_info)
            else:
                # Create new program
                await self._create_program(db, program_info)
                logger.info(f"New program discovered: {program_info.name}")
    
    async def _create_program(self, db, program_info: ProgramInfo):
        """Create new program record."""
        program = Program(
            name=program_info.name,
            platform=program_info.platform,
            url=program_info.url,
            company=program_info.company,
            description=program_info.description,
            scope=program_info.scope,
            out_of_scope=program_info.out_of_scope,
            min_bounty=program_info.min_bounty,
            max_bounty=program_info.max_bounty,
            avg_bounty=program_info.avg_bounty,
            reports_resolved=program_info.reports_resolved,
            reports_submitted=program_info.reports_submitted,
            response_time_avg=program_info.response_time_avg,
            status=program_info.status,
            discovered_at=datetime.now(timezone.utc)
        )
        
        db.add(program)
        await db.commit()
    
    async def _update_program(self, db, existing: Program, new_info: ProgramInfo):
        """Update existing program record."""
        changes = []
        
        # Check for significant changes
        if existing.max_bounty != new_info.max_bounty:
            changes.append(f"Max bounty: ${existing.max_bounty} -> ${new_info.max_bounty}")
            existing.max_bounty = new_info.max_bounty
        
        if existing.status != new_info.status:
            changes.append(f"Status: {existing.status} -> {new_info.status}")
            existing.status = new_info.status
        
        if set(existing.scope or []) != set(new_info.scope):
            changes.append("Scope updated")
            existing.scope = new_info.scope
        
        if changes:
            logger.info(f"Program updated - {existing.name}: {'; '.join(changes)}")
            existing.last_updated = datetime.now(timezone.utc)
            await db.commit()
    
    async def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[Dict]:
        """Make rate-limited HTTP request."""
        if not await self.rate_limiter.acquire():
            wait_time = self.rate_limiter.time_until_next_request()
            logger.debug(f"Rate limited, waiting {wait_time:.1f}s")
            await asyncio.sleep(wait_time)
            return await self._make_request(url, method, **kwargs)
        
        try:
            # Add realistic headers
            headers = kwargs.get('headers', {})
            headers.update({
                'User-Agent': generate_user_agent(),
                'Accept': 'application/json, text/html, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            kwargs['headers'] = headers
            
            # Make request
            import aiohttp
            if not self.session:
                self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
            
            async with self.session.request(method, url, **kwargs) as response:
                if response.status == 200:
                    content_type = response.headers.get('content-type', '')
                    if 'json' in content_type:
                        return await response.json()
                    else:
                        return {'text': await response.text()}
                else:
                    logger.warning(f"Request to {url} returned status {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Request to {url} failed: {e}")
            return None