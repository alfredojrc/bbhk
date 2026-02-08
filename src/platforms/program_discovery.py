"""
HackerOne Program Discovery Service
Phase 1A Implementation - Production Ready
"""

import asyncio
import hashlib
import json
from datetime import datetime
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, asdict
import logging
logger = logging.getLogger(__name__)

from .hackerone_client import HackerOneClient, HACKERONE_CREDENTIALS


@dataclass
class Program:
    """Represents a bug bounty program with all relevant metadata"""
    platform: str
    program_id: str
    handle: str
    name: str
    url: str
    submission_state: str
    managed: bool
    offers_bounties: bool
    max_bounty: Optional[float]
    currency: str
    response_efficiency_percentage: Optional[float]
    first_response_time: Optional[int]  # in hours
    triage_time: Optional[int]  # in hours
    resolution_time: Optional[int]  # in hours
    bookmarked: bool
    allows_private_disclosure: bool
    policy: Optional[str]
    scope: List[Dict[str, Any]]
    out_of_scope: List[str]
    created_at: datetime
    updated_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data
    
    def get_hash(self) -> str:
        """Generate unique hash for deduplication"""
        unique_str = f"{self.platform}:{self.handle}:{self.program_id}"
        return hashlib.sha256(unique_str.encode()).hexdigest()


class ProgramDiscoveryService:
    """Service for discovering and processing bug bounty programs"""
    
    def __init__(self):
        self.client = None
        self.discovered_programs: List[Program] = []
        self.seen_programs: Set[str] = set()
        
    async def initialize(self):
        """Initialize the service with HackerOne client"""
        self.client = HackerOneClient(HACKERONE_CREDENTIALS)
        await self.client.__aenter__()
        logger.info("Program discovery service initialized")
        
    async def cleanup(self):
        """Cleanup resources"""
        if self.client:
            await self.client.__aexit__(None, None, None)
    
    async def discover_programs(self, limit: int = 100, 
                              min_bounty: Optional[float] = None,
                              only_managed: bool = False) -> List[Program]:
        """
        Discover HackerOne programs with filtering options
        
        Args:
            limit: Maximum number of programs to fetch
            min_bounty: Minimum bounty amount filter
            only_managed: Only fetch managed programs
            
        Returns:
            List of discovered Program objects
        """
        try:
            logger.info(f"Starting program discovery (limit={limit})")
            
            # Fetch programs from API
            raw_programs = await self.client.discover_programs(limit=limit)
            logger.info(f"Fetched {len(raw_programs)} programs from HackerOne")
            
            # Process each program
            for raw_program in raw_programs:
                program = await self._process_program(raw_program)
                
                if program:
                    # Apply filters
                    if min_bounty and (not program.max_bounty or program.max_bounty < min_bounty):
                        continue
                    if only_managed and not program.managed:
                        continue
                    
                    # Check for duplicates
                    program_hash = program.get_hash()
                    if program_hash not in self.seen_programs:
                        self.seen_programs.add(program_hash)
                        self.discovered_programs.append(program)
                        logger.debug(f"Added program: {program.handle} ({program.name})")
            
            logger.info(f"Successfully discovered {len(self.discovered_programs)} unique programs")
            return self.discovered_programs
            
        except Exception as e:
            logger.error(f"Error during program discovery: {e}")
            raise
    
    async def _process_program(self, raw_data: Dict[str, Any]) -> Optional[Program]:
        """Process raw API data into Program object"""
        try:
            attrs = raw_data.get('attributes', {})
            
            # Extract bounty information
            max_bounty = None
            currency = 'USD'
            if 'bounty_table' in attrs:
                bounty_table = attrs['bounty_table']
                if bounty_table and 'bounty_table_rows' in bounty_table:
                    rows = bounty_table['bounty_table_rows']
                    if rows:
                        # Get maximum bounty from all severity levels
                        max_bounties = []
                        for row in rows:
                            if 'high' in row:
                                max_bounties.append(row['high'])
                            if 'critical' in row:
                                max_bounties.append(row['critical'])
                        if max_bounties:
                            max_bounty = max(max_bounties)
            
            # Create Program object
            program = Program(
                platform='hackerone',
                program_id=raw_data.get('id', ''),
                handle=attrs.get('handle', ''),
                name=attrs.get('name', ''),
                url=f"https://hackerone.com/{attrs.get('handle', '')}",
                submission_state=attrs.get('submission_state', 'open'),
                managed=attrs.get('managed', False),
                offers_bounties=attrs.get('offers_bounties', False),
                max_bounty=max_bounty,
                currency=currency,
                response_efficiency_percentage=attrs.get('response_efficiency_percentage'),
                first_response_time=attrs.get('first_response_time'),
                triage_time=attrs.get('triage_time'),
                resolution_time=attrs.get('resolution_time'),
                bookmarked=attrs.get('bookmarked', False),
                allows_private_disclosure=attrs.get('allows_private_disclosure', True),
                policy=attrs.get('policy', ''),
                scope=[],  # Will be populated by asset enumeration
                out_of_scope=[],  # Will be populated by asset enumeration
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            return program
            
        except Exception as e:
            logger.warning(f"Error processing program data: {e}")
            return None
    
    async def fetch_program_scope(self, program_id: str) -> Dict[str, Any]:
        """
        Fetch detailed scope information for a program
        
        Args:
            program_id: HackerOne program ID
            
        Returns:
            Dict containing in-scope and out-of-scope assets
        """
        try:
            # Get structured scopes from API
            response = await self.client._make_request('GET', f'/programs/{program_id}/structured_scopes')
            scopes = response.get('data', [])
            
            in_scope = []
            out_of_scope = []
            
            for scope_item in scopes:
                attrs = scope_item.get('attributes', {})
                asset = {
                    'asset_type': attrs.get('asset_type', ''),
                    'asset_identifier': attrs.get('asset_identifier', ''),
                    'eligible_for_bounty': attrs.get('eligible_for_bounty', False),
                    'eligible_for_submission': attrs.get('eligible_for_submission', False),
                    'instruction': attrs.get('instruction', ''),
                    'max_severity': attrs.get('max_severity', 'critical')
                }
                
                if attrs.get('eligible_for_submission', False):
                    in_scope.append(asset)
                else:
                    out_of_scope.append(asset['asset_identifier'])
            
            return {
                'in_scope': in_scope,
                'out_of_scope': out_of_scope
            }
            
        except Exception as e:
            logger.warning(f"Error fetching scope for program {program_id}: {e}")
            return {'in_scope': [], 'out_of_scope': []}
    
    async def enrich_with_scope(self, programs: Optional[List[Program]] = None):
        """
        Enrich programs with detailed scope information
        
        Args:
            programs: List of programs to enrich (uses discovered_programs if None)
        """
        if programs is None:
            programs = self.discovered_programs
        
        logger.info(f"Enriching {len(programs)} programs with scope information")
        
        for program in programs:
            if program.program_id:
                scope_data = await self.fetch_program_scope(program.program_id)
                program.scope = scope_data['in_scope']
                program.out_of_scope = scope_data['out_of_scope']
                logger.debug(f"Enriched {program.handle} with {len(program.scope)} in-scope assets")
        
        logger.info("Scope enrichment complete")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get discovery statistics"""
        total = len(self.discovered_programs)
        managed = sum(1 for p in self.discovered_programs if p.managed)
        with_bounties = sum(1 for p in self.discovered_programs if p.offers_bounties)
        
        bounty_amounts = [p.max_bounty for p in self.discovered_programs if p.max_bounty]
        avg_bounty = sum(bounty_amounts) / len(bounty_amounts) if bounty_amounts else 0
        max_bounty_overall = max(bounty_amounts) if bounty_amounts else 0
        
        return {
            'total_programs': total,
            'managed_programs': managed,
            'programs_with_bounties': with_bounties,
            'average_max_bounty': avg_bounty,
            'highest_bounty': max_bounty_overall,
            'unique_programs': len(self.seen_programs)
        }


async def main():
    """Test program discovery"""
    service = ProgramDiscoveryService()
    
    try:
        await service.initialize()
        
        # Discover programs
        programs = await service.discover_programs(limit=50, min_bounty=1000)
        
        # Enrich with scope (only first 5 for testing)
        await service.enrich_with_scope(programs[:5])
        
        # Show statistics
        stats = service.get_statistics()
        print(f"\nDiscovery Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        # Show sample programs
        print(f"\nSample Programs:")
        for program in programs[:5]:
            print(f"\n  {program.name} ({program.handle})")
            print(f"    - Platform: {program.platform}")
            print(f"    - Managed: {program.managed}")
            print(f"    - Max Bounty: ${program.max_bounty}")
            print(f"    - In-Scope Assets: {len(program.scope)}")
            
    finally:
        await service.cleanup()


if __name__ == "__main__":
    asyncio.run(main())