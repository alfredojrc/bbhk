"""Base scanner classes and utilities."""

import asyncio
import random
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set, AsyncGenerator
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
from loguru import logger

from ..core.database import Scan, Vulnerability, get_async_db
from ..core.config import config
from ..core.utils import generate_user_agent, random_delay, async_random_delay
from ..compliance.engine import compliance_engine

@dataclass
class ScanResult:
    """Represents a scan result."""
    target: str
    scan_type: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error: Optional[str] = None
    duration: float = 0.0
    
@dataclass
class Finding:
    """Represents a security finding."""
    title: str
    description: str
    severity: str  # low, medium, high, critical
    confidence: float  # 0.0 - 1.0
    url: str
    vulnerability_type: str
    payload: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    cvss_score: Optional[float] = None

class BaseScanner(ABC):
    """Base class for all scanners."""
    
    def __init__(self, name: str, program_id: int):
        """Initialize base scanner.
        
        Args:
            name: Scanner name
            program_id: Associated program ID
        """
        self.name = name
        self.program_id = program_id
        self.session = None
        self.running = False
        
        # Human-like behavior settings
        self.min_delay = config.scanner.default_timeout / 100
        self.max_delay = config.scanner.default_timeout / 50
        self.request_patterns = []
        
        # Statistics
        self.requests_made = 0
        self.findings_discovered = 0
        self.start_time = None
    
    @abstractmethod
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Perform scan on target."""
        pass
    
    async def start_scan(self, target: str, **kwargs) -> int:
        """Start a new scan and return scan ID."""
        try:
            # Check compliance before starting
            compliance_result = await compliance_engine.check_compliance(
                self.program_id, 'scan', target, **kwargs
            )
            
            if not compliance_result['allowed']:
                logger.error(f"Scan blocked by compliance: {compliance_result['violations']}")
                return await self._create_failed_scan(target, "Compliance violation", kwargs)
            
            # Create scan record
            scan_id = await self._create_scan_record(target, kwargs)
            
            # Perform the actual scan
            self.start_time = time.time()
            self.running = True
            
            try:
                result = await self.scan(target, **kwargs)
                await self._update_scan_record(scan_id, result)
                
                # Create vulnerability records for findings
                for finding_data in result.findings:
                    await self._create_vulnerability_record(scan_id, finding_data)
                
                logger.info(f"Scan completed: {self.name} on {target} "
                          f"- {len(result.findings)} findings")
                
            except Exception as e:
                logger.error(f"Scan failed: {self.name} on {target}: {e}")
                await self._update_scan_record(scan_id, ScanResult(
                    target=target,
                    scan_type=self.name,
                    success=False,
                    error=str(e),
                    duration=time.time() - self.start_time
                ))
            
            finally:
                self.running = False
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start scan: {e}")
            return await self._create_failed_scan(target, str(e), kwargs)
    
    async def stop_scan(self):
        """Stop the current scan."""
        self.running = False
        if self.session:
            await self.session.close()
        logger.info(f"Stopped scan: {self.name}")
    
    async def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[Dict]:
        """Make a human-like HTTP request."""
        # Check compliance for each request
        compliance_result = await compliance_engine.check_compliance(
            self.program_id, 'http_request', url, method=method, **kwargs
        )
        
        if not compliance_result['allowed']:
            logger.debug(f"Request blocked: {url}")
            return None
        
        # Add human-like delays
        await async_random_delay(self.min_delay, self.max_delay)
        
        # Add realistic headers
        headers = kwargs.get('headers', {})
        headers.update(self._get_realistic_headers())
        kwargs['headers'] = headers
        
        try:
            import aiohttp
            if not self.session:
                timeout = aiohttp.ClientTimeout(total=config.scanner.default_timeout)
                self.session = aiohttp.ClientSession(timeout=timeout)
            
            # Record request for compliance
            await compliance_engine.rate_limiters.get(self.program_id, 
                type('RateLimiter', (), {'record_request_start': lambda *args: None})()
            ).record_request_start('http_request', url)
            
            async with self.session.request(method, url, **kwargs) as response:
                self.requests_made += 1
                
                # Parse response based on content type
                content_type = response.headers.get('content-type', '').lower()
                
                if 'json' in content_type:
                    data = await response.json()
                elif 'text' in content_type or 'html' in content_type:
                    data = await response.text()
                else:
                    data = await response.read()
                
                return {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'data': data,
                    'url': str(response.url),
                    'method': method
                }
                
        except asyncio.TimeoutError:
            logger.debug(f"Request timeout: {url}")
            return None
        except Exception as e:
            logger.debug(f"Request failed: {url}: {e}")
            return None
    
    def _get_realistic_headers(self) -> Dict[str, str]:
        """Get realistic HTTP headers."""
        return {
            'User-Agent': generate_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        }
    
    async def _create_scan_record(self, target: str, parameters: Dict) -> int:
        """Create initial scan record in database."""
        async with get_async_db() as db:
            scan = Scan(
                program_id=self.program_id,
                scan_type=self.name,
                target=target,
                parameters=parameters,
                status='running',
                started_at=time.time()
            )
            db.add(scan)
            await db.commit()
            await db.refresh(scan)
            return scan.id
    
    async def _create_failed_scan(self, target: str, error: str, parameters: Dict) -> int:
        """Create failed scan record."""
        async with get_async_db() as db:
            scan = Scan(
                program_id=self.program_id,
                scan_type=self.name,
                target=target,
                parameters=parameters,
                status='failed',
                started_at=time.time(),
                completed_at=time.time(),
                duration=0.0,
                findings_count=0,
                raw_output=error
            )
            db.add(scan)
            await db.commit()
            await db.refresh(scan)
            return scan.id
    
    async def _update_scan_record(self, scan_id: int, result: ScanResult):
        """Update scan record with results."""
        async with get_async_db() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = 'completed' if result.success else 'failed'
                scan.completed_at = time.time()
                scan.duration = result.duration
                scan.findings_count = len(result.findings)
                scan.findings = [self._finding_to_dict(f) for f in result.findings]
                scan.raw_output = result.error if result.error else 'Completed successfully'
                await db.commit()
    
    async def _create_vulnerability_record(self, scan_id: int, finding: Dict[str, Any]):
        """Create vulnerability record from finding."""
        async with get_async_db() as db:
            vulnerability = Vulnerability(
                scan_id=scan_id,
                title=finding.get('title', 'Unknown vulnerability'),
                description=finding.get('description', ''),
                vulnerability_type=finding.get('vulnerability_type', 'other'),
                severity=finding.get('severity', 'low'),
                cvss_score=finding.get('cvss_score'),
                url=finding.get('url', ''),
                parameter=finding.get('parameter'),
                payload=finding.get('payload'),
                confidence=finding.get('confidence', 0.0),
                proof_of_concept=finding.get('evidence', {}).get('poc', ''),
                verified=False,
                reported=False
            )
            db.add(vulnerability)
            await db.commit()
    
    def _finding_to_dict(self, finding: Any) -> Dict[str, Any]:
        """Convert finding object to dictionary."""
        if isinstance(finding, dict):
            return finding
        elif hasattr(finding, '__dict__'):
            return finding.__dict__
        else:
            return {'raw': str(finding)}
    
    async def cleanup(self):
        """Clean up scanner resources."""
        self.running = False
        if self.session:
            await self.session.close()

class PassiveScanner(BaseScanner):
    """Base class for passive scanners that don't send requests."""
    
    async def make_request(self, *args, **kwargs) -> None:
        """Passive scanners don't make requests."""
        raise NotImplementedError("Passive scanners cannot make requests")

class ActiveScanner(BaseScanner):
    """Base class for active scanners that send requests."""
    
    def __init__(self, name: str, program_id: int):
        """Initialize active scanner."""
        super().__init__(name, program_id)
        self.max_concurrent_requests = config.scanner.max_concurrent_scans
        self.request_semaphore = asyncio.Semaphore(self.max_concurrent_requests)