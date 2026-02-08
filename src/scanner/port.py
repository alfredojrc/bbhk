"""Port scanning and service enumeration."""

import asyncio
import socket
from typing import List, Dict, Any, Set, Tuple
from urllib.parse import urlparse
from loguru import logger

from .base import ActiveScanner, ScanResult, Finding
from ..core.utils import is_ip_address

class PortScanner(ActiveScanner):
    """Port scanner for service enumeration."""
    
    def __init__(self, program_id: int):
        """Initialize port scanner."""
        super().__init__('port_scan', program_id)
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017
        ]
        
        # Extended port list for thorough scans
        self.extended_ports = self.common_ports + [
            20, 69, 88, 135, 389, 445, 464, 636, 873, 902, 1433, 1521, 1522,
            2049, 2375, 2376, 3000, 3001, 4444, 5000, 5001, 5060, 5061,
            5432, 5984, 6000, 6001, 6379, 7000, 7001, 8000, 8001, 8008,
            8009, 8081, 8082, 8090, 8180, 8443, 9000, 9001, 9090, 9200,
            9300, 9999, 10000, 11211, 50070
        ]
        
        # Service fingerprints
        self.service_signatures = {
            21: {'service': 'FTP', 'banners': [b'220', b'FTP']},
            22: {'service': 'SSH', 'banners': [b'SSH-2.0', b'SSH-1.99']},
            23: {'service': 'Telnet', 'banners': [b'Telnet']},
            25: {'service': 'SMTP', 'banners': [b'220', b'SMTP', b'ESMTP']},
            53: {'service': 'DNS', 'banners': []},
            80: {'service': 'HTTP', 'banners': [b'HTTP/']},
            110: {'service': 'POP3', 'banners': [b'+OK']},
            143: {'service': 'IMAP', 'banners': [b'* OK']},
            443: {'service': 'HTTPS', 'banners': []},
            993: {'service': 'IMAPS', 'banners': []},
            995: {'service': 'POP3S', 'banners': []},
            3306: {'service': 'MySQL', 'banners': [b'mysql']},
            3389: {'service': 'RDP', 'banners': []},
            5432: {'service': 'PostgreSQL', 'banners': []},
            6379: {'service': 'Redis', 'banners': [b'-NOAUTH', b'+PONG']},
            8080: {'service': 'HTTP-Alt', 'banners': [b'HTTP/']},
            9200: {'service': 'Elasticsearch', 'banners': [b'elasticsearch']},
            27017: {'service': 'MongoDB', 'banners': []}
        }
    
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Perform port scan on target."""
        import time
        start_time = time.time()
        findings = []
        
        try:
            # Parse target
            if target.startswith('http'):
                parsed = urlparse(target)
                host = parsed.hostname
            else:
                host = target.strip()
            
            # Validate target
            if not host:
                return ScanResult(
                    target=target,
                    scan_type=self.name,
                    success=False,
                    error="Invalid target format",
                    duration=time.time() - start_time
                )
            
            # Determine port list based on scan type
            scan_type = kwargs.get('scan_type', 'common')
            if scan_type == 'full':
                ports = list(range(1, 65536))
            elif scan_type == 'extended':
                ports = self.extended_ports
            else:
                ports = self.common_ports
            
            # Custom port list
            if 'ports' in kwargs:
                ports = kwargs['ports']
            
            logger.info(f"Starting port scan on {host} ({len(ports)} ports)")
            
            # Perform port scan with rate limiting
            open_ports = await self._scan_ports(host, ports)
            
            # Service detection on open ports
            services = {}
            if kwargs.get('service_detection', True):
                services = await self._detect_services(host, open_ports)
            
            # Create findings for open ports
            for port in sorted(open_ports):
                service_info = services.get(port, {})
                service_name = service_info.get('service', 'unknown')
                banner = service_info.get('banner', '')
                
                # Determine severity based on service
                severity = self._assess_port_severity(port, service_name)
                
                finding = Finding(
                    title=f"Open port discovered: {port}/{service_name}",
                    description=f"Port {port} is open on {host} running {service_name}",
                    severity=severity,
                    confidence=0.95,
                    url=f"{host}:{port}",
                    vulnerability_type="information_disclosure",
                    evidence={
                        'host': host,
                        'port': port,
                        'service': service_name,
                        'banner': banner,
                        'protocol': 'tcp'
                    }
                )
                findings.append(finding)
            
            # Check for dangerous service combinations
            dangerous_combos = self._check_dangerous_combinations(open_ports, services)
            findings.extend(dangerous_combos)
            
            logger.info(f"Port scan completed: {len(open_ports)} open ports found")
            
            return ScanResult(
                target=target,
                scan_type=self.name,
                findings=findings,
                metadata={
                    'host': host,
                    'total_ports_scanned': len(ports),
                    'open_ports': len(open_ports),
                    'services_detected': len(services)
                },
                success=True,
                duration=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            return ScanResult(
                target=target,
                scan_type=self.name,
                success=False,
                error=str(e),
                duration=time.time() - start_time
            )
    
    async def _scan_ports(self, host: str, ports: List[int]) -> Set[int]:
        """Scan ports using TCP connect."""
        open_ports = set()
        
        async def scan_port(port: int):
            """Scan a single port."""
            if not self.running:
                return
            
            try:
                # Use asyncio to create connection with timeout
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(future, timeout=5.0)
                
                # Port is open
                open_ports.add(port)
                
                # Close connection
                writer.close()
                await writer.wait_closed()
                
                logger.debug(f"Port {port} is open on {host}")
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Port is closed or filtered
                pass
            except Exception as e:
                logger.debug(f"Error scanning port {port} on {host}: {e}")
            
            # Small delay to be respectful
            await asyncio.sleep(0.01)
        
        # Scan with limited concurrency
        semaphore = asyncio.Semaphore(50)  # Limit concurrent connections
        
        async def scan_with_semaphore(port: int):
            async with semaphore:
                await scan_port(port)
        
        # Create tasks for all ports
        tasks = [scan_with_semaphore(port) for port in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return open_ports
    
    async def _detect_services(self, host: str, ports: Set[int]) -> Dict[int, Dict[str, str]]:
        """Detect services running on open ports."""
        services = {}
        
        async def detect_service(port: int):
            """Detect service on a specific port."""
            if not self.running:
                return
            
            try:
                # Connect and try to get banner
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(future, timeout=10.0)
                
                service_info = {'service': 'unknown', 'banner': ''}
                
                # Send probe based on port
                probe = self._get_service_probe(port)
                if probe:
                    writer.write(probe)
                    await writer.drain()
                
                # Read response
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                    banner = data.decode('utf-8', errors='ignore').strip()
                    service_info['banner'] = banner
                    
                    # Identify service from banner
                    service_info['service'] = self._identify_service(port, banner)
                    
                except asyncio.TimeoutError:
                    # No banner received
                    pass
                
                # Close connection
                writer.close()
                await writer.wait_closed()
                
                services[port] = service_info
                logger.debug(f"Service detected on {host}:{port} - {service_info['service']}")
                
            except Exception as e:
                logger.debug(f"Service detection failed for {host}:{port}: {e}")
                services[port] = {'service': 'unknown', 'banner': ''}
        
        # Detect services with limited concurrency
        semaphore = asyncio.Semaphore(10)
        
        async def detect_with_semaphore(port: int):
            async with semaphore:
                await detect_service(port)
        
        tasks = [detect_with_semaphore(port) for port in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return services
    
    def _get_service_probe(self, port: int) -> bytes:
        """Get appropriate probe for service detection."""
        probes = {
            21: b'',  # FTP sends banner immediately
            22: b'',  # SSH sends banner immediately
            25: b'EHLO test\r\n',  # SMTP
            80: b'GET / HTTP/1.1\r\nHost: test\r\n\r\n',  # HTTP
            110: b'',  # POP3 sends banner immediately
            143: b'',  # IMAP sends banner immediately
            6379: b'PING\r\n'  # Redis
        }
        return probes.get(port, b'')
    
    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service from port and banner."""
        banner_lower = banner.lower()
        
        # Check known signatures
        if port in self.service_signatures:
            expected_service = self.service_signatures[port]['service']
            expected_banners = self.service_signatures[port]['banners']
            
            # Check if banner matches expected
            for sig in expected_banners:
                if sig.decode('utf-8', errors='ignore').lower() in banner_lower:
                    return expected_service
            
            # If no banner match but common port, return expected service
            if not banner:
                return expected_service
        
        # Service identification based on banner patterns
        if 'http/' in banner_lower:
            return 'HTTP'
        elif 'ssh' in banner_lower:
            return 'SSH'
        elif 'ftp' in banner_lower or '220' in banner:
            return 'FTP'
        elif 'smtp' in banner_lower or 'mail' in banner_lower:
            return 'SMTP'
        elif 'mysql' in banner_lower:
            return 'MySQL'
        elif 'redis' in banner_lower or 'pong' in banner_lower:
            return 'Redis'
        elif 'elasticsearch' in banner_lower:
            return 'Elasticsearch'
        elif 'mongodb' in banner_lower:
            return 'MongoDB'
        
        return 'unknown'
    
    def _assess_port_severity(self, port: int, service: str) -> str:
        """Assess severity of open port based on port and service."""
        # Critical ports (dangerous services)
        if port in [23, 135, 445, 1433, 3389, 5432, 6379, 27017]:
            return 'high'
        
        # Administrative/management ports
        if port in [21, 22, 25, 110, 143, 993, 995, 3306]:
            return 'medium'
        
        # Web services
        if port in [80, 443, 8080, 8443]:
            return 'low'
        
        # Service-based assessment
        if service.lower() in ['telnet', 'ftp', 'rdp', 'mysql', 'postgresql', 'redis', 'mongodb']:
            return 'medium'
        
        return 'low'
    
    def _check_dangerous_combinations(self, ports: Set[int], services: Dict[int, Dict]) -> List[Finding]:
        """Check for dangerous service combinations."""
        dangerous_findings = []
        
        # Database + Web server combination
        db_ports = {3306, 5432, 6379, 27017} & ports
        web_ports = {80, 443, 8080, 8443} & ports
        
        if db_ports and web_ports:
            dangerous_findings.append(Finding(
                title="Database and web server on same host",
                description=f"Both database services {db_ports} and web services {web_ports} are exposed",
                severity="medium",
                confidence=0.8,
                url="",
                vulnerability_type="information_disclosure",
                evidence={
                    'database_ports': list(db_ports),
                    'web_ports': list(web_ports),
                    'risk': 'potential_data_exposure'
                }
            ))
        
        # Multiple administrative services
        admin_ports = {21, 22, 23, 3389} & ports
        if len(admin_ports) > 2:
            dangerous_findings.append(Finding(
                title="Multiple administrative services exposed",
                description=f"Multiple administrative services exposed: {admin_ports}",
                severity="high",
                confidence=0.9,
                url="",
                vulnerability_type="information_disclosure",
                evidence={
                    'admin_ports': list(admin_ports),
                    'risk': 'increased_attack_surface'
                }
            ))
        
        return dangerous_findings