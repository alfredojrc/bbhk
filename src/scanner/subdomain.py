"""Subdomain enumeration scanner."""

import asyncio
import json
from typing import List, Dict, Any, Set
from urllib.parse import urlparse
from loguru import logger

from .base import BaseScanner, ScanResult, Finding
from ..core.utils import dns_lookup, is_subdomain, validate_domain

class SubdomainScanner(BaseScanner):
    """Scanner for subdomain enumeration."""
    
    def __init__(self, program_id: int):
        """Initialize subdomain scanner."""
        super().__init__('subdomain_enum', program_id)
        
        # Wordlists for subdomain enumeration
        self.common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'admin', 'hosts', 'www2', 'ns', 'dns',
            'search', 'api', 'exchange', 'www1', 'portal', 'email', 'mailserver',
            'ftp', 'localhost', 'webdisk', 'www3', 'whois', 'monitoring',
            'test', 'beta', 'stage', 'staging', 'dev', 'development',
            'm', 'mobile', 'app', 'apps', 'support', 'help', 'docs',
            'cdn', 'assets', 'img', 'images', 'js', 'css', 'static',
            'shop', 'store', 'payment', 'pay', 'billing', 'invoice',
            'crm', 'erp', 'intranet', 'extranet', 'partner', 'partners',
            'git', 'svn', 'repo', 'repository', 'ci', 'jenkins', 'build'
        ]
        
        # Extended wordlist for thorough scans
        self.extended_subdomains = self.common_subdomains + [
            'autodiscover', 'autoconfig', 'lyncdiscover', 'sip', 'owa',
            'cpanel', 'whm', 'plesk', 'panel', 'manage', 'management',
            'backup', 'backups', 'old', 'archive', 'files', 'upload',
            'downloads', 'download', 'mirror', 'mirrors', 'updates',
            'v1', 'v2', 'v3', 'api1', 'api2', 'apitest', 'sandbox',
            'demo', 'example', 'sample', 'preview', 'tmp', 'temp',
            'cache', 'redis', 'db', 'database', 'mysql', 'postgres',
            'elasticsearch', 'kibana', 'grafana', 'prometheus', 'nagios',
            'zabbix', 'munin', 'cacti', 'icinga', 'sensu', 'datadog',
            'newrelic', 'pingdom', 'uptime', 'status', 'health'
        ]
    
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Perform subdomain enumeration scan."""
        start_time = time.time()
        findings = []
        
        try:
            # Parse target domain
            if target.startswith('http'):
                domain = urlparse(target).netloc
            else:
                domain = target.strip()
            
            if not validate_domain(domain):
                return ScanResult(
                    target=target,
                    scan_type=self.name,
                    success=False,
                    error="Invalid domain format",
                    duration=time.time() - start_time
                )
            
            logger.info(f"Starting subdomain enumeration for {domain}")
            
            # Determine scan intensity
            wordlist = self.extended_subdomains if kwargs.get('intensive', False) else self.common_subdomains
            
            # Perform enumeration using multiple techniques
            subdomains = set()
            
            # 1. Dictionary-based enumeration
            dict_results = await self._dictionary_enumeration(domain, wordlist)
            subdomains.update(dict_results)
            
            # 2. DNS zone transfer (passive)
            zone_results = await self._zone_transfer_check(domain)
            subdomains.update(zone_results)
            
            # 3. Certificate transparency logs
            ct_results = await self._certificate_transparency_search(domain)
            subdomains.update(ct_results)
            
            # 4. Search engine enumeration
            if kwargs.get('use_search_engines', True):
                search_results = await self._search_engine_enumeration(domain)
                subdomains.update(search_results)
            
            # Create findings for discovered subdomains
            for subdomain in sorted(subdomains):
                if subdomain != domain:  # Don't include the main domain
                    finding = Finding(
                        title=f"Subdomain discovered: {subdomain}",
                        description=f"Discovered subdomain {subdomain} of {domain}",
                        severity="info",
                        confidence=0.9,
                        url=f"https://{subdomain}",
                        vulnerability_type="information_disclosure",
                        evidence={
                            'subdomain': subdomain,
                            'parent_domain': domain,
                            'enumeration_methods': ['dictionary', 'ct_logs', 'dns']
                        }
                    )
                    findings.append(finding)
            
            logger.info(f"Subdomain enumeration completed: {len(findings)} subdomains found")
            
            return ScanResult(
                target=target,
                scan_type=self.name,
                findings=findings,
                metadata={
                    'parent_domain': domain,
                    'total_subdomains': len(findings),
                    'wordlist_size': len(wordlist)
                },
                success=True,
                duration=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {e}")
            return ScanResult(
                target=target,
                scan_type=self.name,
                success=False,
                error=str(e),
                duration=time.time() - start_time
            )
    
    async def _dictionary_enumeration(self, domain: str, wordlist: List[str]) -> Set[str]:
        """Perform dictionary-based subdomain enumeration."""
        discovered = set()
        
        async def check_subdomain(subdomain_name: str):
            """Check if a subdomain exists."""
            if not self.running:
                return
            
            subdomain = f"{subdomain_name}.{domain}"
            
            try:
                # DNS A record lookup
                a_records = await dns_lookup(subdomain, 'A')
                if a_records:
                    discovered.add(subdomain)
                    return
                
                # DNS CNAME record lookup
                cname_records = await dns_lookup(subdomain, 'CNAME')
                if cname_records:
                    discovered.add(subdomain)
                    return
                    
            except Exception as e:
                logger.debug(f"DNS lookup failed for {subdomain}: {e}")
            
            # Add small delay to be respectful
            await asyncio.sleep(0.1)
        
        # Process wordlist with limited concurrency
        semaphore = asyncio.Semaphore(10)  # Limit concurrent DNS queries
        
        async def check_with_semaphore(subdomain_name: str):
            async with semaphore:
                await check_subdomain(subdomain_name)
        
        tasks = [check_with_semaphore(sub) for sub in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"Dictionary enumeration found {len(discovered)} subdomains")
        return discovered
    
    async def _zone_transfer_check(self, domain: str) -> Set[str]:
        """Check for DNS zone transfers (AXFR)."""
        discovered = set()
        
        try:
            import dns.zone
            import dns.query
            import dns.resolver
            
            # Get authoritative name servers
            ns_records = await dns_lookup(domain, 'NS')
            
            for ns in ns_records:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
                    
                    # Extract subdomains from zone
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{domain}"
                        if validate_domain(subdomain) and is_subdomain(subdomain, domain):
                            discovered.add(subdomain)
                    
                    logger.warning(f"Zone transfer successful from {ns} - potential security issue")
                    break  # One successful zone transfer is enough
                    
                except Exception as e:
                    logger.debug(f"Zone transfer failed from {ns}: {e}")
            
        except ImportError:
            logger.debug("dnspython not available for zone transfer checks")
        except Exception as e:
            logger.debug(f"Zone transfer check failed: {e}")
        
        return discovered
    
    async def _certificate_transparency_search(self, domain: str) -> Set[str]:
        """Search certificate transparency logs for subdomains."""
        discovered = set()
        
        try:
            # Use crt.sh API
            crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            response = await self.make_request(crt_url)
            if response and response['status'] == 200:
                try:
                    ct_data = json.loads(response['data'])
                    
                    for cert in ct_data:
                        name_value = cert.get('name_value', '')
                        
                        # Parse certificate names
                        for name in name_value.split('\n'):
                            name = name.strip()
                            
                            # Skip wildcards and invalid names
                            if name.startswith('*'):
                                continue
                            
                            if validate_domain(name) and is_subdomain(name, domain):
                                discovered.add(name)
                
                except json.JSONDecodeError:
                    logger.debug("Failed to parse CT logs response")
            
        except Exception as e:
            logger.debug(f"Certificate transparency search failed: {e}")
        
        logger.info(f"Certificate transparency found {len(discovered)} subdomains")
        return discovered
    
    async def _search_engine_enumeration(self, domain: str) -> Set[str]:
        """Use search engines to find subdomains."""
        discovered = set()
        
        # This would implement search engine queries
        # For ethical reasons, we'll use a placeholder implementation
        
        search_queries = [
            f"site:*.{domain}",
            f"site:{domain} -www",
            f'inurl:"{domain}" -www'
        ]
        
        # In a real implementation, this would query search engines
        # with proper rate limiting and respect for robots.txt
        logger.debug(f"Search engine enumeration skipped for {domain} (placeholder)")
        
        return discovered