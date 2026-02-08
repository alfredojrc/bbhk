"""Utility functions and helpers."""

import re
import random
import hashlib
import asyncio
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
import dns.resolver
from loguru import logger

def normalize_url(url: str) -> str:
    """Normalize URL for consistent handling."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    # Remove trailing slash and fragments
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    
    return normalized

def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc.lower()

def extract_subdomain(domain: str) -> str:
    """Extract subdomain from domain."""
    parts = domain.split('.')
    if len(parts) > 2:
        return parts[0]
    return ''

def is_subdomain(subdomain: str, parent_domain: str) -> bool:
    """Check if subdomain belongs to parent domain."""
    return subdomain.endswith('.' + parent_domain) or subdomain == parent_domain

def generate_user_agent() -> str:
    """Generate a random realistic user agent."""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
    ]
    return random.choice(user_agents)

def random_delay(min_delay: float = 1.0, max_delay: float = 3.0) -> float:
    """Generate random delay to mimic human behavior."""
    return random.uniform(min_delay, max_delay)

async def async_random_delay(min_delay: float = 1.0, max_delay: float = 3.0):
    """Async version of random delay."""
    delay = random_delay(min_delay, max_delay)
    await asyncio.sleep(delay)

def hash_string(text: str, algorithm: str = 'sha256') -> str:
    """Generate hash of string."""
    hasher = hashlib.new(algorithm)
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()

def validate_email(email: str) -> bool:
    """Validate email address format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_domain(domain: str) -> bool:
    """Validate domain name format."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    return re.match(pattern, domain) is not None

async def dns_lookup(domain: str, record_type: str = 'A') -> List[str]:
    """Perform DNS lookup for domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        answers = await asyncio.get_event_loop().run_in_executor(
            None, resolver.resolve, domain, record_type
        )
        
        return [str(rdata) for rdata in answers]
    except Exception as e:
        logger.debug(f"DNS lookup failed for {domain}: {e}")
        return []

def is_ip_address(address: str) -> bool:
    """Check if string is an IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def clean_html(html: str) -> str:
    """Clean HTML content to plain text."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    return soup.get_text(strip=True)

def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text to specified length."""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

def format_bytes(bytes_count: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} TB"

def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"

def parse_severity(severity_str: str) -> str:
    """Parse and normalize severity string."""
    severity_map = {
        'info': 'low',
        'informational': 'low',
        'low': 'low',
        'medium': 'medium',
        'mod': 'medium',
        'moderate': 'medium',
        'high': 'high',
        'critical': 'critical',
        'crit': 'critical'
    }
    
    normalized = severity_str.lower().strip()
    return severity_map.get(normalized, 'low')

def calculate_cvss_score(vector: str) -> float:
    """Calculate CVSS score from vector string."""
    # Simplified CVSS calculation
    # In production, use proper CVSS library
    base_scores = {
        'AV:N': 0.85, 'AV:A': 0.62, 'AV:L': 0.55, 'AV:P': 0.2,
        'AC:L': 0.77, 'AC:H': 0.44,
        'PR:N': 0.85, 'PR:L': 0.62, 'PR:H': 0.27,
        'UI:N': 0.85, 'UI:R': 0.62,
        'S:U': 0.0, 'S:C': 0.0,
        'C:H': 0.56, 'C:L': 0.22, 'C:N': 0.0,
        'I:H': 0.56, 'I:L': 0.22, 'I:N': 0.0,
        'A:H': 0.56, 'A:L': 0.22, 'A:N': 0.0
    }
    
    try:
        # Parse CVSS vector
        metrics = dict(metric.split(':') for metric in vector.split('/') if ':' in metric)
        
        # Calculate base score (simplified)
        exploitability = (
            base_scores.get(f"AV:{metrics.get('AV', 'L')}", 0.55) *
            base_scores.get(f"AC:{metrics.get('AC', 'L')}", 0.77) *
            base_scores.get(f"PR:{metrics.get('PR', 'N')}", 0.85) *
            base_scores.get(f"UI:{metrics.get('UI', 'N')}", 0.85)
        )
        
        impact = 1 - (
            (1 - base_scores.get(f"C:{metrics.get('C', 'N')}", 0.0)) *
            (1 - base_scores.get(f"I:{metrics.get('I', 'N')}", 0.0)) *
            (1 - base_scores.get(f"A:{metrics.get('A', 'N')}", 0.0))
        )
        
        if impact <= 0:
            return 0.0
            
        base_score = min(10.0, (impact + exploitability - 1.5) * 1.08)
        return max(0.0, round(base_score, 1))
        
    except Exception as e:
        logger.warning(f"Failed to calculate CVSS score for vector {vector}: {e}")
        return 0.0

class RateLimiter:
    """Simple rate limiter implementation."""
    
    def __init__(self, max_requests: int, time_window: int):
        """Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
    
    async def acquire(self) -> bool:
        """Acquire permission to make request."""
        now = datetime.now(timezone.utc)
        
        # Clean old requests
        cutoff = now.timestamp() - self.time_window
        self.requests = [req for req in self.requests if req > cutoff]
        
        # Check if we can make request
        if len(self.requests) >= self.max_requests:
            return False
        
        # Add current request
        self.requests.append(now.timestamp())
        return True
    
    def time_until_next_request(self) -> float:
        """Get time until next request is allowed."""
        if len(self.requests) < self.max_requests:
            return 0.0
        
        oldest_request = min(self.requests)
        return max(0.0, self.time_window - (datetime.now(timezone.utc).timestamp() - oldest_request))

def create_fingerprint(data: Dict[str, Any]) -> str:
    """Create unique fingerprint for data."""
    # Sort dictionary and create hash
    sorted_items = sorted(data.items())
    fingerprint_str = str(sorted_items)
    return hash_string(fingerprint_str)[:16]