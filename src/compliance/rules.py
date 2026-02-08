"""Rule parsing and management for program compliance."""

import re
import json
import asyncio
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse
from loguru import logger

from ..core.database import Program, get_async_db
from ..core.utils import validate_domain, is_subdomain, dns_lookup

@dataclass
class ScopeRule:
    """Represents a scope rule."""
    rule_type: str  # 'domain', 'subdomain', 'url', 'ip', 'mobile_app', 'api'
    pattern: str
    includes_subdomains: bool = False
    port_restrictions: Optional[List[int]] = None
    path_restrictions: Optional[str] = None
    method_restrictions: Optional[List[str]] = None
    additional_notes: str = ""

@dataclass
class OutOfScopeRule:
    """Represents an out-of-scope rule."""
    rule_type: str
    pattern: str
    reason: str = ""
    severity: str = "critical"  # critical, high, medium, low

@dataclass
class RateLimit:
    """Rate limiting configuration."""
    requests_per_second: float = 1.0
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    concurrent_requests: int = 5
    respect_retry_after: bool = True

@dataclass
class ComplianceRules:
    """Complete compliance rules for a program."""
    program_id: int
    scope_rules: List[ScopeRule] = field(default_factory=list)
    out_of_scope_rules: List[OutOfScopeRule] = field(default_factory=list)
    rate_limits: RateLimit = field(default_factory=RateLimit)
    
    # Additional restrictions
    allowed_methods: Set[str] = field(default_factory=lambda: {'GET', 'POST', 'PUT', 'DELETE', 'PATCH'})
    blocked_paths: Set[str] = field(default_factory=lambda: {'/admin', '/wp-admin', '/.git'})
    require_authentication: bool = False
    respect_robots_txt: bool = True
    
    # Safety settings
    max_payload_size: int = 1024 * 1024  # 1MB
    timeout_seconds: int = 30
    max_redirects: int = 5

class RuleParser:
    """Parse program policies into structured rules."""
    
    def __init__(self):
        """Initialize rule parser."""
        self.domain_patterns = [
            r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            r'\*\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/?\*?'
        ]
        
        self.ip_patterns = [
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})'
        ]
        
        self.mobile_patterns = [
            r'(?:ios|android|mobile).+app',
            r'app.+(?:store|play)',
            r'(?:bundle|package).+(?:id|identifier)'
        ]
    
    async def parse_program_policy(self, program: Program) -> ComplianceRules:
        """Parse program policy into compliance rules."""
        rules = ComplianceRules(program_id=program.id)
        
        try:
            # Parse scope
            if program.scope:
                rules.scope_rules = await self._parse_scope_rules(program.scope)
            
            # Parse out of scope
            if program.out_of_scope:
                rules.out_of_scope_rules = await self._parse_out_of_scope_rules(program.out_of_scope)
            
            # Set platform-specific rate limits
            rules.rate_limits = self._get_platform_rate_limits(program.platform)
            
            # Parse additional restrictions from description
            if program.description:
                await self._parse_additional_restrictions(program.description, rules)
            
            logger.info(f"Parsed rules for {program.name}: "
                       f"{len(rules.scope_rules)} scope, "
                       f"{len(rules.out_of_scope_rules)} out-of-scope")
            
        except Exception as e:
            logger.error(f"Failed to parse rules for {program.name}: {e}")
        
        return rules
    
    async def _parse_scope_rules(self, scope_data: List[str]) -> List[ScopeRule]:
        """Parse scope rules from scope data."""
        scope_rules = []
        
        for item in scope_data:
            if isinstance(item, dict):
                # Structured scope data
                rule = await self._parse_structured_scope(item)
                if rule:
                    scope_rules.append(rule)
            else:
                # Text-based scope data
                parsed_rules = await self._parse_text_scope(str(item))
                scope_rules.extend(parsed_rules)
        
        return scope_rules
    
    async def _parse_structured_scope(self, scope_item: Dict[str, Any]) -> Optional[ScopeRule]:
        """Parse structured scope item."""
        try:
            asset_type = scope_item.get('asset_type', '').lower()
            identifier = scope_item.get('asset_identifier', '')
            instruction = scope_item.get('instruction', '')
            
            if not identifier:
                return None
            
            # Map asset types
            type_mapping = {
                'url': 'url',
                'domain': 'domain',
                'wildcard': 'subdomain',
                'ip_address': 'ip',
                'mobile_application': 'mobile_app',
                'api': 'api'
            }
            
            rule_type = type_mapping.get(asset_type, 'domain')
            
            # Check for subdomain inclusion
            includes_subdomains = ('*.' in identifier or 
                                 'subdomain' in instruction.lower() or
                                 'wildcard' in asset_type.lower())
            
            return ScopeRule(
                rule_type=rule_type,
                pattern=identifier,
                includes_subdomains=includes_subdomains,
                additional_notes=instruction
            )
            
        except Exception as e:
            logger.error(f"Failed to parse structured scope: {e}")
            return None
    
    async def _parse_text_scope(self, text: str) -> List[ScopeRule]:
        """Parse text-based scope description."""
        rules = []
        text = text.lower()
        
        try:
            # Find domains
            for pattern in self.domain_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    if validate_domain(match):
                        includes_subdomains = '*.' in text or 'subdomain' in text
                        rules.append(ScopeRule(
                            rule_type='subdomain' if includes_subdomains else 'domain',
                            pattern=match,
                            includes_subdomains=includes_subdomains
                        ))
            
            # Find IP addresses
            for pattern in self.ip_patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    rules.append(ScopeRule(
                        rule_type='ip',
                        pattern=match
                    ))
            
            # Find mobile apps
            for pattern in self.mobile_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    rules.append(ScopeRule(
                        rule_type='mobile_app',
                        pattern=text[:100],  # Truncate long text
                        additional_notes=text
                    ))
            
            # Find APIs
            if any(keyword in text for keyword in ['api', 'graphql', 'rest', 'endpoint']):
                api_urls = re.findall(r'https?://[^\s]+(?:api|graphql)', text, re.IGNORECASE)
                for url in api_urls:
                    rules.append(ScopeRule(
                        rule_type='api',
                        pattern=url
                    ))
            
        except Exception as e:
            logger.error(f"Failed to parse text scope: {e}")
        
        return rules
    
    async def _parse_out_of_scope_rules(self, out_of_scope_data: List[str]) -> List[OutOfScopeRule]:
        """Parse out-of-scope rules."""
        oos_rules = []
        
        for item in out_of_scope_data:
            if isinstance(item, dict):
                rule = await self._parse_structured_out_of_scope(item)
                if rule:
                    oos_rules.append(rule)
            else:
                parsed_rules = await self._parse_text_out_of_scope(str(item))
                oos_rules.extend(parsed_rules)
        
        return oos_rules
    
    async def _parse_structured_out_of_scope(self, oos_item: Dict[str, Any]) -> Optional[OutOfScopeRule]:
        """Parse structured out-of-scope item."""
        try:
            identifier = oos_item.get('asset_identifier', '')
            instruction = oos_item.get('instruction', '')
            
            if not identifier:
                return None
            
            return OutOfScopeRule(
                rule_type='domain',
                pattern=identifier,
                reason=instruction,
                severity='critical'
            )
            
        except Exception as e:
            logger.error(f"Failed to parse structured out-of-scope: {e}")
            return None
    
    async def _parse_text_out_of_scope(self, text: str) -> List[OutOfScopeRule]:
        """Parse text-based out-of-scope description."""
        rules = []
        
        try:
            # Common out-of-scope patterns
            critical_patterns = [
                r'(?:no|don\'t|do not).+(?:test|attack|scan)',
                r'(?:production|live|prod).+(?:system|environment|server)',
                r'(?:user|customer|client).+(?:data|information|privacy)',
                r'(?:denial.+service|dos|ddos)',
                r'(?:social.+engineering|phishing|spam)'
            ]
            
            for pattern in critical_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    rules.append(OutOfScopeRule(
                        rule_type='restriction',
                        pattern=pattern,
                        reason=text[:200],
                        severity='critical'
                    ))
            
            # Find specific domains/IPs to exclude
            for pattern in self.domain_patterns + self.ip_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    rules.append(OutOfScopeRule(
                        rule_type='domain',
                        pattern=match,
                        reason=text[:100],
                        severity='high'
                    ))
                    
        except Exception as e:
            logger.error(f"Failed to parse text out-of-scope: {e}")
        
        return rules
    
    def _get_platform_rate_limits(self, platform: str) -> RateLimit:
        """Get platform-specific rate limits."""
        platform_limits = {
            'hackerone': RateLimit(
                requests_per_second=0.5,
                requests_per_minute=30,
                requests_per_hour=500,
                concurrent_requests=3
            ),
            'bugcrowd': RateLimit(
                requests_per_second=0.3,
                requests_per_minute=20,
                requests_per_hour=300,
                concurrent_requests=2
            ),
            'intigriti': RateLimit(
                requests_per_second=0.5,
                requests_per_minute=25,
                requests_per_hour=400,
                concurrent_requests=3
            )
        }
        
        return platform_limits.get(platform, RateLimit())
    
    async def _parse_additional_restrictions(self, description: str, rules: ComplianceRules):
        """Parse additional restrictions from program description."""
        description = description.lower()
        
        # Check for method restrictions
        if 'get only' in description or 'read only' in description:
            rules.allowed_methods = {'GET'}
        elif 'no post' in description:
            rules.allowed_methods.discard('POST')
        
        # Check for authentication requirements
        if any(keyword in description for keyword in ['login', 'authenticate', 'credential']):
            rules.require_authentication = True
        
        # Check for special paths to avoid
        dangerous_paths = ['admin', 'test', 'dev', 'stage', 'internal']
        for path in dangerous_paths:
            if path in description:
                rules.blocked_paths.add(f'/{path}')

class ScopeValidator:
    """Validate targets against program scope rules."""
    
    def __init__(self, rules: ComplianceRules):
        """Initialize scope validator."""
        self.rules = rules
    
    async def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """Check if target is in scope.
        
        Returns:
            Tuple of (is_valid, reason)
        """
        try:
            # First check out-of-scope rules (blocklist)
            is_blocked, block_reason = await self._check_out_of_scope(target)
            if is_blocked:
                return False, f"Out of scope: {block_reason}"
            
            # Then check scope rules (allowlist)
            is_allowed, allow_reason = await self._check_in_scope(target)
            if not is_allowed:
                return False, f"Not in scope: {allow_reason}"
            
            return True, "In scope"
            
        except Exception as e:
            logger.error(f"Failed to validate scope for {target}: {e}")
            return False, f"Validation error: {e}"
    
    async def _check_out_of_scope(self, target: str) -> Tuple[bool, str]:
        """Check if target is explicitly out of scope."""
        for rule in self.rules.out_of_scope_rules:
            if await self._matches_rule(target, rule.pattern, rule.rule_type):
                return True, rule.reason or "Explicitly excluded"
        
        return False, ""
    
    async def _check_in_scope(self, target: str) -> Tuple[bool, str]:
        """Check if target is in scope."""
        if not self.rules.scope_rules:
            return False, "No scope rules defined"
        
        parsed_target = urlparse(target if target.startswith('http') else f'https://{target}')
        target_domain = parsed_target.netloc or target
        
        for rule in self.rules.scope_rules:
            if await self._matches_scope_rule(target, target_domain, rule):
                return True, f"Matches {rule.rule_type} rule: {rule.pattern}"
        
        return False, "No matching scope rules"
    
    async def _matches_scope_rule(self, target: str, target_domain: str, rule: ScopeRule) -> bool:
        """Check if target matches a scope rule."""
        try:
            if rule.rule_type == 'domain':
                return target_domain == rule.pattern
            
            elif rule.rule_type == 'subdomain':
                return (target_domain == rule.pattern or 
                       is_subdomain(target_domain, rule.pattern))
            
            elif rule.rule_type == 'url':
                return target.startswith(rule.pattern)
            
            elif rule.rule_type == 'ip':
                # Resolve domain to IP if needed
                if not target_domain.replace('.', '').isdigit():
                    ips = await dns_lookup(target_domain)
                    return any(ip in rule.pattern for ip in ips)
                else:
                    return target_domain in rule.pattern
            
            elif rule.rule_type == 'api':
                return 'api' in target.lower() and target.startswith(rule.pattern.split('/')[0])
            
        except Exception as e:
            logger.error(f"Failed to match rule {rule.pattern}: {e}")
        
        return False
    
    async def _matches_rule(self, target: str, pattern: str, rule_type: str) -> bool:
        """Check if target matches a generic rule pattern."""
        try:
            if rule_type == 'domain':
                target_domain = urlparse(target if target.startswith('http') else f'https://{target}').netloc
                return target_domain == pattern or is_subdomain(target_domain, pattern)
            
            elif rule_type == 'restriction':
                # Pattern matching for text restrictions
                return re.search(pattern, target, re.IGNORECASE) is not None
            
            else:
                return pattern.lower() in target.lower()
                
        except Exception as e:
            logger.error(f"Failed to match pattern {pattern}: {e}")
            return False
    
    def get_allowed_methods(self, target: str) -> Set[str]:
        """Get allowed HTTP methods for target."""
        return self.rules.allowed_methods.copy()
    
    def is_path_blocked(self, path: str) -> bool:
        """Check if path is blocked."""
        return any(blocked in path.lower() for blocked in self.rules.blocked_paths)
    
    def get_rate_limits(self) -> RateLimit:
        """Get rate limits for the program."""
        return self.rules.rate_limits