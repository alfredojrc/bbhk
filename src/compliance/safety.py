"""Safety monitoring and emergency controls."""

import asyncio
import re
import time
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict, deque
from urllib.parse import urlparse
from loguru import logger

from ..core.config import config

@dataclass
class SafetyRule:
    """Safety rule definition."""
    name: str
    pattern: str
    rule_type: str  # 'url', 'payload', 'header', 'method'
    severity: str  # 'critical', 'high', 'medium', 'low'
    action: str  # 'block', 'warn', 'monitor'
    description: str = ""

@dataclass
class SafetyViolation:
    """Safety violation record."""
    timestamp: float
    rule_name: str
    target: str
    action: str
    severity: str
    details: str = ""

class SafetyMonitor:
    """Monitor for safety violations and dangerous patterns."""
    
    def __init__(self):
        """Initialize safety monitor."""
        self.safety_rules = self._load_default_rules()
        self.violations: deque = deque(maxlen=10000)  # Keep last 10k violations
        self.blocked_patterns: Set[str] = set()
        self.suspicious_targets: Dict[str, int] = defaultdict(int)
        
        # Automatic emergency triggers
        self.max_violations_per_minute = 10
        self.max_violations_per_hour = 100
        self.emergency_threshold = 5  # Critical violations before emergency
        
        self._lock = asyncio.Lock()
    
    def _load_default_rules(self) -> List[SafetyRule]:
        """Load default safety rules."""
        return [
            # Critical rules - immediate blocking
            SafetyRule(
                name="sql_injection_attempt",
                pattern=r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into|update\s+.+set)",
                rule_type="payload",
                severity="critical",
                action="block",
                description="Detected SQL injection attempt"
            ),
            SafetyRule(
                name="xss_payload",
                pattern=r"(?i)(<script|javascript:|on\w+\s*=|<iframe|<object)",
                rule_type="payload",
                severity="critical", 
                action="block",
                description="Detected XSS payload"
            ),
            SafetyRule(
                name="command_injection",
                pattern=r"(?i)(;|&&|\||`|\$\(|wget\s+|curl\s+|nc\s+|bash\s+|sh\s+)",
                rule_type="payload",
                severity="critical",
                action="block",
                description="Detected command injection attempt"
            ),
            SafetyRule(
                name="directory_traversal",
                pattern=r"(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)",
                rule_type="payload",
                severity="high",
                action="block",
                description="Detected directory traversal attempt"
            ),
            SafetyRule(
                name="sensitive_files",
                pattern=r"(?i)(\/etc\/passwd|\/etc\/shadow|web\.config|\.env|\.git\/config|database\.yml)",
                rule_type="url",
                severity="high",
                action="block",
                description="Attempted access to sensitive files"
            ),
            
            # High severity rules
            SafetyRule(
                name="admin_paths",
                pattern=r"(?i)(\/admin|\/wp-admin|\/administrator|\/manager|\/control)",
                rule_type="url", 
                severity="high",
                action="warn",
                description="Access to admin paths"
            ),
            SafetyRule(
                name="backup_files",
                pattern=r"(?i)\.(bak|backup|old|orig|tmp|~)$",
                rule_type="url",
                severity="medium",
                action="warn", 
                description="Access to backup files"
            ),
            SafetyRule(
                name="test_environments",
                pattern=r"(?i)(test|dev|stage|staging|beta|demo)[\.-]",
                rule_type="url",
                severity="medium",
                action="warn",
                description="Access to test environments"
            ),
            
            # Production safety rules
            SafetyRule(
                name="production_domains",
                pattern=r"(?i)(prod|production|live)[\.-]",
                rule_type="url",
                severity="critical",
                action="block",
                description="Attempted access to production systems"
            ),
            SafetyRule(
                name="destructive_methods",
                pattern=r"(?i)(DELETE|PURGE)",
                rule_type="method",
                severity="high",
                action="warn",
                description="Using destructive HTTP methods"
            ),
            
            # Data exfiltration prevention
            SafetyRule(
                name="data_keywords",
                pattern=r"(?i)(password|credit.?card|ssn|social.?security|api.?key|secret|token)",
                rule_type="payload",
                severity="high",
                action="warn",
                description="Payload contains sensitive data keywords"
            ),
        ]
    
    async def check_safety(self, action: str, target: str, **kwargs) -> Dict[str, Any]:
        """Check if action is safe to perform."""
        result = {
            'safe': True,
            'violations': [],
            'warnings': [],
            'reasons': []
        }
        
        async with self._lock:
            current_time = time.time()
            
            # Check each safety rule
            for rule in self.safety_rules:
                violation = await self._check_rule(rule, action, target, **kwargs)
                if violation:
                    # Record violation
                    self.violations.append(SafetyViolation(
                        timestamp=current_time,
                        rule_name=rule.name,
                        target=target,
                        action=action,
                        severity=rule.severity,
                        details=violation
                    ))
                    
                    # Handle violation based on action
                    if rule.action == 'block':
                        result['safe'] = False
                        result['violations'].append(f"{rule.description}: {violation}")
                        result['reasons'].append(rule.description)
                    elif rule.action == 'warn':
                        result['warnings'].append(f"{rule.description}: {violation}")
                    
                    logger.warning(f"Safety rule triggered: {rule.name} for {target}")
            
            # Check for emergency conditions
            emergency = await self._check_emergency_conditions(current_time)
            if emergency:
                result['safe'] = False
                result['violations'].extend(emergency)
            
            # Track suspicious targets
            if not result['safe']:
                self.suspicious_targets[target] += 1
                if self.suspicious_targets[target] > 5:
                    result['violations'].append(f"Target flagged as suspicious: {target}")
        
        return result
    
    async def _check_rule(self, rule: SafetyRule, action: str, target: str, **kwargs) -> Optional[str]:
        """Check a specific safety rule."""
        try:
            if rule.rule_type == 'url':
                if re.search(rule.pattern, target):
                    return f"URL matches dangerous pattern: {rule.pattern}"
            
            elif rule.rule_type == 'payload':
                # Check various payload sources
                for key in ['data', 'payload', 'body', 'params']:
                    if key in kwargs and kwargs[key]:
                        payload_str = str(kwargs[key])
                        if re.search(rule.pattern, payload_str):
                            return f"Payload contains dangerous pattern: {rule.pattern}"
            
            elif rule.rule_type == 'header':
                headers = kwargs.get('headers', {})
                for header_value in headers.values():
                    if re.search(rule.pattern, str(header_value)):
                        return f"Header contains dangerous pattern: {rule.pattern}"
            
            elif rule.rule_type == 'method':
                method = kwargs.get('method', action).upper()
                if re.search(rule.pattern, method):
                    return f"Method matches dangerous pattern: {rule.pattern}"
            
        except Exception as e:
            logger.error(f"Error checking safety rule {rule.name}: {e}")
        
        return None
    
    async def _check_emergency_conditions(self, current_time: float) -> List[str]:
        """Check for conditions that should trigger emergency stop."""
        emergencies = []
        
        # Check violation rate
        recent_violations = [v for v in self.violations 
                           if current_time - v.timestamp < 60]  # Last minute
        
        if len(recent_violations) > self.max_violations_per_minute:
            emergencies.append(f"Too many violations per minute: {len(recent_violations)}")
        
        # Check critical violations
        recent_critical = [v for v in recent_violations if v.severity == 'critical']
        if len(recent_critical) >= self.emergency_threshold:
            emergencies.append(f"Too many critical violations: {len(recent_critical)}")
        
        # Check for repeated violations on same target
        target_violations = defaultdict(int)
        for violation in recent_violations:
            target_violations[violation.target] += 1
        
        for target, count in target_violations.items():
            if count > 3:  # More than 3 violations per minute on same target
                emergencies.append(f"Repeated violations on target: {target} ({count} violations)")
        
        return emergencies
    
    async def add_safety_rule(self, rule: SafetyRule):
        """Add a custom safety rule."""
        async with self._lock:
            self.safety_rules.append(rule)
            logger.info(f"Added safety rule: {rule.name}")
    
    async def remove_safety_rule(self, rule_name: str) -> bool:
        """Remove a safety rule."""
        async with self._lock:
            for i, rule in enumerate(self.safety_rules):
                if rule.name == rule_name:
                    del self.safety_rules[i]
                    logger.info(f"Removed safety rule: {rule_name}")
                    return True
            return False
    
    async def block_pattern(self, pattern: str, reason: str):
        """Block a specific pattern."""
        async with self._lock:
            self.blocked_patterns.add(pattern)
            logger.warning(f"Blocked pattern: {pattern} - {reason}")
    
    async def unblock_pattern(self, pattern: str):
        """Unblock a pattern."""
        async with self._lock:
            self.blocked_patterns.discard(pattern)
            logger.info(f"Unblocked pattern: {pattern}")
    
    async def get_status(self) -> Dict[str, Any]:
        """Get current safety monitor status."""
        async with self._lock:
            current_time = time.time()
            
            # Recent violations
            recent_violations = [v for v in self.violations 
                               if current_time - v.timestamp < 3600]  # Last hour
            
            # Violation counts by severity
            severity_counts = defaultdict(int)
            for violation in recent_violations:
                severity_counts[violation.severity] += 1
            
            # Most violated rules
            rule_counts = defaultdict(int)
            for violation in recent_violations:
                rule_counts[violation.rule_name] += 1
            
            return {
                'total_rules': len(self.safety_rules),
                'blocked_patterns': len(self.blocked_patterns),
                'violations_last_hour': len(recent_violations),
                'violations_by_severity': dict(severity_counts),
                'most_violated_rules': dict(sorted(rule_counts.items(), 
                                                 key=lambda x: x[1], reverse=True)[:5]),
                'suspicious_targets': dict(sorted(self.suspicious_targets.items(),
                                                key=lambda x: x[1], reverse=True)[:10]),
                'emergency_threshold': self.emergency_threshold,
                'max_violations_per_minute': self.max_violations_per_minute
            }
    
    async def get_violation_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get violation history for analysis."""
        async with self._lock:
            current_time = time.time()
            cutoff_time = current_time - (hours * 3600)
            
            recent_violations = [v for v in self.violations 
                               if v.timestamp >= cutoff_time]
            
            return [
                {
                    'timestamp': v.timestamp,
                    'rule_name': v.rule_name,
                    'target': v.target,
                    'action': v.action,
                    'severity': v.severity,
                    'details': v.details
                }
                for v in recent_violations
            ]
    
    async def reset_suspicious_targets(self):
        """Reset suspicious target tracking."""
        async with self._lock:
            self.suspicious_targets.clear()
            logger.info("Reset suspicious target tracking")
    
    async def cleanup(self):
        """Clean up safety monitor resources."""
        async with self._lock:
            self.violations.clear()
            self.blocked_patterns.clear()
            self.suspicious_targets.clear()
            logger.debug("Safety monitor cleaned up")