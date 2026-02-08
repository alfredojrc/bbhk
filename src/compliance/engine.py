"""Main compliance engine for coordinating all compliance checks."""

import asyncio
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
from loguru import logger

from .rules import RuleParser, ComplianceRules, ScopeValidator, RateLimit
from .limiter import ComplianceRateLimiter
from .safety import SafetyMonitor
from ..core.database import Program, AuditLog, get_async_db
from ..core.config import config
from ..core.logger import get_audit_logger

class ComplianceEngine:
    """Main compliance engine that coordinates all compliance checks."""
    
    def __init__(self):
        """Initialize compliance engine."""
        self.rule_parser = RuleParser()
        self.program_rules: Dict[int, ComplianceRules] = {}
        self.scope_validators: Dict[int, ScopeValidator] = {}
        self.rate_limiters: Dict[int, ComplianceRateLimiter] = {}
        self.safety_monitor = SafetyMonitor()
        self.kill_switch_active = False
        
    async def initialize_program(self, program_id: int) -> bool:
        """Initialize compliance rules for a program."""
        try:
            async with get_async_db() as db:
                program = await db.get(Program, program_id)
                if not program:
                    logger.error(f"Program {program_id} not found")
                    return False
                
                # Parse compliance rules
                rules = await self.rule_parser.parse_program_policy(program)
                self.program_rules[program_id] = rules
                
                # Create scope validator
                self.scope_validators[program_id] = ScopeValidator(rules)
                
                # Create rate limiter
                self.rate_limiters[program_id] = ComplianceRateLimiter(rules.rate_limits)
                
                logger.info(f"Initialized compliance for program: {program.name}")
                
                # Log compliance initialization
                audit_logger = get_audit_logger()
                audit_logger.info(f"Compliance initialized for {program.name}",
                                 action="compliance_init",
                                 resource="program",
                                 resource_id=program_id)
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to initialize compliance for program {program_id}: {e}")
            return False
    
    async def check_compliance(self, program_id: int, action: str, target: str, 
                              method: str = 'GET', **kwargs) -> Dict[str, Any]:
        """Comprehensive compliance check for an action."""
        compliance_result = {
            'compliant': False,
            'violations': [],
            'warnings': [],
            'allowed': False,
            'rate_limited': False,
            'safety_blocked': False
        }
        
        try:
            # Check if kill switch is active
            if self.kill_switch_active:
                compliance_result['violations'].append('Kill switch is active')
                return compliance_result
            
            # Check if program is initialized
            if program_id not in self.program_rules:
                await self.initialize_program(program_id)
            
            rules = self.program_rules.get(program_id)
            validator = self.scope_validators.get(program_id)
            rate_limiter = self.rate_limiters.get(program_id)
            
            if not all([rules, validator, rate_limiter]):
                compliance_result['violations'].append('Program compliance not properly initialized')
                return compliance_result
            
            # 1. Scope validation
            is_in_scope, scope_reason = await validator.is_in_scope(target)
            if not is_in_scope:
                compliance_result['violations'].append(f'Scope violation: {scope_reason}')
            
            # 2. Method validation
            allowed_methods = validator.get_allowed_methods(target)
            if method.upper() not in allowed_methods:
                compliance_result['violations'].append(f'Method {method} not allowed')
            
            # 3. Path validation
            if 'path' in kwargs:
                if validator.is_path_blocked(kwargs['path']):
                    compliance_result['violations'].append(f'Blocked path: {kwargs["path"]}')
            
            # 4. Rate limiting
            can_proceed = await rate_limiter.can_make_request(action, target)
            if not can_proceed:
                compliance_result['rate_limited'] = True
                compliance_result['violations'].append('Rate limit exceeded')
            
            # 5. Safety monitoring
            safety_check = await self.safety_monitor.check_safety(action, target, **kwargs)
            if not safety_check['safe']:
                compliance_result['safety_blocked'] = True
                compliance_result['violations'].extend(safety_check['reasons'])
            
            # 6. Payload size check
            if 'data' in kwargs and kwargs['data']:
                data_size = len(str(kwargs['data']).encode('utf-8'))
                if data_size > rules.max_payload_size:
                    compliance_result['violations'].append(f'Payload too large: {data_size} > {rules.max_payload_size}')
            
            # 7. Robots.txt compliance (if enabled)
            if rules.respect_robots_txt and config.compliance.respect_robots_txt:
                robots_ok = await self._check_robots_txt(target, kwargs.get('path', '/'))
                if not robots_ok:
                    compliance_result['warnings'].append('Path may be disallowed by robots.txt')
            
            # Determine overall compliance
            compliance_result['compliant'] = len(compliance_result['violations']) == 0
            compliance_result['allowed'] = compliance_result['compliant'] and not compliance_result['rate_limited']
            
            # Log compliance check
            await self._log_compliance_check(program_id, action, target, compliance_result)
            
        except Exception as e:
            logger.error(f"Compliance check failed: {e}")
            compliance_result['violations'].append(f'Compliance check error: {e}')
        
        return compliance_result
    
    async def activate_kill_switch(self, reason: str):
        """Activate emergency kill switch."""
        self.kill_switch_active = True
        logger.critical(f"KILL SWITCH ACTIVATED: {reason}")
        
        # Log kill switch activation
        audit_logger = get_audit_logger()
        audit_logger.critical(f"Kill switch activated: {reason}",
                             action="kill_switch_activated",
                             resource="system")
        
        # Stop all active operations
        for rate_limiter in self.rate_limiters.values():
            await rate_limiter.pause_all()
        
        # Send emergency notifications
        await self._send_emergency_notification(reason)
    
    async def deactivate_kill_switch(self, reason: str):
        """Deactivate kill switch."""
        self.kill_switch_active = False
        logger.warning(f"Kill switch deactivated: {reason}")
        
        # Log kill switch deactivation
        audit_logger = get_audit_logger()
        audit_logger.warning(f"Kill switch deactivated: {reason}",
                            action="kill_switch_deactivated",
                            resource="system")
        
        # Resume operations
        for rate_limiter in self.rate_limiters.values():
            await rate_limiter.resume_all()
    
    async def get_compliance_status(self, program_id: int) -> Dict[str, Any]:
        """Get compliance status for a program."""
        if program_id not in self.program_rules:
            return {'error': 'Program not initialized'}
        
        rules = self.program_rules[program_id]
        rate_limiter = self.rate_limiters[program_id]
        
        return {
            'program_id': program_id,
            'kill_switch_active': self.kill_switch_active,
            'scope_rules_count': len(rules.scope_rules),
            'out_of_scope_rules_count': len(rules.out_of_scope_rules),
            'rate_limits': {
                'requests_per_second': rules.rate_limits.requests_per_second,
                'requests_per_minute': rules.rate_limits.requests_per_minute,
                'concurrent_requests': rules.rate_limits.concurrent_requests
            },
            'current_usage': await rate_limiter.get_current_usage(),
            'safety_status': await self.safety_monitor.get_status()
        }
    
    async def update_program_rules(self, program_id: int) -> bool:
        """Update rules for a program (e.g., after policy changes)."""
        try:
            # Remove existing rules
            if program_id in self.program_rules:
                del self.program_rules[program_id]
                del self.scope_validators[program_id]
                await self.rate_limiters[program_id].cleanup()
                del self.rate_limiters[program_id]
            
            # Re-initialize
            return await self.initialize_program(program_id)
            
        except Exception as e:
            logger.error(f"Failed to update rules for program {program_id}: {e}")
            return False
    
    async def _check_robots_txt(self, target: str, path: str) -> bool:
        """Check robots.txt compliance."""
        try:
            from urllib.robotparser import RobotFileParser
            
            # Parse domain from target
            from urllib.parse import urlparse
            parsed = urlparse(target if target.startswith('http') else f'https://{target}')
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            # Simple check - in production, would implement more robust robots.txt parsing
            rp = RobotFileParser()
            rp.set_url(robots_url)
            
            # Use a timeout to avoid hanging
            try:
                rp.read()
                return rp.can_fetch('*', path)
            except (OSError, UnicodeDecodeError):
                # If robots.txt is not accessible, assume it's OK
                return True
                
        except Exception as e:
            logger.debug(f"Robots.txt check failed for {target}: {e}")
            return True  # Default to allowing if check fails
    
    async def _log_compliance_check(self, program_id: int, action: str, target: str, result: Dict[str, Any]):
        """Log compliance check to audit trail."""
        try:
            async with get_async_db() as db:
                audit_log = AuditLog(
                    action='compliance_check',
                    resource_type='target',
                    resource_id=program_id,
                    target_url=target,
                    metadata={
                        'action': action,
                        'compliant': result['compliant'],
                        'violations': result['violations'],
                        'warnings': result['warnings']
                    },
                    compliant=result['compliant'],
                    compliance_notes='; '.join(result['violations']) if result['violations'] else 'OK',
                    timestamp=datetime.now(timezone.utc)
                )
                db.add(audit_log)
                await db.commit()
                
        except Exception as e:
            logger.error(f"Failed to log compliance check: {e}")
    
    async def _send_emergency_notification(self, reason: str):
        """Send emergency notification when kill switch is activated."""
        notification_message = f"""
        🚨 EMERGENCY: Kill Switch Activated 🚨
        
        Reason: {reason}
        Time: {datetime.now(timezone.utc).isoformat()}
        
        All bug bounty activities have been suspended immediately.
        Manual intervention required to resume operations.
        """
        
        logger.critical(notification_message)
        
        # In production, this would send actual notifications
        # await self._send_slack_alert(notification_message)
        # await self._send_email_alert(notification_message)
        # await self._call_emergency_contact()
    
    async def cleanup(self):
        """Clean up compliance engine resources."""
        for rate_limiter in self.rate_limiters.values():
            await rate_limiter.cleanup()
        
        await self.safety_monitor.cleanup()

# Global compliance engine instance
compliance_engine = ComplianceEngine()