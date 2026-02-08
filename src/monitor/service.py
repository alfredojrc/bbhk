"""Main monitoring service that coordinates all platform monitors."""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from loguru import logger

from .hackerone import HackerOneMonitor
from .bugcrowd import BugcrowdMonitor
from ..core.config import config
from ..core.database import get_async_db, Program, AuditLog
from ..core.logger import get_audit_logger

class MonitoringService:
    """Main service that coordinates all platform monitoring."""
    
    def __init__(self):
        """Initialize monitoring service."""
        self.monitors = {}
        self.running = False
        self.tasks = []
        
        # Initialize platform monitors based on config
        if config.monitor.hackerone_enabled:
            self.monitors['hackerone'] = HackerOneMonitor()
        
        if config.monitor.bugcrowd_enabled:
            self.monitors['bugcrowd'] = BugcrowdMonitor()
    
    async def start(self):
        """Start all monitoring services."""
        if self.running:
            logger.warning("Monitoring service is already running")
            return
        
        self.running = True
        logger.info("Starting bug bounty program monitoring service")
        
        # Start each monitor
        for platform, monitor in self.monitors.items():
            task = asyncio.create_task(
                monitor.start_monitoring(config.monitor.check_interval)
            )
            self.tasks.append(task)
            logger.info(f"Started {platform} monitor")
        
        # Start news monitoring
        news_task = asyncio.create_task(self._monitor_news())
        self.tasks.append(news_task)
        
        # Start update alerts
        alert_task = asyncio.create_task(self._monitor_updates())
        self.tasks.append(alert_task)
        
        # Log service start
        audit_logger = get_audit_logger()
        audit_logger.info("Monitoring service started", 
                         action="service_start", 
                         resource="monitoring_service")
    
    async def stop(self):
        """Stop all monitoring services."""
        if not self.running:
            return
        
        self.running = False
        logger.info("Stopping monitoring service")
        
        # Stop all monitors
        for monitor in self.monitors.values():
            await monitor.stop_monitoring()
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        
        self.tasks.clear()
        
        # Log service stop
        audit_logger = get_audit_logger()
        audit_logger.info("Monitoring service stopped", 
                         action="service_stop", 
                         resource="monitoring_service")
    
    async def force_update_all(self):
        """Force immediate update of all programs."""
        logger.info("Forcing update of all programs")
        
        for platform, monitor in self.monitors.items():
            try:
                await monitor._monitor_cycle()
                logger.info(f"Forced update completed for {platform}")
            except Exception as e:
                logger.error(f"Failed to force update {platform}: {e}")
    
    async def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        async with get_async_db() as db:
            # Get program counts by platform
            program_counts = {}
            for platform in self.monitors.keys():
                count = await db.query(Program).filter(
                    Program.platform == platform
                ).count()
                program_counts[platform] = count
            
            # Get recent activity
            recent_programs = await db.query(Program).filter(
                Program.discovered_at >= datetime.now(timezone.utc).replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
            ).count()
            
            return {
                'running': self.running,
                'monitors': list(self.monitors.keys()),
                'program_counts': program_counts,
                'programs_discovered_today': recent_programs,
                'check_interval': config.monitor.check_interval
            }
    
    async def _monitor_news(self):
        """Monitor news sources for program announcements."""
        while self.running:
            try:
                await self._check_acquisition_news()
                await asyncio.sleep(3600)  # Check hourly
            except Exception as e:
                logger.error(f"News monitoring failed: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
    
    async def _check_acquisition_news(self):
        """Check for acquisition news that might affect programs."""
        # This would implement RSS/news API monitoring
        # for now, it's a placeholder
        logger.debug("Checking acquisition news")
        
        # Example sources to monitor:
        # - Security news sites
        # - Company blogs
        # - Press release feeds
        # - Social media APIs
        
        # Placeholder implementation
        news_sources = [
            'https://feeds.feedburner.com/oreilly/radar',
            'https://threatpost.com/feed/',
            'https://krebsonsecurity.com/feed/'
        ]
        
        for source in news_sources:
            try:
                # Would implement RSS parsing here
                pass
            except Exception as e:
                logger.debug(f"Failed to check news source {source}: {e}")
    
    async def _monitor_updates(self):
        """Monitor for program updates and send alerts."""
        while self.running:
            try:
                await self._check_program_updates()
                await asyncio.sleep(1800)  # Check every 30 minutes
            except Exception as e:
                logger.error(f"Update monitoring failed: {e}")
                await asyncio.sleep(300)
    
    async def _check_program_updates(self):
        """Check existing programs for updates."""
        async with get_async_db() as db:
            # Get programs to check (limit to avoid overload)
            programs = await db.query(Program).filter(
                Program.status == 'active'
            ).limit(50).all()
            
            for program in programs:
                try:
                    monitor = self.monitors.get(program.platform)
                    if not monitor:
                        continue
                    
                    updates = await monitor.check_program_updates(program)
                    if updates:
                        await self._handle_program_update(program, updates)
                        
                    # Update last checked time
                    program.last_checked = datetime.now(timezone.utc)
                    await db.commit()
                    
                    # Respectful delay between checks
                    await asyncio.sleep(2)
                    
                except Exception as e:
                    logger.error(f"Failed to check updates for {program.name}: {e}")
    
    async def _handle_program_update(self, program: Program, updates: Dict[str, Any]):
        """Handle detected program updates."""
        logger.info(f"Program update detected for {program.name}: {updates}")
        
        # Log to audit trail
        async with get_async_db() as db:
            audit_log = AuditLog(
                action='program_update_detected',
                resource_type='program',
                resource_id=program.id,
                before_state={'max_bounty': program.max_bounty, 'status': program.status},
                after_state=updates,
                metadata={'platform': program.platform},
                timestamp=datetime.now(timezone.utc)
            )
            db.add(audit_log)
            await db.commit()
        
        # Send notifications (placeholder)
        await self._send_update_notification(program, updates)
    
    async def _send_update_notification(self, program: Program, updates: Dict[str, Any]):
        """Send notification about program update."""
        # This would implement actual notification sending
        # Could use email, Slack, Discord, webhooks, etc.
        
        notification_text = f"Program Update: {program.name}\n"
        
        for update_type, change in updates.items():
            if update_type == 'max_bounty':
                notification_text += f"- Max bounty changed: ${change['old']} -> ${change['new']}\n"
            elif update_type == 'status':
                notification_text += f"- Status changed: {change['old']} -> {change['new']}\n"
            elif update_type == 'scope':
                if change['added']:
                    notification_text += f"- Scope added: {', '.join(change['added'][:3])}...\n"
                if change['removed']:
                    notification_text += f"- Scope removed: {', '.join(change['removed'][:3])}...\n"
        
        logger.info(f"Notification: {notification_text}")
        
        # Placeholder for actual notification implementation
        # await self._send_email_notification(notification_text)
        # await self._send_slack_notification(notification_text)
        # await self._send_webhook_notification(program, updates)

# Global monitoring service instance
monitoring_service = MonitoringService()