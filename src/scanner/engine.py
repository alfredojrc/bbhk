"""Main scanning engine that orchestrates all scanners."""

import asyncio
from typing import Dict, List, Any, Optional, Type
from datetime import datetime, timezone
from loguru import logger

from .subdomain import SubdomainScanner
from .port import PortScanner
from .vulnerability import VulnerabilityScanner
from .base import BaseScanner, ScanResult
from ..core.database import Program, Scan, get_async_db
from ..core.config import config
from ..compliance.engine import compliance_engine

class ScanEngine:
    """Main scanning engine that coordinates all scanners."""
    
    def __init__(self):
        """Initialize scan engine."""
        self.scanners: Dict[str, Type[BaseScanner]] = {
            'subdomain': SubdomainScanner,
            'port': PortScanner, 
            'vulnerability': VulnerabilityScanner
        }
        
        self.active_scans: Dict[int, BaseScanner] = {}
        self.scan_queue = asyncio.Queue()
        self.max_concurrent_scans = config.scanner.max_concurrent_scans
        self.running = False
        
    async def start(self):
        """Start the scan engine."""
        if self.running:
            logger.warning("Scan engine is already running")
            return
        
        self.running = True
        logger.info("Starting scan engine")
        
        # Start scan workers
        workers = []
        for i in range(self.max_concurrent_scans):
            worker = asyncio.create_task(self._scan_worker(f"worker-{i}"))
            workers.append(worker)
        
        # Wait for workers to complete
        try:
            await asyncio.gather(*workers)
        except Exception as e:
            logger.error(f"Scan engine error: {e}")
        finally:
            self.running = False
    
    async def stop(self):
        """Stop the scan engine."""
        self.running = False
        logger.info("Stopping scan engine")
        
        # Stop all active scans
        for scan_id, scanner in self.active_scans.items():
            await scanner.stop_scan()
        
        self.active_scans.clear()
    
    async def queue_scan(self, program_id: int, scan_type: str, target: str, **kwargs) -> int:
        """Queue a scan for execution."""
        try:
            # Validate program exists
            async with get_async_db() as db:
                program = await db.get(Program, program_id)
                if not program:
                    raise ValueError(f"Program {program_id} not found")
            
            # Validate scan type
            if scan_type not in self.scanners:
                raise ValueError(f"Unknown scan type: {scan_type}")
            
            # Check compliance
            compliance_result = await compliance_engine.check_compliance(
                program_id, 'queue_scan', target, scan_type=scan_type, **kwargs
            )
            
            if not compliance_result['allowed']:
                logger.error(f"Scan blocked by compliance: {compliance_result['violations']}")
                raise ValueError(f"Compliance violation: {compliance_result['violations']}")
            
            # Create scan task
            scan_task = {
                'program_id': program_id,
                'scan_type': scan_type,
                'target': target,
                'kwargs': kwargs,
                'queued_at': datetime.now(timezone.utc)
            }
            
            # Add to queue
            await self.scan_queue.put(scan_task)
            logger.info(f"Queued {scan_type} scan for {target} (program {program_id})")
            
            # Return estimated scan ID (actual ID created when scan starts)
            return hash(f"{program_id}_{scan_type}_{target}_{datetime.now().timestamp()}")
            
        except Exception as e:
            logger.error(f"Failed to queue scan: {e}")
            raise
    
    async def get_scan_status(self, scan_id: int) -> Dict[str, Any]:
        """Get status of a specific scan."""
        try:
            async with get_async_db() as db:
                scan = await db.get(Scan, scan_id)
                if not scan:
                    return {'error': 'Scan not found'}
                
                # Check if scan is currently active
                active_scanner = self.active_scans.get(scan_id)
                
                status = {
                    'id': scan.id,
                    'program_id': scan.program_id,
                    'scan_type': scan.scan_type,
                    'target': scan.target,
                    'status': scan.status,
                    'started_at': scan.started_at,
                    'completed_at': scan.completed_at,
                    'duration': scan.duration,
                    'findings_count': scan.findings_count,
                    'is_active': active_scanner is not None
                }
                
                if active_scanner:
                    status.update({
                        'requests_made': active_scanner.requests_made,
                        'findings_discovered': active_scanner.findings_discovered,
                        'runtime': datetime.now(timezone.utc).timestamp() - (scan.started_at or 0)
                    })
                
                return status
                
        except Exception as e:
            logger.error(f"Failed to get scan status: {e}")
            return {'error': str(e)}
    
    async def stop_scan(self, scan_id: int) -> bool:
        """Stop a specific scan."""
        try:
            scanner = self.active_scans.get(scan_id)
            if scanner:
                await scanner.stop_scan()
                del self.active_scans[scan_id]
                logger.info(f"Stopped scan {scan_id}")
                return True
            else:
                logger.warning(f"Scan {scan_id} is not active")
                return False
                
        except Exception as e:
            logger.error(f"Failed to stop scan {scan_id}: {e}")
            return False
    
    async def list_active_scans(self) -> List[Dict[str, Any]]:
        """List all currently active scans."""
        active = []
        
        for scan_id, scanner in self.active_scans.items():
            try:
                async with get_async_db() as db:
                    scan = await db.get(Scan, scan_id)
                    if scan:
                        active.append({
                            'id': scan.id,
                            'program_id': scan.program_id,
                            'scan_type': scan.scan_type,
                            'target': scan.target,
                            'started_at': scan.started_at,
                            'requests_made': scanner.requests_made,
                            'findings_discovered': scanner.findings_discovered
                        })
            except Exception as e:
                logger.error(f"Failed to get info for active scan {scan_id}: {e}")
        
        return active
    
    async def get_engine_status(self) -> Dict[str, Any]:
        """Get overall engine status."""
        return {
            'running': self.running,
            'active_scans': len(self.active_scans),
            'queue_size': self.scan_queue.qsize(),
            'max_concurrent_scans': self.max_concurrent_scans,
            'available_scanners': list(self.scanners.keys())
        }
    
    async def _scan_worker(self, worker_name: str):
        """Worker that processes scans from the queue."""
        logger.info(f"Scan worker {worker_name} started")
        
        while self.running:
            try:
                # Get scan task from queue
                try:
                    scan_task = await asyncio.wait_for(
                        self.scan_queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Execute scan
                await self._execute_scan(scan_task, worker_name)
                
                # Mark task as done
                self.scan_queue.task_done()
                
            except Exception as e:
                logger.error(f"Scan worker {worker_name} error: {e}")
                await asyncio.sleep(1)  # Brief pause before retry
        
        logger.info(f"Scan worker {worker_name} stopped")
    
    async def _execute_scan(self, scan_task: Dict[str, Any], worker_name: str):
        """Execute a single scan task."""
        program_id = scan_task['program_id']
        scan_type = scan_task['scan_type']
        target = scan_task['target']
        kwargs = scan_task['kwargs']
        
        scanner = None
        scan_id = None
        
        try:
            # Create scanner instance
            scanner_class = self.scanners[scan_type]
            scanner = scanner_class(program_id)
            
            logger.info(f"Worker {worker_name} starting {scan_type} scan on {target}")
            
            # Start scan (this creates the scan record and returns scan ID)
            scan_id = await scanner.start_scan(target, **kwargs)
            
            # Track active scan
            if scan_id:
                self.active_scans[scan_id] = scanner
            
            # Scan is completed when start_scan returns
            logger.info(f"Worker {worker_name} completed {scan_type} scan on {target}")
            
        except Exception as e:
            logger.error(f"Worker {worker_name} failed to execute scan: {e}")
            
        finally:
            # Clean up
            if scanner:
                await scanner.cleanup()
            
            if scan_id and scan_id in self.active_scans:
                del self.active_scans[scan_id]

# Global scan engine instance
scan_engine = ScanEngine()