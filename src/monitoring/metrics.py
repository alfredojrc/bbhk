"""Production monitoring and metrics collection for BBHK system."""

import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, start_http_server
from loguru import logger
import psutil
import threading
from datetime import datetime, timedelta


@dataclass
class MetricConfig:
    """Configuration for metrics collection."""
    port: int = 8000
    collect_interval: int = 30  # seconds
    enable_system_metrics: bool = True
    enable_business_metrics: bool = True
    enable_performance_metrics: bool = True


class ProductionMetrics:
    """Comprehensive metrics collection for production monitoring."""
    
    def __init__(self, config: MetricConfig):
        self.config = config
        self.registry = CollectorRegistry()
        self._setup_metrics()
        self._collector_thread = None
        self._stop_collecting = threading.Event()
        
    def _setup_metrics(self):
        """Initialize all metrics."""
        
        # Application Metrics
        self.agent_spawned = Counter(
            'bbhk_agents_spawned_total',
            'Total number of agents spawned',
            ['agent_type', 'platform'],
            registry=self.registry
        )
        
        self.agent_failures = Counter(
            'bbhk_agent_failures_total',
            'Total number of agent failures',
            ['agent_type', 'error_type'],
            registry=self.registry
        )
        
        self.scans_completed = Counter(
            'bbhk_scans_completed_total',
            'Total number of scans completed',
            ['scan_type', 'status', 'platform'],
            registry=self.registry
        )
        
        self.scan_duration = Histogram(
            'bbhk_scan_duration_seconds',
            'Duration of scans in seconds',
            ['scan_type', 'platform'],
            registry=self.registry
        )
        
        self.vulnerabilities_found = Counter(
            'bbhk_vulnerabilities_found_total',
            'Total vulnerabilities discovered',
            ['severity', 'vulnerability_type', 'platform'],
            registry=self.registry
        )
        
        # System Resource Metrics
        self.cpu_usage = Gauge(
            'bbhk_cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        self.memory_usage = Gauge(
            'bbhk_memory_usage_bytes',
            'Memory usage in bytes',
            registry=self.registry
        )
        
        self.disk_usage = Gauge(
            'bbhk_disk_usage_percent',
            'Disk usage percentage',
            ['mount_point'],
            registry=self.registry
        )
        
        self.network_bytes = Counter(
            'bbhk_network_bytes_total',
            'Total network bytes transferred',
            ['direction'],
            registry=self.registry
        )
        
        # Business Metrics
        self.bounty_earned = Counter(
            'bbhk_bounty_earned_total',
            'Total bounty earned in USD',
            ['platform', 'severity'],
            registry=self.registry
        )
        
        self.roi_score = Gauge(
            'bbhk_roi_score',
            'Current ROI score',
            ['program_id'],
            registry=self.registry
        )
        
        self.success_rate = Gauge(
            'bbhk_success_rate_percent',
            'Success rate percentage by agent type',
            ['agent_type'],
            registry=self.registry
        )
        
        # Performance Metrics
        self.api_requests = Counter(
            'bbhk_api_requests_total',
            'Total API requests made',
            ['platform', 'method', 'status'],
            registry=self.registry
        )
        
        self.api_request_duration = Histogram(
            'bbhk_api_request_duration_seconds',
            'API request duration in seconds',
            ['platform', 'endpoint'],
            registry=self.registry
        )
        
        self.task_queue_size = Gauge(
            'bbhk_task_queue_size',
            'Current task queue size',
            ['priority', 'task_type'],
            registry=self.registry
        )
        
        self.active_agents = Gauge(
            'bbhk_active_agents',
            'Number of currently active agents',
            ['agent_type', 'status'],
            registry=self.registry
        )
        
        # Error Tracking
        self.errors_total = Counter(
            'bbhk_errors_total',
            'Total errors by component',
            ['component', 'error_type', 'severity'],
            registry=self.registry
        )
        
        logger.info("Production metrics initialized")
    
    def start_collection(self):
        """Start metrics collection server and background collector."""
        try:
            # Start Prometheus metrics server
            start_http_server(self.config.port, registry=self.registry)
            logger.info(f"Metrics server started on port {self.config.port}")
            
            # Start background system metrics collection
            self._collector_thread = threading.Thread(
                target=self._collect_system_metrics,
                daemon=True
            )
            self._collector_thread.start()
            logger.info("System metrics collection started")
            
        except Exception as e:
            logger.error(f"Failed to start metrics collection: {e}")
            raise
    
    def stop_collection(self):
        """Stop metrics collection."""
        self._stop_collecting.set()
        if self._collector_thread:
            self._collector_thread.join(timeout=5)
        logger.info("Metrics collection stopped")
    
    def _collect_system_metrics(self):
        """Background thread for collecting system metrics."""
        while not self._stop_collecting.is_set():
            try:
                if self.config.enable_system_metrics:
                    # CPU usage
                    cpu_percent = psutil.cpu_percent(interval=1)
                    self.cpu_usage.set(cpu_percent)
                    
                    # Memory usage
                    memory = psutil.virtual_memory()
                    self.memory_usage.set(memory.used)
                    
                    # Disk usage
                    for partition in psutil.disk_partitions():
                        try:
                            disk_usage = psutil.disk_usage(partition.mountpoint)
                            usage_percent = (disk_usage.used / disk_usage.total) * 100
                            self.disk_usage.labels(mount_point=partition.mountpoint).set(usage_percent)
                        except PermissionError:
                            continue
                    
                    # Network I/O
                    net_io = psutil.net_io_counters()
                    if hasattr(net_io, 'bytes_sent'):
                        self.network_bytes.labels(direction='sent')._value._value = net_io.bytes_sent
                        self.network_bytes.labels(direction='recv')._value._value = net_io.bytes_recv
                
            except Exception as e:
                logger.warning(f"Error collecting system metrics: {e}")
            
            self._stop_collecting.wait(self.config.collect_interval)
    
    # Agent Metrics Methods
    def record_agent_spawn(self, agent_type: str, platform: str):
        """Record agent spawn event."""
        self.agent_spawned.labels(agent_type=agent_type, platform=platform).inc()
        logger.debug(f"Recorded agent spawn: {agent_type} on {platform}")
    
    def record_agent_failure(self, agent_type: str, error_type: str):
        """Record agent failure event."""
        self.agent_failures.labels(agent_type=agent_type, error_type=error_type).inc()
        logger.warning(f"Recorded agent failure: {agent_type} - {error_type}")
    
    def record_scan_completion(self, scan_type: str, platform: str, status: str, duration: float):
        """Record scan completion with duration."""
        self.scans_completed.labels(scan_type=scan_type, status=status, platform=platform).inc()
        self.scan_duration.labels(scan_type=scan_type, platform=platform).observe(duration)
        logger.debug(f"Recorded scan completion: {scan_type} on {platform} ({status}, {duration:.2f}s)")
    
    def record_vulnerability_found(self, severity: str, vulnerability_type: str, platform: str):
        """Record vulnerability discovery."""
        self.vulnerabilities_found.labels(
            severity=severity,
            vulnerability_type=vulnerability_type,
            platform=platform
        ).inc()
        logger.info(f"Recorded vulnerability: {severity} {vulnerability_type} on {platform}")
    
    def record_bounty_earned(self, amount: float, platform: str, severity: str):
        """Record bounty payment received."""
        self.bounty_earned.labels(platform=platform, severity=severity).inc(amount)
        logger.info(f"Recorded bounty: ${amount} from {platform} ({severity})")
    
    def record_api_request(self, platform: str, method: str, status: str, duration: float, endpoint: str = ""):
        """Record API request metrics."""
        self.api_requests.labels(platform=platform, method=method, status=status).inc()
        if endpoint:
            self.api_request_duration.labels(platform=platform, endpoint=endpoint).observe(duration)
    
    def update_task_queue_size(self, priority: str, task_type: str, size: int):
        """Update task queue size gauge."""
        self.task_queue_size.labels(priority=priority, task_type=task_type).set(size)
    
    def update_active_agents(self, agent_type: str, status: str, count: int):
        """Update active agents count."""
        self.active_agents.labels(agent_type=agent_type, status=status).set(count)
    
    def update_roi_score(self, program_id: str, score: float):
        """Update ROI score for a program."""
        self.roi_score.labels(program_id=program_id).set(score)
    
    def update_success_rate(self, agent_type: str, rate: float):
        """Update success rate percentage."""
        self.success_rate.labels(agent_type=agent_type).set(rate)
    
    def record_error(self, component: str, error_type: str, severity: str = "warning"):
        """Record error occurrence."""
        self.errors_total.labels(component=component, error_type=error_type, severity=severity).inc()
        logger.error(f"Recorded error: {component} - {error_type} ({severity})")


class HealthChecker:
    """Health check endpoint for monitoring systems."""
    
    def __init__(self):
        self.checks = {}
        self.last_check_time = None
        self.check_interval = 30  # seconds
    
    def register_check(self, name: str, check_func, critical: bool = True):
        """Register a health check function."""
        self.checks[name] = {
            'func': check_func,
            'critical': critical,
            'last_status': None,
            'last_error': None
        }
    
    async def run_health_checks(self) -> Dict[str, Any]:
        """Run all registered health checks."""
        results = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'checks': {}
        }
        
        overall_healthy = True
        
        for name, check in self.checks.items():
            try:
                status = await check['func']()
                results['checks'][name] = {
                    'status': 'healthy' if status else 'unhealthy',
                    'critical': check['critical']
                }
                
                if not status and check['critical']:
                    overall_healthy = False
                    
            except Exception as e:
                results['checks'][name] = {
                    'status': 'error',
                    'error': str(e),
                    'critical': check['critical']
                }
                
                if check['critical']:
                    overall_healthy = False
        
        results['status'] = 'healthy' if overall_healthy else 'unhealthy'
        self.last_check_time = datetime.utcnow()
        
        return results
    
    async def check_database_connection(self) -> bool:
        """Check database connectivity."""
        try:
            from ..core.database import db_manager
            with db_manager.get_session() as session:
                session.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    async def check_memory_usage(self) -> bool:
        """Check if memory usage is within acceptable limits."""
        memory = psutil.virtual_memory()
        return memory.percent < 90  # Less than 90% memory usage
    
    async def check_disk_space(self) -> bool:
        """Check if disk space is sufficient."""
        disk_usage = psutil.disk_usage('/')
        usage_percent = (disk_usage.used / disk_usage.total) * 100
        return usage_percent < 85  # Less than 85% disk usage


# Global metrics instance
metrics = None
health_checker = HealthChecker()


def initialize_metrics(config: Optional[MetricConfig] = None) -> ProductionMetrics:
    """Initialize global metrics collection."""
    global metrics
    
    if config is None:
        config = MetricConfig()
    
    metrics = ProductionMetrics(config)
    
    # Register default health checks
    health_checker.register_check('database', health_checker.check_database_connection)
    health_checker.register_check('memory', health_checker.check_memory_usage)
    health_checker.register_check('disk', health_checker.check_disk_space, critical=False)
    
    return metrics


def get_metrics() -> ProductionMetrics:
    """Get the global metrics instance."""
    if metrics is None:
        raise RuntimeError("Metrics not initialized. Call initialize_metrics() first.")
    return metrics


# Decorator for automatic metrics collection
def monitor_operation(operation_type: str, component: str):
    """Decorator to automatically collect metrics for operations."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                if metrics:
                    # Record successful operation
                    metrics.api_request_duration.labels(
                        platform=component,
                        endpoint=operation_type
                    ).observe(duration)
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                if metrics:
                    # Record error
                    metrics.record_error(component, type(e).__name__, "error")
                
                raise
        
        return wrapper
    return decorator