"""Circuit breaker and resilience patterns for production reliability."""

import time
import asyncio
from typing import Callable, Any, Optional, Dict, List
from dataclasses import dataclass, field
from enum import Enum
import threading
from loguru import logger
import random
from datetime import datetime, timedelta


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"         # Failing, blocking requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5          # Failures before opening
    recovery_timeout: int = 60          # Seconds before trying half-open
    success_threshold: int = 2          # Successes needed to close from half-open
    timeout: float = 30.0               # Operation timeout
    expected_exception: tuple = (Exception,)  # Exceptions that count as failures


@dataclass
class CircuitBreakerStats:
    """Circuit breaker statistics."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    total_requests: int = 0
    total_failures: int = 0
    total_successes: int = 0
    state_changed_at: float = field(default_factory=time.time)


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""
    pass


class CircuitBreaker:
    """Circuit breaker pattern implementation for fault tolerance."""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.stats = CircuitBreakerStats()
        self._lock = threading.Lock()
        
        logger.info(f"Circuit breaker '{name}' initialized with config: {config}")
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator usage."""
        def wrapper(*args, **kwargs):
            return self.call(func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function through circuit breaker."""
        with self._lock:
            self.stats.total_requests += 1
            
            if self._should_attempt_call():
                try:
                    # Set timeout for the operation
                    if asyncio.iscoroutinefunction(func):
                        result = asyncio.wait_for(
                            func(*args, **kwargs),
                            timeout=self.config.timeout
                        )
                    else:
                        result = func(*args, **kwargs)
                    
                    self._on_success()
                    return result
                    
                except self.config.expected_exception as e:
                    self._on_failure(e)
                    raise
                except asyncio.TimeoutError as e:
                    self._on_failure(e)
                    raise
            else:
                logger.warning(f"Circuit breaker '{self.name}' is OPEN, blocking request")
                raise CircuitBreakerError(f"Circuit breaker '{self.name}' is OPEN")
    
    def _should_attempt_call(self) -> bool:
        """Determine if we should attempt the call based on current state."""
        current_time = time.time()
        
        if self.stats.state == CircuitState.CLOSED:
            return True
        
        elif self.stats.state == CircuitState.OPEN:
            if (current_time - self.stats.last_failure_time) >= self.config.recovery_timeout:
                logger.info(f"Circuit breaker '{self.name}' transitioning to HALF_OPEN")
                self.stats.state = CircuitState.HALF_OPEN
                self.stats.success_count = 0
                self.stats.state_changed_at = current_time
                return True
            return False
        
        elif self.stats.state == CircuitState.HALF_OPEN:
            return True
        
        return False
    
    def _on_success(self):
        """Handle successful operation."""
        self.stats.total_successes += 1
        
        if self.stats.state == CircuitState.HALF_OPEN:
            self.stats.success_count += 1
            if self.stats.success_count >= self.config.success_threshold:
                logger.info(f"Circuit breaker '{self.name}' transitioning to CLOSED")
                self.stats.state = CircuitState.CLOSED
                self.stats.failure_count = 0
                self.stats.success_count = 0
                self.stats.state_changed_at = time.time()
        
        elif self.stats.state == CircuitState.CLOSED:
            self.stats.failure_count = 0  # Reset failure count on success
    
    def _on_failure(self, exception: Exception):
        """Handle failed operation."""
        self.stats.total_failures += 1
        self.stats.failure_count += 1
        self.stats.last_failure_time = time.time()
        
        logger.warning(f"Circuit breaker '{self.name}' recorded failure: {exception}")
        
        if self.stats.state == CircuitState.HALF_OPEN:
            logger.info(f"Circuit breaker '{self.name}' transitioning to OPEN (failed during half-open)")
            self.stats.state = CircuitState.OPEN
            self.stats.state_changed_at = time.time()
        
        elif self.stats.state == CircuitState.CLOSED:
            if self.stats.failure_count >= self.config.failure_threshold:
                logger.error(f"Circuit breaker '{self.name}' transitioning to OPEN (failure threshold reached)")
                self.stats.state = CircuitState.OPEN
                self.stats.state_changed_at = time.time()
    
    def get_stats(self) -> dict:
        """Get current circuit breaker statistics."""
        return {
            'name': self.name,
            'state': self.stats.state.value,
            'failure_count': self.stats.failure_count,
            'success_count': self.stats.success_count,
            'total_requests': self.stats.total_requests,
            'total_failures': self.stats.total_failures,
            'total_successes': self.stats.total_successes,
            'success_rate': (self.stats.total_successes / max(self.stats.total_requests, 1)) * 100,
            'last_failure_time': self.stats.last_failure_time,
            'state_duration': time.time() - self.stats.state_changed_at
        }
    
    def reset(self):
        """Manually reset circuit breaker to closed state."""
        with self._lock:
            logger.info(f"Circuit breaker '{self.name}' manually reset to CLOSED")
            self.stats = CircuitBreakerStats()


class RetryPolicy:
    """Retry policy with exponential backoff."""
    
    def __init__(self, 
                 max_attempts: int = 3,
                 base_delay: float = 1.0,
                 max_delay: float = 60.0,
                 exponential_base: float = 2.0,
                 jitter: bool = True):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator usage."""
        def wrapper(*args, **kwargs):
            return self.execute(func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry policy."""
        last_exception = None
        
        for attempt in range(self.max_attempts):
            try:
                if asyncio.iscoroutinefunction(func):
                    return asyncio.run(func(*args, **kwargs))
                else:
                    return func(*args, **kwargs)
            
            except Exception as e:
                last_exception = e
                
                if attempt == self.max_attempts - 1:
                    logger.error(f"Retry exhausted for {func.__name__} after {self.max_attempts} attempts")
                    raise
                
                delay = min(self.base_delay * (self.exponential_base ** attempt), self.max_delay)
                
                if self.jitter:
                    delay *= (0.5 + random.random() * 0.5)  # Add 0-50% jitter
                
                logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}, retrying in {delay:.2f}s: {e}")
                time.sleep(delay)
        
        raise last_exception


class BulkheadPattern:
    """Bulkhead pattern for resource isolation."""
    
    def __init__(self, name: str, max_concurrent: int = 10):
        self.name = name
        self.max_concurrent = max_concurrent
        self.semaphore = threading.Semaphore(max_concurrent)
        self.active_requests = 0
        self.total_requests = 0
        self.rejected_requests = 0
        self._lock = threading.Lock()
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator usage."""
        def wrapper(*args, **kwargs):
            return self.execute(func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with bulkhead isolation."""
        with self._lock:
            self.total_requests += 1
        
        if not self.semaphore.acquire(blocking=False):
            with self._lock:
                self.rejected_requests += 1
            raise RuntimeError(f"Bulkhead '{self.name}' at capacity ({self.max_concurrent} concurrent requests)")
        
        try:
            with self._lock:
                self.active_requests += 1
            
            logger.debug(f"Executing in bulkhead '{self.name}' ({self.active_requests}/{self.max_concurrent})")
            
            if asyncio.iscoroutinefunction(func):
                return asyncio.run(func(*args, **kwargs))
            else:
                return func(*args, **kwargs)
        
        finally:
            with self._lock:
                self.active_requests -= 1
            self.semaphore.release()
    
    def get_stats(self) -> dict:
        """Get bulkhead statistics."""
        return {
            'name': self.name,
            'max_concurrent': self.max_concurrent,
            'active_requests': self.active_requests,
            'total_requests': self.total_requests,
            'rejected_requests': self.rejected_requests,
            'rejection_rate': (self.rejected_requests / max(self.total_requests, 1)) * 100,
            'utilization': (self.active_requests / self.max_concurrent) * 100
        }


class TimeoutWrapper:
    """Timeout wrapper for operations."""
    
    def __init__(self, timeout: float):
        self.timeout = timeout
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator usage."""
        def wrapper(*args, **kwargs):
            return self.execute(func, *args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with timeout."""
        if asyncio.iscoroutinefunction(func):
            return asyncio.wait_for(func(*args, **kwargs), timeout=self.timeout)
        else:
            # For sync functions, we need to use threading
            import concurrent.futures
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    return future.result(timeout=self.timeout)
                except concurrent.futures.TimeoutError:
                    raise asyncio.TimeoutError(f"Operation timed out after {self.timeout}s")


class ReliabilityManager:
    """Central manager for all reliability patterns."""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.bulkheads: Dict[str, BulkheadPattern] = {}
        self.retry_policies: Dict[str, RetryPolicy] = {}
        self.timeouts: Dict[str, TimeoutWrapper] = {}
    
    def create_circuit_breaker(self, name: str, config: CircuitBreakerConfig) -> CircuitBreaker:
        """Create and register a circuit breaker."""
        breaker = CircuitBreaker(name, config)
        self.circuit_breakers[name] = breaker
        logger.info(f"Created circuit breaker: {name}")
        return breaker
    
    def create_bulkhead(self, name: str, max_concurrent: int) -> BulkheadPattern:
        """Create and register a bulkhead."""
        bulkhead = BulkheadPattern(name, max_concurrent)
        self.bulkheads[name] = bulkhead
        logger.info(f"Created bulkhead: {name} (max_concurrent: {max_concurrent})")
        return bulkhead
    
    def create_retry_policy(self, name: str, **kwargs) -> RetryPolicy:
        """Create and register a retry policy."""
        policy = RetryPolicy(**kwargs)
        self.retry_policies[name] = policy
        logger.info(f"Created retry policy: {name}")
        return policy
    
    def create_timeout(self, name: str, timeout: float) -> TimeoutWrapper:
        """Create and register a timeout wrapper."""
        wrapper = TimeoutWrapper(timeout)
        self.timeouts[name] = wrapper
        logger.info(f"Created timeout wrapper: {name} ({timeout}s)")
        return wrapper
    
    def get_system_health(self) -> dict:
        """Get overall system reliability health."""
        breaker_stats = {name: cb.get_stats() for name, cb in self.circuit_breakers.items()}
        bulkhead_stats = {name: bh.get_stats() for name, bh in self.bulkheads.items()}
        
        # Calculate overall health score
        total_breakers = len(self.circuit_breakers)
        healthy_breakers = sum(1 for cb in self.circuit_breakers.values() 
                              if cb.stats.state == CircuitState.CLOSED)
        
        total_bulkheads = len(self.bulkheads)
        healthy_bulkheads = sum(1 for bh in self.bulkheads.values()
                               if bh.rejection_rate < 10)  # Less than 10% rejection rate
        
        health_score = 100
        if total_breakers > 0:
            health_score *= (healthy_breakers / total_breakers)
        if total_bulkheads > 0:
            health_score *= (healthy_bulkheads / total_bulkheads)
        
        return {
            'overall_health_score': health_score,
            'circuit_breakers': breaker_stats,
            'bulkheads': bulkhead_stats,
            'summary': {
                'total_circuit_breakers': total_breakers,
                'healthy_circuit_breakers': healthy_breakers,
                'total_bulkheads': total_bulkheads,
                'healthy_bulkheads': healthy_bulkheads
            }
        }
    
    def reset_all_circuit_breakers(self):
        """Reset all circuit breakers (emergency use)."""
        for name, breaker in self.circuit_breakers.items():
            breaker.reset()
        logger.warning("All circuit breakers have been reset")


# Global reliability manager
reliability_manager = ReliabilityManager()


# Pre-configured patterns for common use cases
def database_circuit_breaker():
    """Circuit breaker optimized for database operations."""
    config = CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=30,
        timeout=10.0,
        expected_exception=(Exception,)
    )
    return reliability_manager.create_circuit_breaker("database", config)


def api_circuit_breaker(platform: str):
    """Circuit breaker optimized for external API calls."""
    config = CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout=60,
        timeout=30.0,
        expected_exception=(Exception,)
    )
    return reliability_manager.create_circuit_breaker(f"api_{platform}", config)


def scanning_bulkhead():
    """Bulkhead for scanning operations."""
    return reliability_manager.create_bulkhead("scanning", max_concurrent=5)


def api_retry_policy():
    """Retry policy for API calls."""
    return reliability_manager.create_retry_policy(
        "api",
        max_attempts=3,
        base_delay=2.0,
        max_delay=30.0,
        jitter=True
    )