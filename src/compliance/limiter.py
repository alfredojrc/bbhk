"""Rate limiting implementation for compliance."""

import asyncio
import time
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from loguru import logger

from .rules import RateLimit
from ..core.utils import RateLimiter

@dataclass
class RequestRecord:
    """Record of a request for rate limiting."""
    timestamp: float
    action: str
    target: str
    success: bool = True

class ComplianceRateLimiter:
    """Advanced rate limiter with multiple strategies."""
    
    def __init__(self, limits: RateLimit):
        """Initialize rate limiter with specified limits."""
        self.limits = limits
        
        # Track requests by different time windows
        self.second_requests: deque = deque()
        self.minute_requests: deque = deque()
        self.hour_requests: deque = deque()
        
        # Track concurrent requests
        self.active_requests = 0
        self.max_concurrent = limits.concurrent_requests
        
        # Per-target rate limiting
        self.target_limiters: Dict[str, RateLimiter] = {}
        
        # Request history for analysis
        self.request_history: List[RequestRecord] = []
        self.max_history_size = 10000
        
        # Pause/resume functionality
        self.paused = False
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
    
    async def can_make_request(self, action: str, target: str) -> bool:
        """Check if request can be made within rate limits."""
        async with self._lock:
            if self.paused:
                return False
            
            current_time = time.time()
            
            # Clean old requests
            await self._clean_old_requests(current_time)
            
            # Check global rate limits
            if not await self._check_global_limits():
                logger.debug(f"Global rate limit exceeded for {action} on {target}")
                return False
            
            # Check per-target rate limits
            if not await self._check_target_limits(target):
                logger.debug(f"Per-target rate limit exceeded for {target}")
                return False
            
            # Check concurrent request limit
            if self.active_requests >= self.max_concurrent:
                logger.debug(f"Concurrent request limit exceeded ({self.active_requests}/{self.max_concurrent})")
                return False
            
            return True
    
    async def record_request_start(self, action: str, target: str):
        """Record the start of a request."""
        async with self._lock:
            current_time = time.time()
            
            # Add to tracking queues
            self.second_requests.append(current_time)
            self.minute_requests.append(current_time)
            self.hour_requests.append(current_time)
            
            # Update concurrent counter
            self.active_requests += 1
            
            # Record in history
            self.request_history.append(RequestRecord(
                timestamp=current_time,
                action=action,
                target=target
            ))
            
            # Trim history if needed
            if len(self.request_history) > self.max_history_size:
                self.request_history = self.request_history[-self.max_history_size//2:]
            
            logger.debug(f"Request started: {action} on {target} (active: {self.active_requests})")
    
    async def record_request_end(self, action: str, target: str, success: bool = True):
        """Record the end of a request."""
        async with self._lock:
            # Update concurrent counter
            if self.active_requests > 0:
                self.active_requests -= 1
            
            # Update history record
            if self.request_history:
                self.request_history[-1].success = success
            
            logger.debug(f"Request ended: {action} on {target} (active: {self.active_requests}, success: {success})")
    
    async def wait_for_rate_limit(self, action: str, target: str) -> float:
        """Calculate how long to wait before next request is allowed."""
        async with self._lock:
            current_time = time.time()
            await self._clean_old_requests(current_time)
            
            wait_times = []
            
            # Check seconds limit
            if len(self.second_requests) >= int(self.limits.requests_per_second):
                oldest_in_second = self.second_requests[0]
                wait_times.append(1.0 - (current_time - oldest_in_second))
            
            # Check minutes limit
            if len(self.minute_requests) >= self.limits.requests_per_minute:
                oldest_in_minute = self.minute_requests[0]
                wait_times.append(60.0 - (current_time - oldest_in_minute))
            
            # Check hours limit
            if len(self.hour_requests) >= self.limits.requests_per_hour:
                oldest_in_hour = self.hour_requests[0]
                wait_times.append(3600.0 - (current_time - oldest_in_hour))
            
            return max(wait_times + [0.0])
    
    async def get_current_usage(self) -> Dict[str, any]:
        """Get current rate limiting usage statistics."""
        async with self._lock:
            current_time = time.time()
            await self._clean_old_requests(current_time)
            
            return {
                'requests_last_second': len(self.second_requests),
                'requests_last_minute': len(self.minute_requests),
                'requests_last_hour': len(self.hour_requests),
                'active_concurrent_requests': self.active_requests,
                'limits': {
                    'requests_per_second': self.limits.requests_per_second,
                    'requests_per_minute': self.limits.requests_per_minute,
                    'requests_per_hour': self.limits.requests_per_hour,
                    'max_concurrent': self.max_concurrent
                },
                'utilization': {
                    'second': len(self.second_requests) / max(1, int(self.limits.requests_per_second)),
                    'minute': len(self.minute_requests) / max(1, self.limits.requests_per_minute),
                    'hour': len(self.hour_requests) / max(1, self.limits.requests_per_hour),
                    'concurrent': self.active_requests / max(1, self.max_concurrent)
                },
                'paused': self.paused
            }
    
    async def get_request_statistics(self, time_window: int = 3600) -> Dict[str, any]:
        """Get request statistics for analysis."""
        async with self._lock:
            current_time = time.time()
            cutoff_time = current_time - time_window
            
            recent_requests = [r for r in self.request_history if r.timestamp >= cutoff_time]
            
            if not recent_requests:
                return {'total_requests': 0, 'success_rate': 0.0}
            
            total_requests = len(recent_requests)
            successful_requests = sum(1 for r in recent_requests if r.success)
            
            # Group by action
            action_counts = defaultdict(int)
            for request in recent_requests:
                action_counts[request.action] += 1
            
            # Group by target
            target_counts = defaultdict(int)
            for request in recent_requests:
                target_counts[request.target] += 1
            
            return {
                'time_window_seconds': time_window,
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'failed_requests': total_requests - successful_requests,
                'success_rate': successful_requests / total_requests if total_requests > 0 else 0.0,
                'requests_by_action': dict(action_counts),
                'requests_by_target': dict(target_counts),
                'average_requests_per_minute': (total_requests / time_window) * 60
            }
    
    async def pause_all(self):
        """Pause all requests."""
        async with self._lock:
            self.paused = True
            logger.warning("Rate limiter paused - all requests will be blocked")
    
    async def resume_all(self):
        """Resume all requests."""
        async with self._lock:
            self.paused = False
            logger.info("Rate limiter resumed - requests will be rate limited normally")
    
    async def _check_global_limits(self) -> bool:
        """Check if global rate limits are exceeded."""
        # Check seconds
        if len(self.second_requests) >= int(self.limits.requests_per_second):
            return False
        
        # Check minutes
        if len(self.minute_requests) >= self.limits.requests_per_minute:
            return False
        
        # Check hours
        if len(self.hour_requests) >= self.limits.requests_per_hour:
            return False
        
        return True
    
    async def _check_target_limits(self, target: str) -> bool:
        """Check per-target rate limits."""
        if target not in self.target_limiters:
            # Create per-target limiter (more conservative)
            target_limit = max(1, int(self.limits.requests_per_minute // 10))
            self.target_limiters[target] = RateLimiter(target_limit, 60)
        
        return await self.target_limiters[target].acquire()
    
    async def _clean_old_requests(self, current_time: float):
        """Clean old requests from tracking queues."""
        # Clean second requests (older than 1 second)
        while self.second_requests and current_time - self.second_requests[0] > 1.0:
            self.second_requests.popleft()
        
        # Clean minute requests (older than 1 minute)
        while self.minute_requests and current_time - self.minute_requests[0] > 60.0:
            self.minute_requests.popleft()
        
        # Clean hour requests (older than 1 hour)
        while self.hour_requests and current_time - self.hour_requests[0] > 3600.0:
            self.hour_requests.popleft()
    
    async def adjust_limits(self, new_limits: RateLimit):
        """Dynamically adjust rate limits."""
        async with self._lock:
            old_limits = self.limits
            self.limits = new_limits
            self.max_concurrent = new_limits.concurrent_requests
            
            logger.info(f"Rate limits adjusted: "
                       f"RPS {old_limits.requests_per_second} -> {new_limits.requests_per_second}, "
                       f"RPM {old_limits.requests_per_minute} -> {new_limits.requests_per_minute}")
    
    async def cleanup(self):
        """Clean up rate limiter resources."""
        async with self._lock:
            self.second_requests.clear()
            self.minute_requests.clear()
            self.hour_requests.clear()
            self.target_limiters.clear()
            self.request_history.clear()
            logger.debug("Rate limiter cleaned up")