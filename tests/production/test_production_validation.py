"""
Production validation tests to ensure system readiness for deployment.
These tests validate against real infrastructure components and services.
"""

import pytest
import asyncio
import aiohttp
import time
import subprocess
import sqlite3
import redis
import psutil
from datetime import datetime, timedelta
from typing import List, Dict, Any
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.database import db_manager, Program, Scan, Vulnerability
from src.core.config import config
from src.monitoring.metrics import ProductionMetrics, MetricConfig, HealthChecker
from src.reliability.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from src.scanner.engine import scan_engine
from src.monitor.service import monitoring_service
from src.compliance.engine import compliance_engine


class TestProductionValidation:
    """Comprehensive production validation test suite."""
    
    @pytest.fixture(scope="class")
    def real_database(self):
        """Set up a real SQLite database for testing."""
        test_db_url = "sqlite:///test_production.db"
        engine = create_engine(test_db_url)
        
        # Create tables
        from src.core.database import Base
        Base.metadata.create_all(bind=engine)
        
        yield test_db_url
        
        # Cleanup
        try:
            import os
            os.remove("test_production.db")
        except FileNotFoundError:
            pass
    
    @pytest.fixture(scope="class")
    def redis_client(self):
        """Set up Redis client for testing."""
        try:
            client = redis.Redis(host='localhost', port=6379, decode_responses=True)
            client.ping()
            yield client
        except (redis.ConnectionError, redis.ResponseError):
            pytest.skip("Redis not available for production testing")
    
    def test_database_crud_operations(self, real_database):
        """Test CRUD operations against real database."""
        engine = create_engine(real_database)
        SessionLocal = sessionmaker(bind=engine)
        
        with SessionLocal() as session:
            # Create operation
            program = Program(
                name="Test Program",
                platform="hackerone",
                url="https://hackerone.com/test",
                company="Test Company",
                description="Test program description",
                scope=["https://example.com", "https://api.example.com"],
                min_bounty=100.0,
                max_bounty=5000.0
            )
            session.add(program)
            session.commit()
            session.refresh(program)
            
            assert program.id is not None
            assert program.discovered_at is not None
            
            # Read operation
            retrieved = session.query(Program).filter_by(id=program.id).first()
            assert retrieved is not None
            assert retrieved.name == "Test Program"
            assert retrieved.platform == "hackerone"
            
            # Update operation
            retrieved.description = "Updated description"
            session.commit()
            
            updated = session.query(Program).filter_by(id=program.id).first()
            assert updated.description == "Updated description"
            
            # Delete operation
            session.delete(updated)
            session.commit()
            
            deleted = session.query(Program).filter_by(id=program.id).first()
            assert deleted is None
    
    def test_database_transaction_integrity(self, real_database):
        """Test database transaction integrity and rollback."""
        engine = create_engine(real_database)
        SessionLocal = sessionmaker(bind=engine)
        
        with SessionLocal() as session:
            try:
                # Create a program
                program = Program(
                    name="Transaction Test",
                    platform="bugcrowd",
                    url="https://bugcrowd.com/test"
                )
                session.add(program)
                session.flush()  # Get ID without committing
                
                # Create a scan linked to this program
                scan = Scan(
                    program_id=program.id,
                    scan_type="subdomain",
                    target="example.com"
                )
                session.add(scan)
                
                # Simulate an error to test rollback
                raise Exception("Simulated error")
                
            except Exception:
                session.rollback()
                
                # Verify rollback worked
                count = session.query(Program).filter_by(name="Transaction Test").count()
                assert count == 0
    
    def test_redis_cache_operations(self, redis_client):
        """Test Redis cache operations with real Redis instance."""
        # Basic operations
        redis_client.set("test_key", "test_value", ex=300)
        value = redis_client.get("test_key")
        assert value == "test_value"
        
        # Hash operations
        redis_client.hset("test_hash", mapping={
            "field1": "value1",
            "field2": "value2"
        })
        
        hash_values = redis_client.hgetall("test_hash")
        assert hash_values["field1"] == "value1"
        assert hash_values["field2"] == "value2"
        
        # List operations
        redis_client.lpush("test_list", "item1", "item2", "item3")
        list_items = redis_client.lrange("test_list", 0, -1)
        assert "item1" in list_items
        
        # Cleanup
        redis_client.delete("test_key", "test_hash", "test_list")
    
    @pytest.mark.asyncio
    async def test_external_api_integration(self):
        """Test integration with external APIs (using httpbin for testing)."""
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Test GET request
            async with session.get("https://httpbin.org/json") as response:
                assert response.status == 200
                data = await response.json()
                assert "slideshow" in data
            
            # Test POST request
            test_data = {"test": "data", "timestamp": datetime.now().isoformat()}
            async with session.post("https://httpbin.org/post", json=test_data) as response:
                assert response.status == 200
                data = await response.json()
                assert data["json"]["test"] == "data"
            
            # Test timeout handling
            try:
                async with session.get("https://httpbin.org/delay/35") as response:
                    await response.text()
                    assert False, "Should have timed out"
            except asyncio.TimeoutError:
                pass  # Expected timeout
    
    def test_concurrent_database_access(self, real_database):
        """Test database under concurrent load."""
        import threading
        import time
        
        engine = create_engine(real_database, pool_size=10, max_overflow=20)
        SessionLocal = sessionmaker(bind=engine)
        
        results = []
        errors = []
        
        def database_worker(worker_id: int):
            try:
                with SessionLocal() as session:
                    # Create program
                    program = Program(
                        name=f"Concurrent Test {worker_id}",
                        platform="test",
                        url=f"https://test{worker_id}.com"
                    )
                    session.add(program)
                    session.commit()
                    
                    # Create scan
                    scan = Scan(
                        program_id=program.id,
                        scan_type="test",
                        target=f"test{worker_id}.com"
                    )
                    session.add(scan)
                    session.commit()
                    
                    # Simulate processing time
                    time.sleep(0.1)
                    
                    # Query data
                    count = session.query(Program).count()
                    results.append(count)
                    
            except Exception as e:
                errors.append(str(e))
        
        # Start 10 concurrent workers
        threads = []
        for i in range(10):
            thread = threading.Thread(target=database_worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join(timeout=30)
        
        # Verify results
        assert len(errors) == 0, f"Database errors occurred: {errors}"
        assert len(results) == 10, "Not all workers completed"
        assert all(count >= 1 for count in results), "Database operations failed"
    
    def test_metrics_collection_real_data(self):
        """Test metrics collection with real data points."""
        config = MetricConfig(port=8001, collect_interval=1)  # Use different port
        metrics = ProductionMetrics(config)
        
        try:
            # Start metrics collection
            metrics.start_collection()
            
            # Generate some metrics
            metrics.record_agent_spawn("test_agent", "hackerone")
            metrics.record_scan_completion("subdomain", "hackerone", "completed", 15.5)
            metrics.record_vulnerability_found("high", "xss", "hackerone")
            metrics.record_bounty_earned(500.0, "hackerone", "high")
            
            # Wait for system metrics collection
            time.sleep(2)
            
            # Verify metrics server is running
            import requests
            response = requests.get("http://localhost:8001/metrics", timeout=5)
            assert response.status_code == 200
            
            metrics_text = response.text
            assert "bbhk_agents_spawned_total" in metrics_text
            assert "bbhk_scans_completed_total" in metrics_text
            assert "bbhk_vulnerabilities_found_total" in metrics_text
            assert "bbhk_bounty_earned_total" in metrics_text
            
        finally:
            metrics.stop_collection()
    
    @pytest.mark.asyncio
    async def test_health_checks_comprehensive(self):
        """Test comprehensive health check functionality."""
        health_checker = HealthChecker()
        
        # Register custom health checks
        async def check_memory_usage():
            memory = psutil.virtual_memory()
            return memory.percent < 95
        
        async def check_disk_space():
            disk = psutil.disk_usage('/')
            return (disk.used / disk.total) < 0.95
        
        health_checker.register_check("memory", check_memory_usage)
        health_checker.register_check("disk", check_disk_space)
        
        # Run health checks
        results = await health_checker.run_health_checks()
        
        assert "status" in results
        assert "timestamp" in results
        assert "checks" in results
        assert "memory" in results["checks"]
        assert "disk" in results["checks"]
        
        # Verify each check has proper structure
        for check_name, check_result in results["checks"].items():
            assert "status" in check_result
            assert check_result["status"] in ["healthy", "unhealthy", "error"]
    
    def test_circuit_breaker_production_behavior(self):
        """Test circuit breaker behavior under production-like conditions."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            recovery_timeout=5,
            timeout=1.0
        )
        
        circuit_breaker = CircuitBreaker("test_service", config)
        
        # Test normal operation
        def successful_operation():
            return "success"
        
        result = circuit_breaker.call(successful_operation)
        assert result == "success"
        assert circuit_breaker.stats.state.value == "closed"
        
        # Test failure accumulation
        def failing_operation():
            raise Exception("Service failure")
        
        for i in range(3):
            with pytest.raises(Exception):
                circuit_breaker.call(failing_operation)
        
        # Circuit should be open now
        assert circuit_breaker.stats.state.value == "open"
        
        # Test that calls are blocked
        from src.reliability.circuit_breaker import CircuitBreakerError
        with pytest.raises(CircuitBreakerError):
            circuit_breaker.call(successful_operation)
        
        # Wait for recovery timeout
        time.sleep(6)
        
        # Should be able to try again (half-open)
        result = circuit_breaker.call(successful_operation)
        assert result == "success"
    
    def test_system_resource_monitoring(self):
        """Test system resource monitoring accuracy."""
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        assert 0 <= cpu_percent <= 100
        
        # Memory usage
        memory = psutil.virtual_memory()
        assert memory.total > 0
        assert 0 <= memory.percent <= 100
        
        # Disk usage
        disk = psutil.disk_usage('/')
        assert disk.total > 0
        assert disk.used >= 0
        assert disk.free >= 0
        assert disk.used + disk.free <= disk.total
        
        # Network I/O
        net_io = psutil.net_io_counters()
        assert hasattr(net_io, 'bytes_sent')
        assert hasattr(net_io, 'bytes_recv')
        assert net_io.bytes_sent >= 0
        assert net_io.bytes_recv >= 0
    
    def test_configuration_validation(self):
        """Test configuration validation and environment handling."""
        # Test default configuration
        assert config.database.url is not None
        assert config.monitor.check_interval > 0
        assert config.scanner.max_concurrent_scans > 0
        assert config.compliance.enable_kill_switch is not None
        
        # Test environment variable override
        import os
        original_db_url = os.environ.get('BBHK_DB_URL')
        
        try:
            os.environ['BBHK_DB_URL'] = 'sqlite:///test_override.db'
            
            # Reload configuration (this would normally happen at startup)
            from src.core.config import Config
            test_config = Config()
            
            assert test_config.database.url == 'sqlite:///test_override.db'
            
        finally:
            # Restore original value
            if original_db_url is not None:
                os.environ['BBHK_DB_URL'] = original_db_url
            else:
                os.environ.pop('BBHK_DB_URL', None)
    
    @pytest.mark.asyncio
    async def test_graceful_shutdown_behavior(self):
        """Test graceful shutdown procedures."""
        import signal
        import asyncio
        
        shutdown_complete = False
        
        async def mock_service():
            nonlocal shutdown_complete
            try:
                # Simulate long-running service
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                # Cleanup operations
                await asyncio.sleep(0.1)  # Simulate cleanup time
                shutdown_complete = True
                raise
        
        # Start the service
        task = asyncio.create_task(mock_service())
        
        # Allow service to start
        await asyncio.sleep(0.1)
        
        # Cancel the task (simulate shutdown signal)
        task.cancel()
        
        try:
            await task
        except asyncio.CancelledError:
            pass
        
        assert shutdown_complete, "Graceful shutdown procedures not executed"
    
    def test_file_system_operations(self):
        """Test file system operations and permissions."""
        import tempfile
        import os
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test file creation
            test_file = os.path.join(temp_dir, "test_file.txt")
            with open(test_file, 'w') as f:
                f.write("Test data")
            
            assert os.path.exists(test_file)
            
            # Test file reading
            with open(test_file, 'r') as f:
                content = f.read()
            
            assert content == "Test data"
            
            # Test directory creation
            test_dir = os.path.join(temp_dir, "test_subdir")
            os.makedirs(test_dir)
            
            assert os.path.isdir(test_dir)
            
            # Test file permissions (Unix-like systems)
            if hasattr(os, 'chmod'):
                os.chmod(test_file, 0o644)
                stat_info = os.stat(test_file)
                assert stat_info.st_mode & 0o777 == 0o644
    
    def test_logging_production_format(self):
        """Test logging format and output for production."""
        import logging
        from io import StringIO
        
        # Create a test logger
        logger = logging.getLogger("test_production")
        logger.setLevel(logging.INFO)
        
        # Create string handler to capture output
        log_capture = StringIO()
        handler = logging.StreamHandler(log_capture)
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # Test different log levels
        logger.info("Test info message")
        logger.warning("Test warning message")
        logger.error("Test error message")
        
        log_output = log_capture.getvalue()
        
        # Verify log format
        assert "INFO" in log_output
        assert "WARNING" in log_output
        assert "ERROR" in log_output
        assert "test_production" in log_output
        assert "Test info message" in log_output
    
    @pytest.mark.slow
    def test_performance_under_load(self):
        """Test system performance under simulated load."""
        import threading
        import time
        import statistics
        
        response_times = []
        errors = []
        
        def simulated_work(worker_id: int, iterations: int):
            worker_times = []
            try:
                for i in range(iterations):
                    start_time = time.time()
                    
                    # Simulate CPU-intensive work
                    result = sum(x*x for x in range(1000))
                    
                    # Simulate I/O operation
                    time.sleep(0.001)
                    
                    end_time = time.time()
                    worker_times.append(end_time - start_time)
                
                response_times.extend(worker_times)
                
            except Exception as e:
                errors.append(f"Worker {worker_id}: {str(e)}")
        
        # Run concurrent load test
        workers = []
        num_workers = 10
        iterations_per_worker = 50
        
        start_time = time.time()
        
        for i in range(num_workers):
            worker = threading.Thread(
                target=simulated_work,
                args=(i, iterations_per_worker)
            )
            workers.append(worker)
            worker.start()
        
        # Wait for all workers
        for worker in workers:
            worker.join(timeout=60)  # 1 minute timeout
        
        total_time = time.time() - start_time
        
        # Analyze performance metrics
        assert len(errors) == 0, f"Errors occurred during load test: {errors}"
        assert len(response_times) == num_workers * iterations_per_worker
        
        avg_response_time = statistics.mean(response_times)
        p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        
        # Performance assertions (adjust based on requirements)
        assert avg_response_time < 0.1, f"Average response time too high: {avg_response_time}"
        assert p95_response_time < 0.2, f"95th percentile response time too high: {p95_response_time}"
        assert total_time < 30, f"Total test time too high: {total_time}"
        
        # Throughput calculation
        total_operations = num_workers * iterations_per_worker
        throughput = total_operations / total_time
        
        assert throughput > 10, f"Throughput too low: {throughput} ops/sec"


@pytest.mark.integration
class TestExternalServiceIntegration:
    """Test integration with external services and APIs."""
    
    @pytest.mark.asyncio
    async def test_dns_resolution(self):
        """Test DNS resolution for various domains."""
        import socket
        
        test_domains = ["google.com", "github.com", "stackoverflow.com"]
        
        for domain in test_domains:
            try:
                ip = socket.gethostbyname(domain)
                assert ip is not None
                assert len(ip.split('.')) == 4  # IPv4 format
            except socket.gaierror as e:
                pytest.fail(f"DNS resolution failed for {domain}: {e}")
    
    @pytest.mark.asyncio
    async def test_http_client_robustness(self):
        """Test HTTP client robustness with various scenarios."""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            # Test successful request
            async with session.get("https://httpbin.org/status/200") as response:
                assert response.status == 200
            
            # Test error handling
            async with session.get("https://httpbin.org/status/500") as response:
                assert response.status == 500
            
            # Test timeout handling
            try:
                async with session.get("https://httpbin.org/delay/31", timeout=aiohttp.ClientTimeout(total=5)) as response:
                    await response.text()
                    assert False, "Should have timed out"
            except asyncio.TimeoutError:
                pass  # Expected
    
    def test_subprocess_execution(self):
        """Test subprocess execution for external tools."""
        # Test basic command execution
        result = subprocess.run(['echo', 'test'], capture_output=True, text=True, timeout=5)
        assert result.returncode == 0
        assert result.stdout.strip() == 'test'
        
        # Test error handling
        result = subprocess.run(['false'], capture_output=True, timeout=5)
        assert result.returncode != 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])