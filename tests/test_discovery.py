#!/usr/bin/env python3
"""
Unit tests for BBHK Program Discovery Pipeline
Comprehensive test coverage for all components
"""

import unittest
import asyncio
import json
import tempfile
import sqlite3
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from datetime import datetime
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.platforms.program_discovery import Program, ProgramDiscoveryService
from src.correlation.customer_engine import Customer, CustomerCorrelationEngine
from src.storage.database_persistence import DatabasePersistence


class TestProgram(unittest.TestCase):
    """Test Program dataclass"""
    
    def test_program_creation(self):
        """Test creating a Program instance"""
        program = Program(
            platform='hackerone',
            program_id='123',
            handle='test_program',
            name='Test Program',
            url='https://hackerone.com/test_program',
            submission_state='open',
            managed=True,
            offers_bounties=True,
            max_bounty=10000,
            currency='USD',
            response_efficiency_percentage=95.5,
            first_response_time=24,
            triage_time=48,
            resolution_time=168,
            bookmarked=False,
            allows_private_disclosure=True,
            policy='Test policy',
            scope=[],
            out_of_scope=[],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        self.assertEqual(program.platform, 'hackerone')
        self.assertEqual(program.handle, 'test_program')
        self.assertEqual(program.max_bounty, 10000)
        self.assertTrue(program.offers_bounties)
    
    def test_program_to_dict(self):
        """Test converting Program to dictionary"""
        program = Program(
            platform='hackerone',
            program_id='123',
            handle='test',
            name='Test',
            url='https://test.com',
            submission_state='open',
            managed=False,
            offers_bounties=True,
            max_bounty=5000,
            currency='USD',
            response_efficiency_percentage=None,
            first_response_time=None,
            triage_time=None,
            resolution_time=None,
            bookmarked=False,
            allows_private_disclosure=True,
            policy='',
            scope=[],
            out_of_scope=[],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        program_dict = program.to_dict()
        self.assertIsInstance(program_dict, dict)
        self.assertEqual(program_dict['platform'], 'hackerone')
        self.assertEqual(program_dict['max_bounty'], 5000)
        self.assertIn('created_at', program_dict)
    
    def test_program_hash(self):
        """Test Program hash generation"""
        program = Program(
            platform='hackerone',
            program_id='123',
            handle='test',
            name='Test',
            url='',
            submission_state='open',
            managed=False,
            offers_bounties=True,
            max_bounty=None,
            currency='USD',
            response_efficiency_percentage=None,
            first_response_time=None,
            triage_time=None,
            resolution_time=None,
            bookmarked=False,
            allows_private_disclosure=True,
            policy='',
            scope=[],
            out_of_scope=[],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        hash1 = program.get_hash()
        self.assertIsInstance(hash1, str)
        self.assertEqual(len(hash1), 64)  # SHA256 hash length
        
        # Same program should have same hash
        hash2 = program.get_hash()
        self.assertEqual(hash1, hash2)


class TestCustomerCorrelationEngine(unittest.TestCase):
    """Test Customer Correlation Engine"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = CustomerCorrelationEngine()
    
    def test_extract_domain_from_url(self):
        """Test domain extraction from URLs"""
        test_cases = [
            ('https://www.example.com', 'example.com'),
            ('http://subdomain.example.com/path', 'subdomain.example.com'),
            ('example.com', 'example.com'),
            ('www.example.com', 'example.com'),
            ('https://api.example.com:8080/v1', 'api.example.com'),
        ]
        
        for url, expected in test_cases:
            result = self.engine.extract_domain_from_url(url)
            self.assertEqual(result, expected, f"Failed for URL: {url}")
    
    def test_extract_domains_from_scope(self):
        """Test extracting domains from program scope"""
        scope = [
            {'asset_type': 'domain', 'asset_identifier': 'example.com'},
            {'asset_type': 'url', 'asset_identifier': 'https://api.example.com'},
            {'asset_type': 'ip', 'asset_identifier': '192.168.1.1'},
            {'asset_type': 'domain', 'asset_identifier': '*.subdomain.example.com'},
        ]
        
        domains = self.engine.extract_domains_from_scope(scope)
        
        self.assertIn('example.com', domains)
        self.assertIn('api.example.com', domains)
        self.assertEqual(len(domains), 4)  # Including root domains
    
    def test_identify_customer_by_patterns(self):
        """Test customer identification using known patterns"""
        # Test with Google domains
        google_domains = {'google.com', 'googleapis.com', 'youtube.com'}
        result = self.engine.identify_customer_by_patterns(google_domains, 'Google VRP')
        self.assertEqual(result, 'google')
        
        # Test with program name
        result = self.engine.identify_customer_by_patterns(set(), 'Microsoft Bug Bounty')
        self.assertEqual(result, 'microsoft')
        
        # Test with unknown
        result = self.engine.identify_customer_by_patterns({'unknown.com'}, 'Unknown Program')
        self.assertIsNone(result)
    
    def test_calculate_similarity_score(self):
        """Test domain similarity calculation"""
        domains1 = {'example.com', 'api.example.com', 'www.example.com'}
        domains2 = {'example.com', 'api.example.com'}
        
        score = self.engine.calculate_similarity_score(domains1, domains2)
        self.assertGreater(score, 0.5)
        self.assertLessEqual(score, 1.0)
        
        # Test with no overlap
        domains3 = {'different.com', 'other.com'}
        score = self.engine.calculate_similarity_score(domains1, domains3)
        self.assertEqual(score, 0.0)
    
    def test_correlate_program(self):
        """Test program correlation"""
        scope = [
            {'asset_type': 'domain', 'asset_identifier': 'example.com'},
            {'asset_type': 'url', 'asset_identifier': 'https://api.example.com'},
        ]
        
        customer_id = self.engine.correlate_program(
            platform='hackerone',
            program_handle='example',
            program_name='Example Corp',
            scope=scope,
            max_bounty=10000
        )
        
        self.assertIsNotNone(customer_id)
        self.assertIn(customer_id, self.engine.customers)
        
        # Check customer was created correctly
        customer = self.engine.customers[customer_id]
        self.assertEqual(customer.name, 'Example Corp')
        self.assertIn('example.com', customer.domains)
        self.assertIn('hackerone', customer.programs)
        self.assertIn('example', customer.programs['hackerone'])
    
    def test_customer_merge(self):
        """Test merging customers with similar domains"""
        # Create first program
        scope1 = [
            {'asset_type': 'domain', 'asset_identifier': 'example.com'},
            {'asset_type': 'domain', 'asset_identifier': 'api.example.com'},
        ]
        
        customer_id1 = self.engine.correlate_program(
            platform='hackerone',
            program_handle='example1',
            program_name='Example Corp',
            scope=scope1,
            max_bounty=5000
        )
        
        # Create second program with overlapping domains
        scope2 = [
            {'asset_type': 'domain', 'asset_identifier': 'example.com'},
            {'asset_type': 'domain', 'asset_identifier': 'app.example.com'},
        ]
        
        customer_id2 = self.engine.correlate_program(
            platform='hackerone',
            program_handle='example2',
            program_name='Example Corporation',
            scope=scope2,
            max_bounty=10000
        )
        
        # Should be correlated to same customer
        self.assertEqual(customer_id1, customer_id2)
        
        customer = self.engine.customers[customer_id1]
        self.assertEqual(len(customer.programs['hackerone']), 2)
        self.assertIn('api.example.com', customer.domains)
        self.assertIn('app.example.com', customer.domains)


class TestDatabasePersistence(unittest.TestCase):
    """Test Database Persistence Layer"""
    
    def setUp(self):
        """Set up test database"""
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.db = DatabasePersistence(self.temp_db.name)
        
        # Create schema
        with open('core/database/schema.sql', 'r') as f:
            schema = f.read()
        
        conn = sqlite3.connect(self.temp_db.name)
        conn.executescript(schema)
        conn.close()
    
    def tearDown(self):
        """Clean up test database"""
        Path(self.temp_db.name).unlink(missing_ok=True)
    
    def test_get_or_create_platform(self):
        """Test platform creation and retrieval"""
        # Create new platform
        platform_id = self.db.get_or_create_platform('hackerone')
        self.assertIsNotNone(platform_id)
        self.assertIsInstance(platform_id, int)
        
        # Get existing platform
        platform_id2 = self.db.get_or_create_platform('hackerone')
        self.assertEqual(platform_id, platform_id2)
        
        # Create different platform
        platform_id3 = self.db.get_or_create_platform('bugcrowd')
        self.assertNotEqual(platform_id, platform_id3)
    
    def test_upsert_program(self):
        """Test program insertion and update"""
        program_data = {
            'platform': 'hackerone',
            'name': 'Test Program',
            'url': 'https://hackerone.com/test',
            'max_bounty': 10000,
            'offers_bounties': True,
            'allows_private_disclosure': True,
            'submission_state': 'open'
        }
        
        # Insert new program
        program_id = self.db.upsert_program(program_data)
        self.assertIsNotNone(program_id)
        
        # Update existing program
        program_data['max_bounty'] = 15000
        program_id2 = self.db.upsert_program(program_data)
        self.assertEqual(program_id, program_id2)
        
        # Verify update
        programs = self.db.get_programs_by_platform('hackerone')
        self.assertEqual(len(programs), 1)
        self.assertEqual(programs[0]['max_bounty'], 15000)
    
    def test_upsert_targets(self):
        """Test target insertion and update"""
        # Create program first
        program_data = {
            'platform': 'hackerone',
            'name': 'Test Program',
            'url': 'https://test.com'
        }
        program_id = self.db.upsert_program(program_data)
        
        # Add targets
        scope = [
            {'asset_type': 'domain', 'asset_identifier': 'example.com', 'max_severity': 'critical'},
            {'asset_type': 'url', 'asset_identifier': 'https://api.example.com', 'max_severity': 'high'},
            {'asset_type': 'ip', 'asset_identifier': '192.168.1.1', 'max_severity': 'medium'},
        ]
        
        targets_created = self.db.upsert_targets(program_id, scope)
        self.assertEqual(targets_created, 3)
        
        # Get targets
        targets = self.db.get_targets_by_program(program_id)
        self.assertEqual(len(targets), 3)
        
        # Update targets (should update existing ones)
        targets_created = self.db.upsert_targets(program_id, scope)
        self.assertEqual(targets_created, 0)  # No new targets
    
    def test_store_customer_correlation(self):
        """Test storing customer correlation data"""
        customer_data = {
            'customer_id': 'test_customer',
            'name': 'Test Customer',
            'domains': ['example.com', 'test.com'],
            'programs': {'hackerone': ['test1', 'test2']},
            'bounty_thresholds': {'critical': 10000, 'high': 5000}
        }
        
        self.db.store_customer_correlation(customer_data)
        
        # Verify storage (stored as rules)
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT rule_value FROM rules WHERE rule_name = ?",
                (f"customer_{customer_data['customer_id']}",)
            )
            result = cursor.fetchone()
            
            self.assertIsNotNone(result)
            stored_data = json.loads(result[0])
            self.assertEqual(stored_data['name'], 'Test Customer')
            self.assertIn('example.com', stored_data['domains'])
    
    def test_get_statistics(self):
        """Test statistics generation"""
        # Add test data
        program_data = {
            'platform': 'hackerone',
            'name': 'Test Program',
            'max_bounty': 10000,
            'offers_bounties': True,
            'submission_state': 'open'
        }
        program_id = self.db.upsert_program(program_data)
        
        scope = [
            {'asset_type': 'domain', 'asset_identifier': 'example.com'},
        ]
        self.db.upsert_targets(program_id, scope)
        
        # Get statistics
        stats = self.db.get_statistics()
        
        self.assertIn('total_programs', stats)
        self.assertIn('total_targets', stats)
        self.assertIn('programs_with_bounties', stats)
        self.assertEqual(stats['total_programs'], 1)
        self.assertEqual(stats['total_targets'], 1)
        self.assertEqual(stats['programs_with_bounties'], 1)


class TestProgramDiscoveryService(unittest.TestCase):
    """Test Program Discovery Service"""
    
    @patch('src.platforms.program_discovery.HackerOneClient')
    async def test_discover_programs(self, mock_client_class):
        """Test program discovery"""
        # Mock client
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        # Mock API response
        mock_client.discover_programs.return_value = [
            {
                'id': '123',
                'attributes': {
                    'handle': 'test_program',
                    'name': 'Test Program',
                    'managed': True,
                    'offers_bounties': True,
                    'submission_state': 'open',
                    'bounty_table': {
                        'bounty_table_rows': [
                            {'low': 100, 'medium': 500, 'high': 2000, 'critical': 5000}
                        ]
                    }
                }
            }
        ]
        
        # Test discovery
        service = ProgramDiscoveryService()
        service.client = mock_client
        
        programs = await service.discover_programs(limit=10)
        
        self.assertEqual(len(programs), 1)
        self.assertEqual(programs[0].handle, 'test_program')
        self.assertEqual(programs[0].max_bounty, 5000)
        self.assertTrue(programs[0].managed)


def run_async_test(coro):
    """Helper to run async tests"""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(coro)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)