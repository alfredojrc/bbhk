#!/usr/bin/env python3
"""
Campaign Lifecycle System Test Suite
Comprehensive testing for campaign management features
"""

import os
import sys
import sqlite3
import json
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import unittest
import logging

# Add project root to path
sys.path.append('/home/kali/bbhk')

from core.campaign_lifecycle import (
    CampaignManager, Campaign, CampaignStatus, LifecycleStage, 
    CampaignEvent, EventType, create_campaign_manager
)
# Import archival system - adjust path as needed
try:
    from scripts.campaign_archival_system import CampaignArchiver, ArchiveConfig
except ImportError:
    # Load directly from file
    import importlib.util
    spec = importlib.util.spec_from_file_location("campaign_archival_system", "/home/kali/bbhk/scripts/campaign-archival-system.py")
    campaign_archival_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(campaign_archival_module)
    CampaignArchiver = campaign_archival_module.CampaignArchiver
    ArchiveConfig = campaign_archival_module.ArchiveConfig

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CampaignLifecycleTestSuite:
    """Test suite for campaign lifecycle management"""
    
    def __init__(self):
        self.test_db_path = None
        self.campaign_manager = None
        self.archiver = None
        self.temp_dir = None
        
    def setup_test_environment(self):
        """Set up test database and environment"""
        try:
            # Create temporary directory for test data
            self.temp_dir = tempfile.mkdtemp(prefix="bbhk_test_")
            self.test_db_path = os.path.join(self.temp_dir, "test_bbhk.db")
            
            logger.info(f"Setting up test environment in: {self.temp_dir}")
            
            # Copy schema from real database
            real_db_path = "/home/kali/bbhk/core/database/bbhk.db"
            if os.path.exists(real_db_path):
                # Copy structure but not data
                self._copy_database_schema(real_db_path, self.test_db_path)
            else:
                # Create basic schema
                self._create_basic_schema()
            
            # Run schema migration
            try:
                from scripts.migrate_campaign_schema import CampaignSchemaMigration
            except ImportError:
                # Load directly from file
                import importlib.util
                spec = importlib.util.spec_from_file_location("migrate_campaign_schema", "/home/kali/bbhk/scripts/migrate-campaign-schema.py")
                migrate_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(migrate_module)
                CampaignSchemaMigration = migrate_module.CampaignSchemaMigration
            
            migration = CampaignSchemaMigration(self.test_db_path)
            migration.run_migration()
            
            # Initialize managers
            self.campaign_manager = CampaignManager(self.test_db_path, auto_monitor=False)
            
            archive_config = ArchiveConfig()
            archive_config.archive_base_path = os.path.join(self.temp_dir, "archives")
            archive_config.backup_location = os.path.join(self.temp_dir, "backups")
            self.archiver = CampaignArchiver(self.test_db_path, archive_config)
            
            logger.info("Test environment setup complete")
            return True
            
        except Exception as e:
            logger.error(f"Error setting up test environment: {e}")
            return False
    
    def _copy_database_schema(self, source_db: str, target_db: str):
        """Copy database schema without data"""
        try:
            source_conn = sqlite3.connect(source_db)
            target_conn = sqlite3.connect(target_db)
            
            # Get schema
            cursor = source_conn.cursor()
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            # Create tables in target
            target_cursor = target_conn.cursor()
            for table_sql in tables:
                if table_sql[0]:  # Skip None entries
                    target_cursor.execute(table_sql[0])
            
            # Get indexes
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='index'")
            indexes = cursor.fetchall()
            
            # Create indexes in target
            for index_sql in indexes:
                if index_sql[0] and not index_sql[0].startswith("CREATE UNIQUE INDEX sqlite_"):
                    try:
                        target_cursor.execute(index_sql[0])
                    except sqlite3.OperationalError:
                        pass  # Index might already exist
            
            target_conn.commit()
            source_conn.close()
            target_conn.close()
            
        except Exception as e:
            logger.error(f"Error copying database schema: {e}")
            raise
    
    def _create_basic_schema(self):
        """Create basic database schema for testing"""
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        # Create minimal required tables
        cursor.execute("""
            CREATE TABLE platforms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(50) UNIQUE NOT NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform_id INTEGER,
                program_name VARCHAR(100) NOT NULL,
                program_url TEXT,
                active BOOLEAN DEFAULT 1,
                campaign_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER,
                asset_type VARCHAR(50),
                asset_identifier TEXT NOT NULL,
                campaign_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Insert test platform
        cursor.execute("INSERT INTO platforms (name) VALUES ('test_platform')")
        
        conn.commit()
        conn.close()
    
    def cleanup_test_environment(self):
        """Clean up test environment"""
        try:
            if self.campaign_manager:
                self.campaign_manager.stop_monitoring()
            
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info("Test environment cleaned up")
                
        except Exception as e:
            logger.error(f"Error cleaning up test environment: {e}")
    
    def run_all_tests(self) -> Dict[str, bool]:
        """Run all test cases"""
        test_results = {}
        
        logger.info("Starting Campaign Lifecycle Test Suite")
        logger.info("=" * 50)
        
        # Test cases
        test_cases = [
            ("Database Schema Migration", self.test_database_migration),
            ("Campaign Creation", self.test_campaign_creation),
            ("Campaign Status Updates", self.test_campaign_status_updates),
            ("Campaign Search", self.test_campaign_search),
            ("Campaign Metrics", self.test_campaign_metrics),
            ("End Date Detection", self.test_end_date_detection),
            ("Auto-Archival System", self.test_auto_archival),
            ("Archive and Restore", self.test_archive_restore),
            ("Campaign Timeline", self.test_campaign_timeline),
            ("Bulk Operations", self.test_bulk_operations)
        ]
        
        for test_name, test_function in test_cases:
            logger.info(f"\nRunning test: {test_name}")
            try:
                result = test_function()
                test_results[test_name] = result
                status = "✅ PASSED" if result else "❌ FAILED"
                logger.info(f"{test_name}: {status}")
            except Exception as e:
                test_results[test_name] = False
                logger.error(f"{test_name}: ❌ FAILED - {e}")
        
        return test_results
    
    def test_database_migration(self) -> bool:
        """Test database schema migration"""
        try:
            conn = sqlite3.connect(self.test_db_path)
            cursor = conn.cursor()
            
            # Check if campaign tables exist
            required_tables = [
                'campaigns', 'campaign_timeline', 'campaign_archives', 
                'campaign_metrics', 'campaign_search_index'
            ]
            
            for table in required_tables:
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name=?
                """, (table,))
                
                if not cursor.fetchone():
                    logger.error(f"Required table '{table}' not found")
                    conn.close()
                    return False
            
            # Check if campaign_id columns were added to existing tables
            cursor.execute("PRAGMA table_info(programs)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'campaign_id' not in columns:
                logger.error("campaign_id column not added to programs table")
                conn.close()
                return False
            
            conn.close()
            logger.info("Database migration test passed")
            return True
            
        except Exception as e:
            logger.error(f"Database migration test failed: {e}")
            return False
    
    def test_campaign_creation(self) -> bool:
        """Test campaign creation functionality"""
        try:
            # Create test campaign
            campaign = Campaign(
                campaign_name="Test Campaign",
                platform="test_platform",
                handle="test_handle",
                start_date=datetime.now(),
                end_date=datetime.now() + timedelta(days=30),
                status=CampaignStatus.ACTIVE,
                lifecycle_stage=LifecycleStage.OPERATIONAL
            )
            
            campaign_id = self.campaign_manager.create_campaign(campaign)
            
            if not campaign_id:
                logger.error("Failed to create campaign")
                return False
            
            # Verify campaign was created
            retrieved_campaign = self.campaign_manager.get_campaign(campaign_id)
            
            if not retrieved_campaign:
                logger.error("Failed to retrieve created campaign")
                return False
            
            if retrieved_campaign.campaign_name != "Test Campaign":
                logger.error("Campaign data mismatch")
                return False
            
            logger.info(f"Campaign created successfully with ID: {campaign_id}")
            return True
            
        except Exception as e:
            logger.error(f"Campaign creation test failed: {e}")
            return False
    
    def test_campaign_status_updates(self) -> bool:
        """Test campaign status update functionality"""
        try:
            # Create test campaign
            campaign = Campaign(
                campaign_name="Status Test Campaign",
                platform="test_platform",
                handle="status_test",
                status=CampaignStatus.ACTIVE,
                lifecycle_stage=LifecycleStage.OPERATIONAL
            )
            
            campaign_id = self.campaign_manager.create_campaign(campaign)
            
            # Test status update
            success = self.campaign_manager.update_campaign_status(
                campaign_id, 
                CampaignStatus.ENDING_SOON, 
                "Test status update"
            )
            
            if not success:
                logger.error("Failed to update campaign status")
                return False
            
            # Verify status was updated
            updated_campaign = self.campaign_manager.get_campaign(campaign_id)
            
            if updated_campaign.status != CampaignStatus.ENDING_SOON:
                logger.error("Campaign status was not updated correctly")
                return False
            
            # Test lifecycle stage update
            success = self.campaign_manager.update_lifecycle_stage(
                campaign_id,
                LifecycleStage.WINDING_DOWN,
                "Test lifecycle update"
            )
            
            if not success:
                logger.error("Failed to update lifecycle stage")
                return False
            
            logger.info("Campaign status updates test passed")
            return True
            
        except Exception as e:
            logger.error(f"Campaign status updates test failed: {e}")
            return False
    
    def test_campaign_search(self) -> bool:
        """Test campaign search functionality"""
        try:
            # Create multiple test campaigns
            campaigns = [
                Campaign(
                    campaign_name="HackerOne Test Campaign",
                    platform="hackerone",
                    handle="h1_test",
                    status=CampaignStatus.ACTIVE
                ),
                Campaign(
                    campaign_name="Bugcrowd Test Campaign",
                    platform="bugcrowd",
                    handle="bc_test",
                    status=CampaignStatus.ENDED
                ),
                Campaign(
                    campaign_name="Security Research Project",
                    platform="hackerone",
                    handle="sec_research",
                    status=CampaignStatus.ACTIVE
                )
            ]
            
            campaign_ids = []
            for campaign in campaigns:
                campaign_id = self.campaign_manager.create_campaign(campaign)
                campaign_ids.append(campaign_id)
            
            # Test text search
            results = self.campaign_manager.search_campaigns("HackerOne")
            
            if len(results) != 2:  # Should find 2 HackerOne campaigns
                logger.error(f"Text search returned {len(results)} results, expected 2")
                return False
            
            # Test filtered search
            filters = {"platform": "hackerone", "status": "active"}
            results = self.campaign_manager.search_campaigns("", filters)
            
            if len(results) != 2:  # Should find 2 active HackerOne campaigns
                logger.error(f"Filtered search returned {len(results)} results, expected 2")
                return False
            
            logger.info("Campaign search test passed")
            return True
            
        except Exception as e:
            logger.error(f"Campaign search test failed: {e}")
            return False
    
    def test_campaign_metrics(self) -> bool:
        """Test campaign metrics functionality"""
        try:
            # Create test campaign
            campaign = Campaign(
                campaign_name="Metrics Test Campaign",
                platform="test_platform",
                handle="metrics_test",
                start_date=datetime.now() - timedelta(days=10),
                status=CampaignStatus.ACTIVE
            )
            
            campaign_id = self.campaign_manager.create_campaign(campaign)
            
            # Get metrics
            metrics = self.campaign_manager.get_campaign_metrics(campaign_id)
            
            if not metrics:
                logger.error("Failed to get campaign metrics")
                return False
            
            required_metrics = [
                'campaign_id', 'campaign_name', 'status', 'lifecycle_stage',
                'days_active', 'programs_count', 'targets_count', 'findings_count'
            ]
            
            for metric in required_metrics:
                if metric not in metrics:
                    logger.error(f"Missing metric: {metric}")
                    return False
            
            if metrics['days_active'] < 0:
                logger.error("Invalid days_active calculation")
                return False
            
            logger.info("Campaign metrics test passed")
            return True
            
        except Exception as e:
            logger.error(f"Campaign metrics test failed: {e}")
            return False
    
    def test_end_date_detection(self) -> bool:
        """Test automatic end date detection and status updates"""
        try:
            # Create campaign with end date in the past
            campaign = Campaign(
                campaign_name="Ended Campaign Test",
                platform="test_platform",
                handle="ended_test",
                end_date=datetime.now() - timedelta(days=1),
                status=CampaignStatus.ACTIVE
            )
            
            campaign_id = self.campaign_manager.create_campaign(campaign)
            
            # Run status check
            results = self.campaign_manager.check_campaign_statuses()
            
            if results["ended"] < 1:
                logger.error("End date detection failed - no campaigns marked as ended")
                return False
            
            # Verify campaign status was updated
            updated_campaign = self.campaign_manager.get_campaign(campaign_id)
            
            if updated_campaign.status != CampaignStatus.ENDED:
                logger.error("Campaign status was not updated to ENDED")
                return False
            
            logger.info("End date detection test passed")
            return True
            
        except Exception as e:
            logger.error(f"End date detection test failed: {e}")
            return False
    
    def test_auto_archival(self) -> bool:
        """Test automatic archival system"""
        try:
            # Create campaign that should be auto-archived
            campaign = Campaign(
                campaign_name="Auto Archive Test",
                platform="test_platform",
                handle="auto_archive_test",
                end_date=datetime.now() - timedelta(days=10),
                status=CampaignStatus.ENDED,
                auto_archive_enabled=True
            )
            
            campaign_id = self.campaign_manager.create_campaign(campaign)
            
            # Force status to ended
            self.campaign_manager.update_campaign_status(
                campaign_id, CampaignStatus.ENDED, "Test ended status"
            )
            
            # Run auto-archival
            archived_count = self.campaign_manager.auto_archive_ended_campaigns()
            
            if archived_count < 1:
                logger.error("Auto-archival failed - no campaigns archived")
                return False
            
            # Verify campaign was archived
            archived_campaign = self.campaign_manager.get_campaign(campaign_id)
            
            if archived_campaign.status != CampaignStatus.ARCHIVED:
                logger.error("Campaign was not archived correctly")
                return False
            
            logger.info("Auto-archival test passed")
            return True
            
        except Exception as e:
            logger.error(f"Auto-archival test failed: {e}")
            return False
    
    def test_archive_restore(self) -> bool:
        """Test campaign archive and restore functionality"""
        try:
            # Create test campaign
            campaign = Campaign(
                campaign_name="Archive Restore Test",
                platform="test_platform",
                handle="archive_restore_test",
                status=CampaignStatus.ENDED
            )
            
            campaign_id = self.campaign_manager.create_campaign(campaign)
            
            # Create archive
            archive_metadata = self.archiver.create_campaign_archive(
                campaign_id, "Test archive creation"
            )
            
            if not archive_metadata:
                logger.error("Failed to create campaign archive")
                return False
            
            # Verify archive file exists
            archive_path = Path(self.archiver.config.archive_base_path) / archive_metadata.archive_location
            
            if not archive_path.exists():
                logger.error(f"Archive file not created: {archive_path}")
                return False
            
            # Test restore
            success = self.archiver.restore_campaign_from_archive(campaign_id)
            
            if not success:
                logger.error("Failed to restore campaign from archive")
                return False
            
            # Verify campaign was restored
            restored_campaign = self.campaign_manager.get_campaign(campaign_id)
            
            if restored_campaign.lifecycle_stage == LifecycleStage.ARCHIVED:
                logger.error("Campaign lifecycle stage was not updated after restore")
                return False
            
            logger.info("Archive and restore test passed")
            return True
            
        except Exception as e:
            logger.error(f"Archive and restore test failed: {e}")
            return False
    
    def test_campaign_timeline(self) -> bool:
        """Test campaign timeline and event tracking"""
        try:
            # Create test campaign
            campaign = Campaign(
                campaign_name="Timeline Test Campaign",
                platform="test_platform",
                handle="timeline_test",
                status=CampaignStatus.ACTIVE
            )
            
            campaign_id = self.campaign_manager.create_campaign(campaign)
            
            # Perform several status changes
            self.campaign_manager.update_campaign_status(
                campaign_id, CampaignStatus.ENDING_SOON, "Test status change 1"
            )
            
            self.campaign_manager.update_lifecycle_stage(
                campaign_id, LifecycleStage.WINDING_DOWN, "Test lifecycle change"
            )
            
            self.campaign_manager.update_campaign_status(
                campaign_id, CampaignStatus.ENDED, "Test status change 2"
            )
            
            # Get timeline events from database
            conn = self.campaign_manager.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM campaign_timeline 
                WHERE campaign_id = ? 
                ORDER BY event_timestamp ASC
            """, (campaign_id,))
            
            events = cursor.fetchall()
            conn.close()
            
            if len(events) < 4:  # Creation + 3 updates
                logger.error(f"Expected at least 4 timeline events, found {len(events)}")
                return False
            
            # Verify event types
            event_types = [event["event_type"] for event in events]
            
            if "status_change" not in event_types:
                logger.error("Status change events not found in timeline")
                return False
            
            if "lifecycle_change" not in event_types:
                logger.error("Lifecycle change events not found in timeline")
                return False
            
            logger.info("Campaign timeline test passed")
            return True
            
        except Exception as e:
            logger.error(f"Campaign timeline test failed: {e}")
            return False
    
    def test_bulk_operations(self) -> bool:
        """Test bulk campaign operations"""
        try:
            # Create multiple test campaigns
            campaign_ids = []
            
            for i in range(5):
                campaign = Campaign(
                    campaign_name=f"Bulk Test Campaign {i+1}",
                    platform="test_platform",
                    handle=f"bulk_test_{i+1}",
                    status=CampaignStatus.ACTIVE
                )
                
                campaign_id = self.campaign_manager.create_campaign(campaign)
                campaign_ids.append(campaign_id)
            
            # Test getting campaigns by status
            active_campaigns = self.campaign_manager.get_campaigns_by_status(CampaignStatus.ACTIVE)
            
            if len(active_campaigns) < 5:
                logger.error(f"Expected at least 5 active campaigns, found {len(active_campaigns)}")
                return False
            
            # Test bulk status update (simulated)
            updated_count = 0
            for campaign_id in campaign_ids[:3]:
                success = self.campaign_manager.update_campaign_status(
                    campaign_id, CampaignStatus.ENDING_SOON, "Bulk status update"
                )
                if success:
                    updated_count += 1
            
            if updated_count != 3:
                logger.error(f"Expected 3 campaigns updated, got {updated_count}")
                return False
            
            # Verify bulk update
            ending_soon_campaigns = self.campaign_manager.get_campaigns_by_status(CampaignStatus.ENDING_SOON)
            
            if len(ending_soon_campaigns) < 3:
                logger.error("Bulk status update failed")
                return False
            
            logger.info("Bulk operations test passed")
            return True
            
        except Exception as e:
            logger.error(f"Bulk operations test failed: {e}")
            return False
    
    def generate_test_report(self, test_results: Dict[str, bool]) -> str:
        """Generate comprehensive test report"""
        report = []
        report.append("BBHK CAMPAIGN LIFECYCLE SYSTEM TEST REPORT")
        report.append("=" * 50)
        report.append(f"Test executed at: {datetime.now().isoformat()}")
        report.append(f"Test database: {self.test_db_path}")
        report.append("")
        
        passed_tests = sum(1 for result in test_results.values() if result)
        total_tests = len(test_results)
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        
        report.append(f"SUMMARY: {passed_tests}/{total_tests} tests passed ({success_rate:.1f}%)")
        report.append("")
        
        report.append("DETAILED RESULTS:")
        report.append("-" * 30)
        
        for test_name, result in test_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            report.append(f"{test_name:<30} {status}")
        
        report.append("")
        
        if all(test_results.values()):
            report.append("🎉 ALL TESTS PASSED - Campaign lifecycle system is working correctly!")
        else:
            failed_tests = [name for name, result in test_results.items() if not result]
            report.append("⚠️  SOME TESTS FAILED:")
            for test_name in failed_tests:
                report.append(f"   - {test_name}")
            report.append("")
            report.append("Please review the failed tests and fix any issues.")
        
        report.append("")
        report.append("SYSTEM INFORMATION:")
        report.append(f"- Database path: {self.test_db_path}")
        report.append(f"- Archive directory: {self.archiver.config.archive_base_path}")
        report.append(f"- Temp directory: {self.temp_dir}")
        
        return "\n".join(report)

def main():
    """Main test execution function"""
    test_suite = CampaignLifecycleTestSuite()
    
    try:
        # Setup test environment
        if not test_suite.setup_test_environment():
            logger.error("Failed to setup test environment")
            return False
        
        # Run all tests
        test_results = test_suite.run_all_tests()
        
        # Generate and display report
        report = test_suite.generate_test_report(test_results)
        print("\n" + report)
        
        # Save report to file
        report_path = "/home/kali/bbhk/tests/campaign_lifecycle_test_report.txt"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        logger.info(f"Test report saved to: {report_path}")
        
        # Return overall success
        return all(test_results.values())
        
    except Exception as e:
        logger.error(f"Test execution failed: {e}")
        return False
        
    finally:
        # Cleanup
        test_suite.cleanup_test_environment()

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)