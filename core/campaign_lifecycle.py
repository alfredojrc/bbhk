#!/usr/bin/env python3
"""
Campaign Lifecycle Manager
Handles campaign status tracking, lifecycle management, and automated operations
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import os
import threading
import time
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CampaignStatus(Enum):
    """Campaign status enumeration"""
    ACTIVE = "active"
    ENDING_SOON = "ending_soon"
    ENDED = "ended"
    PAUSED = "paused"
    ARCHIVED = "archived"
    UNKNOWN = "unknown"

class LifecycleStage(Enum):
    """Campaign lifecycle stage enumeration"""
    LAUNCH = "launch"
    OPERATIONAL = "operational"
    WINDING_DOWN = "winding_down"
    ARCHIVED = "archived"

class EventType(Enum):
    """Campaign event types"""
    STATUS_CHANGE = "status_change"
    LIFECYCLE_CHANGE = "lifecycle_change"
    AUTO_ARCHIVE = "auto_archive"
    MANUAL_ARCHIVE = "manual_archive"
    RESTORE = "restore"
    END_DATE_UPDATE = "end_date_update"
    WARNING_THRESHOLD = "warning_threshold"

@dataclass
class Campaign:
    """Campaign data structure"""
    id: Optional[int] = None
    program_id: Optional[int] = None
    campaign_name: str = ""
    platform: str = ""
    handle: str = ""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    estimated_end_date: Optional[datetime] = None
    status: CampaignStatus = CampaignStatus.ACTIVE
    submission_state: str = ""
    lifecycle_stage: LifecycleStage = LifecycleStage.OPERATIONAL
    auto_archive_enabled: bool = True
    archived_at: Optional[datetime] = None
    archive_reason: str = ""
    metadata: Dict[str, Any] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class CampaignEvent:
    """Campaign event data structure"""
    id: Optional[int] = None
    campaign_id: int = 0
    event_type: EventType = EventType.STATUS_CHANGE
    previous_status: Optional[str] = None
    new_status: Optional[str] = None
    event_data: Dict[str, Any] = None
    event_timestamp: Optional[datetime] = None
    automated: bool = False
    notes: str = ""
    
    def __post_init__(self):
        if self.event_data is None:
            self.event_data = {}
        if self.event_timestamp is None:
            self.event_timestamp = datetime.now()

class CampaignManager:
    """Manages campaign lifecycle operations"""
    
    def __init__(self, db_path: str, auto_monitor: bool = True):
        self.db_path = db_path
        self.auto_monitor = auto_monitor
        self._monitoring_thread = None
        self._stop_monitoring = threading.Event()
        
        # Configuration
        self.config = {
            "warning_days": 30,  # Days before end to trigger warning
            "auto_archive_delay": 7,  # Days after end to auto-archive
            "check_interval": 3600,  # Seconds between automated checks
            "retention_days": 365,  # Days to keep archived data
        }
        
        if auto_monitor:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start automated monitoring thread"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            return
        
        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(target=self._monitor_campaigns, daemon=True)
        self._monitoring_thread.start()
        logger.info("Campaign monitoring started")
    
    def stop_monitoring(self):
        """Stop automated monitoring"""
        if self._monitoring_thread:
            self._stop_monitoring.set()
            self._monitoring_thread.join(timeout=5)
            logger.info("Campaign monitoring stopped")
    
    def _monitor_campaigns(self):
        """Automated monitoring loop"""
        while not self._stop_monitoring.is_set():
            try:
                self.check_campaign_statuses()
                self.auto_archive_ended_campaigns()
                self.cleanup_old_archives()
            except Exception as e:
                logger.error(f"Error in campaign monitoring: {e}")
            
            self._stop_monitoring.wait(self.config["check_interval"])
    
    def get_db_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def create_campaign(self, campaign: Campaign) -> int:
        """Create a new campaign"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            campaign.created_at = datetime.now()
            campaign.updated_at = campaign.created_at
            
            cursor.execute("""
                INSERT INTO campaigns 
                (program_id, campaign_name, platform, handle, start_date, end_date, 
                 estimated_end_date, status, submission_state, lifecycle_stage,
                 auto_archive_enabled, metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                campaign.program_id,
                campaign.campaign_name,
                campaign.platform,
                campaign.handle,
                campaign.start_date,
                campaign.end_date,
                campaign.estimated_end_date,
                campaign.status.value,
                campaign.submission_state,
                campaign.lifecycle_stage.value,
                campaign.auto_archive_enabled,
                json.dumps(campaign.metadata),
                campaign.created_at,
                campaign.updated_at
            ))
            
            campaign_id = cursor.lastrowid
            
            # Create initial event
            self._create_event(cursor, CampaignEvent(
                campaign_id=campaign_id,
                event_type=EventType.STATUS_CHANGE,
                new_status=campaign.status.value,
                notes="Campaign created",
                automated=False
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Created campaign: {campaign.campaign_name} (ID: {campaign_id})")
            return campaign_id
            
        except Exception as e:
            logger.error(f"Error creating campaign: {e}")
            raise
    
    def get_campaign(self, campaign_id: int) -> Optional[Campaign]:
        """Get campaign by ID"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
            row = cursor.fetchone()
            
            conn.close()
            
            if row:
                return self._row_to_campaign(row)
            return None
            
        except Exception as e:
            logger.error(f"Error getting campaign {campaign_id}: {e}")
            return None
    
    def get_campaigns_by_status(self, status: CampaignStatus) -> List[Campaign]:
        """Get campaigns by status"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM campaigns WHERE status = ?", (status.value,))
            rows = cursor.fetchall()
            
            conn.close()
            
            return [self._row_to_campaign(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting campaigns by status {status}: {e}")
            return []
    
    def get_ending_soon_campaigns(self, days: int = None) -> List[Campaign]:
        """Get campaigns ending soon"""
        if days is None:
            days = self.config["warning_days"]
        
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            end_threshold = datetime.now() + timedelta(days=days)
            
            cursor.execute("""
                SELECT * FROM campaigns 
                WHERE status = 'active' 
                AND end_date IS NOT NULL 
                AND end_date <= ? 
                AND end_date > datetime('now')
                ORDER BY end_date ASC
            """, (end_threshold,))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [self._row_to_campaign(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting ending soon campaigns: {e}")
            return []
    
    def update_campaign_status(self, campaign_id: int, new_status: CampaignStatus, 
                             notes: str = "", automated: bool = False) -> bool:
        """Update campaign status"""
        try:
            campaign = self.get_campaign(campaign_id)
            if not campaign:
                logger.error(f"Campaign {campaign_id} not found")
                return False
            
            old_status = campaign.status
            
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Update campaign
            cursor.execute("""
                UPDATE campaigns 
                SET status = ?, updated_at = ?
                WHERE id = ?
            """, (new_status.value, datetime.now(), campaign_id))
            
            # Create event
            self._create_event(cursor, CampaignEvent(
                campaign_id=campaign_id,
                event_type=EventType.STATUS_CHANGE,
                previous_status=old_status.value,
                new_status=new_status.value,
                notes=notes,
                automated=automated
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Updated campaign {campaign_id} status: {old_status.value} -> {new_status.value}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating campaign status: {e}")
            return False
    
    def update_lifecycle_stage(self, campaign_id: int, new_stage: LifecycleStage,
                              notes: str = "", automated: bool = False) -> bool:
        """Update campaign lifecycle stage"""
        try:
            campaign = self.get_campaign(campaign_id)
            if not campaign:
                logger.error(f"Campaign {campaign_id} not found")
                return False
            
            old_stage = campaign.lifecycle_stage
            
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Update campaign
            cursor.execute("""
                UPDATE campaigns 
                SET lifecycle_stage = ?, updated_at = ?
                WHERE id = ?
            """, (new_stage.value, datetime.now(), campaign_id))
            
            # Create event
            self._create_event(cursor, CampaignEvent(
                campaign_id=campaign_id,
                event_type=EventType.LIFECYCLE_CHANGE,
                previous_status=old_stage.value,
                new_status=new_stage.value,
                notes=notes,
                automated=automated
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Updated campaign {campaign_id} lifecycle: {old_stage.value} -> {new_stage.value}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating campaign lifecycle: {e}")
            return False
    
    def archive_campaign(self, campaign_id: int, reason: str = "", automated: bool = False) -> bool:
        """Archive a campaign"""
        try:
            campaign = self.get_campaign(campaign_id)
            if not campaign:
                logger.error(f"Campaign {campaign_id} not found")
                return False
            
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Update campaign status
            cursor.execute("""
                UPDATE campaigns 
                SET status = ?, lifecycle_stage = ?, archived_at = ?, 
                    archive_reason = ?, updated_at = ?
                WHERE id = ?
            """, (
                CampaignStatus.ARCHIVED.value,
                LifecycleStage.ARCHIVED.value,
                datetime.now(),
                reason,
                datetime.now(),
                campaign_id
            ))
            
            # Create archive data
            archive_data = self._create_archive_data(cursor, campaign_id)
            
            # Store archive
            cursor.execute("""
                INSERT INTO campaign_archives
                (campaign_id, archive_type, archived_data, archive_size_bytes, 
                 retention_until, archive_location)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                campaign_id,
                "full_archive",
                json.dumps(archive_data),
                len(json.dumps(archive_data)),
                datetime.now() + timedelta(days=self.config["retention_days"]),
                f"campaign_{campaign_id}_archive.json"
            ))
            
            # Create event
            event_type = EventType.AUTO_ARCHIVE if automated else EventType.MANUAL_ARCHIVE
            self._create_event(cursor, CampaignEvent(
                campaign_id=campaign_id,
                event_type=event_type,
                previous_status=campaign.status.value,
                new_status=CampaignStatus.ARCHIVED.value,
                notes=reason,
                automated=automated
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Archived campaign {campaign_id}: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Error archiving campaign {campaign_id}: {e}")
            return False
    
    def restore_campaign(self, campaign_id: int, notes: str = "") -> bool:
        """Restore an archived campaign"""
        try:
            campaign = self.get_campaign(campaign_id)
            if not campaign or campaign.status != CampaignStatus.ARCHIVED:
                logger.error(f"Campaign {campaign_id} not found or not archived")
                return False
            
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Determine new status based on end date
            new_status = CampaignStatus.ACTIVE
            new_stage = LifecycleStage.OPERATIONAL
            
            if campaign.end_date and campaign.end_date < datetime.now():
                new_status = CampaignStatus.ENDED
                new_stage = LifecycleStage.WINDING_DOWN
            
            # Update campaign
            cursor.execute("""
                UPDATE campaigns 
                SET status = ?, lifecycle_stage = ?, archived_at = NULL,
                    archive_reason = '', updated_at = ?
                WHERE id = ?
            """, (new_status.value, new_stage.value, datetime.now(), campaign_id))
            
            # Create event
            self._create_event(cursor, CampaignEvent(
                campaign_id=campaign_id,
                event_type=EventType.RESTORE,
                previous_status=CampaignStatus.ARCHIVED.value,
                new_status=new_status.value,
                notes=notes,
                automated=False
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Restored campaign {campaign_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring campaign {campaign_id}: {e}")
            return False
    
    def check_campaign_statuses(self) -> Dict[str, int]:
        """Check and update campaign statuses based on end dates"""
        results = {
            "updated": 0,
            "warnings_sent": 0,
            "ended": 0
        }
        
        try:
            # Check for campaigns that should be marked as ending soon
            active_campaigns = self.get_campaigns_by_status(CampaignStatus.ACTIVE)
            
            for campaign in active_campaigns:
                if campaign.end_date:
                    days_until_end = (campaign.end_date - datetime.now()).days
                    
                    # Check if campaign has ended
                    if campaign.end_date < datetime.now():
                        self.update_campaign_status(
                            campaign.id,
                            CampaignStatus.ENDED,
                            "Campaign ended based on end date",
                            automated=True
                        )
                        self.update_lifecycle_stage(
                            campaign.id,
                            LifecycleStage.WINDING_DOWN,
                            "Campaign ended - entering winding down phase",
                            automated=True
                        )
                        results["ended"] += 1
                    
                    # Check if campaign is ending soon
                    elif days_until_end <= self.config["warning_days"]:
                        self.update_campaign_status(
                            campaign.id,
                            CampaignStatus.ENDING_SOON,
                            f"Campaign ending in {days_until_end} days",
                            automated=True
                        )
                        results["warnings_sent"] += 1
                    
                    results["updated"] += 1
            
            if results["updated"] > 0:
                logger.info(f"Campaign status check completed: {results}")
                
        except Exception as e:
            logger.error(f"Error checking campaign statuses: {e}")
        
        return results
    
    def auto_archive_ended_campaigns(self) -> int:
        """Automatically archive campaigns that have been ended for a while"""
        archived_count = 0
        
        try:
            ended_campaigns = self.get_campaigns_by_status(CampaignStatus.ENDED)
            archive_threshold = datetime.now() - timedelta(days=self.config["auto_archive_delay"])
            
            for campaign in ended_campaigns:
                if (campaign.auto_archive_enabled and 
                    campaign.end_date and 
                    campaign.end_date < archive_threshold):
                    
                    reason = f"Auto-archived {self.config['auto_archive_delay']} days after end date"
                    if self.archive_campaign(campaign.id, reason, automated=True):
                        archived_count += 1
            
            if archived_count > 0:
                logger.info(f"Auto-archived {archived_count} campaigns")
                
        except Exception as e:
            logger.error(f"Error in auto-archiving: {e}")
        
        return archived_count
    
    def cleanup_old_archives(self) -> int:
        """Clean up old archived data past retention period"""
        cleaned_count = 0
        
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Find expired archives
            cursor.execute("""
                SELECT id, campaign_id, archive_location 
                FROM campaign_archives 
                WHERE retention_until < datetime('now')
            """)
            
            expired_archives = cursor.fetchall()
            
            for archive in expired_archives:
                # Delete archive file if it exists
                archive_path = Path(f"/home/kali/bbhk/data/archives/{archive['archive_location']}")
                if archive_path.exists():
                    archive_path.unlink()
                
                # Delete archive record
                cursor.execute("DELETE FROM campaign_archives WHERE id = ?", (archive["id"],))
                cleaned_count += 1
            
            conn.commit()
            conn.close()
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired archives")
                
        except Exception as e:
            logger.error(f"Error cleaning up archives: {e}")
        
        return cleaned_count
    
    def get_campaign_metrics(self, campaign_id: int) -> Dict[str, Any]:
        """Get campaign performance metrics"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Get basic campaign info
            campaign = self.get_campaign(campaign_id)
            if not campaign:
                return {}
            
            metrics = {
                "campaign_id": campaign_id,
                "campaign_name": campaign.campaign_name,
                "status": campaign.status.value,
                "lifecycle_stage": campaign.lifecycle_stage.value,
                "days_active": 0,
                "programs_count": 0,
                "targets_count": 0,
                "findings_count": 0,
                "reports_count": 0,
                "events_count": 0
            }
            
            # Calculate days active
            if campaign.start_date:
                end_date = campaign.end_date or datetime.now()
                metrics["days_active"] = (end_date - campaign.start_date).days
            
            # Get counts
            cursor.execute("SELECT COUNT(*) FROM programs WHERE campaign_id = ?", (campaign_id,))
            metrics["programs_count"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM targets WHERE campaign_id = ?", (campaign_id,))
            metrics["targets_count"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM findings WHERE campaign_id = ?", (campaign_id,))
            metrics["findings_count"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM reports WHERE campaign_id = ?", (campaign_id,))
            metrics["reports_count"] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM campaign_timeline WHERE campaign_id = ?", (campaign_id,))
            metrics["events_count"] = cursor.fetchone()[0]
            
            conn.close()
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting campaign metrics: {e}")
            return {}
    
    def search_campaigns(self, query: str, filters: Dict[str, Any] = None) -> List[Campaign]:
        """Search campaigns with optional filters"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Build query
            sql = "SELECT * FROM campaigns WHERE 1=1"
            params = []
            
            if query:
                sql += " AND (campaign_name LIKE ? OR handle LIKE ? OR platform LIKE ?)"
                params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])
            
            if filters:
                if "status" in filters:
                    sql += " AND status = ?"
                    params.append(filters["status"])
                
                if "platform" in filters:
                    sql += " AND platform = ?"
                    params.append(filters["platform"])
                
                if "lifecycle_stage" in filters:
                    sql += " AND lifecycle_stage = ?"
                    params.append(filters["lifecycle_stage"])
            
            sql += " ORDER BY updated_at DESC"
            
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            
            conn.close()
            
            return [self._row_to_campaign(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error searching campaigns: {e}")
            return []
    
    def _row_to_campaign(self, row) -> Campaign:
        """Convert database row to Campaign object"""
        return Campaign(
            id=row["id"],
            program_id=row["program_id"],
            campaign_name=row["campaign_name"],
            platform=row["platform"],
            handle=row["handle"],
            start_date=datetime.fromisoformat(row["start_date"]) if row["start_date"] else None,
            end_date=datetime.fromisoformat(row["end_date"]) if row["end_date"] else None,
            estimated_end_date=datetime.fromisoformat(row["estimated_end_date"]) if row["estimated_end_date"] else None,
            status=CampaignStatus(row["status"]),
            submission_state=row["submission_state"],
            lifecycle_stage=LifecycleStage(row["lifecycle_stage"]),
            auto_archive_enabled=bool(row["auto_archive_enabled"]),
            archived_at=datetime.fromisoformat(row["archived_at"]) if row["archived_at"] else None,
            archive_reason=row["archive_reason"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updated_at=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None
        )
    
    def _create_event(self, cursor, event: CampaignEvent):
        """Create a campaign event record"""
        cursor.execute("""
            INSERT INTO campaign_timeline
            (campaign_id, event_type, previous_status, new_status, event_data,
             event_timestamp, automated, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.campaign_id,
            event.event_type.value,
            event.previous_status,
            event.new_status,
            json.dumps(event.event_data),
            event.event_timestamp,
            event.automated,
            event.notes
        ))
    
    def _create_archive_data(self, cursor, campaign_id: int) -> Dict[str, Any]:
        """Create comprehensive archive data for a campaign"""
        archive_data = {
            "archived_at": datetime.now().isoformat(),
            "campaign_id": campaign_id,
            "programs": [],
            "targets": [],
            "findings": [],
            "reports": [],
            "timeline": []
        }
        
        # Get related data
        tables = [
            ("programs", "campaign_id"),
            ("targets", "campaign_id"),
            ("findings", "campaign_id"),
            ("reports", "campaign_id")
        ]
        
        for table, id_column in tables:
            cursor.execute(f"SELECT * FROM {table} WHERE {id_column} = ?", (campaign_id,))
            rows = cursor.fetchall()
            archive_data[table] = [dict(row) for row in rows]
        
        # Get timeline
        cursor.execute("SELECT * FROM campaign_timeline WHERE campaign_id = ?", (campaign_id,))
        timeline_rows = cursor.fetchall()
        archive_data["timeline"] = [dict(row) for row in timeline_rows]
        
        return archive_data
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        if hasattr(self, '_monitoring_thread'):
            self.stop_monitoring()

# Utility functions
def create_campaign_manager(db_path: str = None, auto_monitor: bool = True) -> CampaignManager:
    """Create a campaign manager instance"""
    if db_path is None:
        db_path = "/home/kali/bbhk/core/database/bbhk.db"
    
    return CampaignManager(db_path, auto_monitor)

def main():
    """Main function for testing"""
    manager = create_campaign_manager()
    
    # Test basic functionality
    logger.info("Testing campaign lifecycle manager...")
    
    # Check campaign statuses
    results = manager.check_campaign_statuses()
    logger.info(f"Status check results: {results}")
    
    # Get ending soon campaigns
    ending_soon = manager.get_ending_soon_campaigns()
    logger.info(f"Campaigns ending soon: {len(ending_soon)}")
    
    # Auto archive ended campaigns
    archived = manager.auto_archive_ended_campaigns()
    logger.info(f"Auto-archived campaigns: {archived}")
    
    manager.stop_monitoring()

if __name__ == "__main__":
    main()