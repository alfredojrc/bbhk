"""
SQLite Database Persistence Layer
Handles storing and retrieving program data from SQLite database
"""

import sqlite3
import json
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from contextlib import contextmanager
import logging
logger = logging.getLogger(__name__)


class DatabasePersistence:
    """SQLite persistence layer for bug bounty data"""
    
    def __init__(self, db_path: str = "core/database/bbhk.db"):
        self.db_path = db_path
        self.conn = None
        
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def get_or_create_platform(self, platform_name: str) -> int:
        """Get or create platform ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if platform exists
            cursor.execute("SELECT id FROM platforms WHERE name = ?", (platform_name,))
            result = cursor.fetchone()
            
            if result:
                return result[0]
            
            # Create new platform
            cursor.execute("""
                INSERT INTO platforms (name, api_type, auth_type, rate_limit, enabled)
                VALUES (?, ?, ?, ?, ?)
            """, (platform_name, 'rest', 'oauth2', 600, 1))
            
            return cursor.lastrowid
    
    def upsert_program(self, program_data: Dict[str, Any]) -> int:
        """Insert or update program in database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get platform ID
            platform_id = self.get_or_create_platform(program_data.get('platform', 'hackerone'))
            
            # Check if program exists
            cursor.execute("""
                SELECT id FROM programs 
                WHERE platform_id = ? AND program_name = ?
            """, (platform_id, program_data.get('name', '')))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing program
                program_id = existing[0]
                cursor.execute("""
                    UPDATE programs SET
                        program_url = ?,
                        min_bounty = ?,
                        max_bounty = ?,
                        scope_updated = ?,
                        allows_disclosure = ?,
                        vdp_only = ?,
                        active = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (
                    program_data.get('url', ''),
                    0,  # min_bounty
                    program_data.get('max_bounty', 0),
                    datetime.utcnow(),
                    program_data.get('allows_private_disclosure', False),
                    not program_data.get('offers_bounties', True),
                    program_data.get('submission_state', 'open') == 'open',
                    program_id
                ))
                logger.debug(f"Updated program: {program_data.get('name')}")
            else:
                # Insert new program
                cursor.execute("""
                    INSERT INTO programs (
                        platform_id, program_name, program_url, 
                        min_bounty, max_bounty, scope_updated,
                        allows_disclosure, vdp_only, active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    platform_id,
                    program_data.get('name', ''),
                    program_data.get('url', ''),
                    0,  # min_bounty
                    program_data.get('max_bounty', 0),
                    datetime.utcnow(),
                    program_data.get('allows_private_disclosure', False),
                    not program_data.get('offers_bounties', True),
                    program_data.get('submission_state', 'open') == 'open'
                ))
                program_id = cursor.lastrowid
                logger.info(f"Created new program: {program_data.get('name')}")
            
            return program_id
    
    def upsert_targets(self, program_id: int, scope_data: List[Dict[str, Any]]) -> int:
        """Insert or update targets for a program"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            targets_created = 0
            
            # Clear existing targets for this program (to handle removed scopes)
            cursor.execute("UPDATE targets SET in_scope = 0 WHERE program_id = ?", (program_id,))
            
            for asset in scope_data:
                asset_type = asset.get('asset_type', 'unknown')
                asset_identifier = asset.get('asset_identifier', '')
                
                if not asset_identifier:
                    continue
                
                # Map asset types
                if asset_type in ['URL', 'url', 'website']:
                    asset_type = 'domain'
                elif asset_type in ['CIDR', 'IP_ADDRESS']:
                    asset_type = 'ip'
                elif asset_type in ['MOBILE_APP', 'ANDROID_APP', 'IOS_APP']:
                    asset_type = 'mobile_app'
                elif asset_type in ['API']:
                    asset_type = 'api'
                
                # Check if target exists
                cursor.execute("""
                    SELECT id FROM targets 
                    WHERE program_id = ? AND asset_identifier = ?
                """, (program_id, asset_identifier))
                
                existing = cursor.fetchone()
                
                severity = asset.get('max_severity', 'high')
                if severity not in ['critical', 'high', 'medium', 'low']:
                    severity = 'high'
                
                if existing:
                    # Update existing target
                    cursor.execute("""
                        UPDATE targets SET
                            asset_type = ?,
                            severity_rating = ?,
                            in_scope = ?,
                            last_scanned = NULL
                        WHERE id = ?
                    """, (asset_type, severity, 1, existing[0]))
                else:
                    # Insert new target
                    cursor.execute("""
                        INSERT INTO targets (
                            program_id, asset_type, asset_identifier,
                            severity_rating, in_scope
                        ) VALUES (?, ?, ?, ?, ?)
                    """, (program_id, asset_type, asset_identifier, severity, 1))
                    targets_created += 1
            
            logger.debug(f"Updated targets for program {program_id}: {targets_created} new")
            return targets_created
    
    def store_customer_correlation(self, customer_data: Dict[str, Any]):
        """Store customer correlation data"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Store in rules table as customer correlation rules
            cursor.execute("""
                INSERT OR REPLACE INTO rules (
                    scope_type, scope_id, rule_name, rule_value, priority, enabled
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                'customer',
                0,  # No specific scope_id for customer rules
                f"customer_{customer_data['customer_id']}",
                json.dumps({
                    'name': customer_data['name'],
                    'domains': customer_data.get('domains', []),
                    'programs': customer_data.get('programs', {}),
                    'bounty_thresholds': customer_data.get('bounty_thresholds', {})
                }),
                1,
                1
            ))
            
            logger.debug(f"Stored customer correlation: {customer_data['customer_id']}")
    
    def get_programs_by_platform(self, platform: str) -> List[Dict[str, Any]]:
        """Get all programs for a platform"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT p.*, pl.name as platform_name,
                       COUNT(DISTINCT t.id) as target_count
                FROM programs p
                JOIN platforms pl ON p.platform_id = pl.id
                LEFT JOIN targets t ON p.id = t.program_id AND t.in_scope = 1
                WHERE pl.name = ? AND p.active = 1
                GROUP BY p.id
            """, (platform,))
            
            programs = []
            for row in cursor.fetchall():
                programs.append(dict(row))
            
            return programs
    
    def get_targets_by_program(self, program_id: int) -> List[Dict[str, Any]]:
        """Get all targets for a program"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM targets
                WHERE program_id = ? AND in_scope = 1
                ORDER BY severity_rating, asset_type
            """, (program_id,))
            
            targets = []
            for row in cursor.fetchall():
                targets.append(dict(row))
            
            return targets
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Total programs
            cursor.execute("SELECT COUNT(*) FROM programs WHERE active = 1")
            stats['total_programs'] = cursor.fetchone()[0]
            
            # Programs by platform
            cursor.execute("""
                SELECT pl.name, COUNT(p.id) as count
                FROM programs p
                JOIN platforms pl ON p.platform_id = pl.id
                WHERE p.active = 1
                GROUP BY pl.id
            """)
            stats['programs_by_platform'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Total targets
            cursor.execute("SELECT COUNT(*) FROM targets WHERE in_scope = 1")
            stats['total_targets'] = cursor.fetchone()[0]
            
            # Targets by type
            cursor.execute("""
                SELECT asset_type, COUNT(*) as count
                FROM targets
                WHERE in_scope = 1
                GROUP BY asset_type
            """)
            stats['targets_by_type'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Programs with bounties
            cursor.execute("SELECT COUNT(*) FROM programs WHERE max_bounty > 0")
            stats['programs_with_bounties'] = cursor.fetchone()[0]
            
            # Average max bounty
            cursor.execute("SELECT AVG(max_bounty) FROM programs WHERE max_bounty > 0")
            result = cursor.fetchone()[0]
            stats['average_max_bounty'] = round(result, 2) if result else 0
            
            # Customer correlations
            cursor.execute("SELECT COUNT(*) FROM rules WHERE scope_type = 'customer'")
            stats['customer_correlations'] = cursor.fetchone()[0]
            
            return stats
    
    def search_programs(self, query: str, platform: Optional[str] = None,
                       min_bounty: Optional[float] = None) -> List[Dict[str, Any]]:
        """Search programs with filters"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            sql = """
                SELECT p.*, pl.name as platform_name,
                       COUNT(DISTINCT t.id) as target_count
                FROM programs p
                JOIN platforms pl ON p.platform_id = pl.id
                LEFT JOIN targets t ON p.id = t.program_id AND t.in_scope = 1
                WHERE p.active = 1
            """
            
            params = []
            
            if query:
                sql += " AND (p.program_name LIKE ? OR p.program_url LIKE ?)"
                params.extend([f"%{query}%", f"%{query}%"])
            
            if platform:
                sql += " AND pl.name = ?"
                params.append(platform)
            
            if min_bounty:
                sql += " AND p.max_bounty >= ?"
                params.append(min_bounty)
            
            sql += " GROUP BY p.id ORDER BY p.max_bounty DESC"
            
            cursor.execute(sql, params)
            
            programs = []
            for row in cursor.fetchall():
                programs.append(dict(row))
            
            return programs
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old data from database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Delete old sessions
            cursor.execute("""
                DELETE FROM sessions 
                WHERE ended_at < datetime('now', '-' || ? || ' days')
            """, (days,))
            
            deleted_sessions = cursor.rowcount
            
            # Delete old metrics
            cursor.execute("""
                DELETE FROM metrics
                WHERE recorded_at < datetime('now', '-' || ? || ' days')
            """, (days,))
            
            deleted_metrics = cursor.rowcount
            
            logger.info(f"Cleaned up {deleted_sessions} sessions and {deleted_metrics} metrics")
            
            return {
                'deleted_sessions': deleted_sessions,
                'deleted_metrics': deleted_metrics
            }