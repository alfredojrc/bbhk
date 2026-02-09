"""Database models and connection management."""

import asyncio
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Generator, AsyncGenerator
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean,
    Text, Float, JSON, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from loguru import logger

from .config import config

Base = declarative_base()

class Program(Base):
    """Bug bounty program model."""
    __tablename__ = 'programs'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    platform = Column(String(50), nullable=False)  # hackerone, bugcrowd, etc.
    url = Column(String(500), nullable=False)
    status = Column(String(20), default='active')  # active, paused, closed
    
    # Program details
    company = Column(String(200))
    description = Column(Text)
    scope = Column(JSON)  # List of in-scope domains/endpoints
    out_of_scope = Column(JSON)  # List of out-of-scope items
    
    # Bounty information
    min_bounty = Column(Float, default=0.0)
    max_bounty = Column(Float, default=0.0)
    avg_bounty = Column(Float, default=0.0)
    
    # Statistics
    reports_resolved = Column(Integer, default=0)
    reports_submitted = Column(Integer, default=0)
    response_time_avg = Column(Float)  # hours
    
    # Tracking
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_checked = Column(DateTime)
    
    # Relationships
    scans = relationship("Scan", back_populates="program")
    reports = relationship("Report", back_populates="program")
    
    __table_args__ = (
        UniqueConstraint('platform', 'url', name='unique_program_url'),
        Index('idx_program_status', 'status'),
        Index('idx_program_platform', 'platform'),
    )

class Scan(Base):
    """Scan execution model."""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    program_id = Column(Integer, ForeignKey('programs.id'), nullable=False)
    
    # Scan configuration
    scan_type = Column(String(50), nullable=False)  # subdomain, port, vulnerability
    target = Column(String(500), nullable=False)
    parameters = Column(JSON)
    
    # Execution details
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration = Column(Float)  # seconds
    
    # Results
    findings_count = Column(Integer, default=0)
    findings = Column(JSON)  # List of findings
    raw_output = Column(Text)
    
    # Compliance
    compliance_checked = Column(Boolean, default=False)
    rate_limited = Column(Boolean, default=False)
    
    # Relationships
    program = relationship("Program", back_populates="scans")
    
    __table_args__ = (
        Index('idx_scan_status', 'status'),
        Index('idx_scan_program', 'program_id'),
    )

class Vulnerability(Base):
    """Discovered vulnerability model."""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    
    # Vulnerability details
    title = Column(String(200), nullable=False)
    description = Column(Text)
    vulnerability_type = Column(String(100))  # XSS, SQLi, CSRF, etc.
    severity = Column(String(20))  # low, medium, high, critical
    cvss_score = Column(Float)
    
    # Location
    url = Column(String(1000))
    parameter = Column(String(200))
    payload = Column(Text)
    
    # Evidence
    screenshot_path = Column(String(500))
    video_path = Column(String(500))
    proof_of_concept = Column(Text)
    
    # Analysis
    confidence = Column(Float, default=0.0)  # 0-1
    false_positive_probability = Column(Float, default=0.0)
    exploitability = Column(String(20))  # low, medium, high
    
    # Status
    verified = Column(Boolean, default=False)
    reported = Column(Boolean, default=False)
    
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    scan = relationship("Scan")
    reports = relationship("Report", back_populates="vulnerability")
    
    __table_args__ = (
        Index('idx_vuln_severity', 'severity'),
        Index('idx_vuln_type', 'vulnerability_type'),
        Index('idx_vuln_reported', 'reported'),
    )

class Report(Base):
    """Bug report model."""
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True)
    program_id = Column(Integer, ForeignKey('programs.id'), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'), nullable=False)
    
    # Report details
    title = Column(String(200), nullable=False)
    description = Column(Text)
    impact = Column(Text)
    reproduction_steps = Column(Text)
    
    # Submission
    platform_report_id = Column(String(100))  # External platform ID
    submitted_at = Column(DateTime)
    status = Column(String(20), default='draft')  # draft, submitted, accepted, rejected
    
    # Response tracking
    first_response_at = Column(DateTime)
    resolution_at = Column(DateTime)
    bounty_amount = Column(Float)
    
    # Files
    attachments = Column(JSON)  # List of file paths
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    program = relationship("Program", back_populates="reports")
    vulnerability = relationship("Vulnerability", back_populates="reports")
    
    __table_args__ = (
        Index('idx_report_status', 'status'),
        Index('idx_report_program', 'program_id'),
    )

class AuditLog(Base):
    """Audit trail for compliance."""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    
    # Event details
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))  # program, scan, report
    resource_id = Column(Integer)
    
    # Context
    user_agent = Column(String(500))
    ip_address = Column(String(45))
    target_url = Column(String(1000))
    
    # Data
    before_state = Column(JSON)
    after_state = Column(JSON)
    extra_data = Column("metadata", JSON)
    
    # Compliance
    compliant = Column(Boolean, default=True)
    compliance_notes = Column(Text)
    
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (
        Index('idx_audit_action', 'action'),
        Index('idx_audit_timestamp', 'timestamp'),
    )

class DatabaseManager:
    """Database connection and session management."""
    
    def __init__(self):
        """Initialize database manager."""
        self.engine = None
        self.SessionLocal = None
        self.async_engine = None
        self.AsyncSessionLocal = None
        
    def init_db(self, db_url: Optional[str] = None):
        """Initialize database connection."""
        db_url = db_url or config.database.url
        
        # Synchronous engine (SQLite doesn't support pool_size/max_overflow)
        engine_kwargs = {"echo": config.database.echo}
        if not db_url.startswith("sqlite"):
            engine_kwargs["pool_size"] = config.database.pool_size
            engine_kwargs["max_overflow"] = config.database.max_overflow
        self.engine = create_engine(db_url, **engine_kwargs)
        
        # Async engine for async operations
        if db_url.startswith('sqlite:'):
            async_url = db_url.replace('sqlite:', 'sqlite+aiosqlite:')
        else:
            async_url = db_url
            
        self.async_engine = create_async_engine(async_url)
        
        # Session factories
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.AsyncSessionLocal = async_sessionmaker(
            bind=self.async_engine, 
            class_=AsyncSession
        )
        
        # Create tables
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database initialized successfully")
    
    def get_session(self) -> Session:
        """Get synchronous database session (raw, caller must close)."""
        return self.SessionLocal()

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """Context manager for synchronous database sessions.

        Usage:
            with db_manager.session_scope() as session:
                session.query(Program).all()
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_async_session(self) -> AsyncSession:
        """Get asynchronous database session (raw, caller must close)."""
        return self.AsyncSessionLocal()

    @asynccontextmanager
    async def async_session_scope(self) -> AsyncGenerator[AsyncSession, None]:
        """Context manager for asynchronous database sessions.

        Usage:
            async with db_manager.async_session_scope() as session:
                await session.execute(select(Program))
        """
        session = self.AsyncSessionLocal()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def close(self):
        """Close database connections."""
        if self.async_engine:
            await self.async_engine.dispose()
        if self.engine:
            self.engine.dispose()

# Global database manager
db_manager = DatabaseManager()

# Convenience functions
def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for database sessions."""
    with db_manager.session_scope() as session:
        yield session

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for async database sessions."""
    async with db_manager.async_session_scope() as session:
        yield session