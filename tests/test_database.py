"""Tests for src/core/database.py."""

import pytest
from sqlalchemy import inspect

from src.core.database import DatabaseManager, Program, Scan, Vulnerability, Report, AuditLog, Base


class TestDatabaseManager:
    def setup_method(self):
        self.db = DatabaseManager()
        self.db.init_db("sqlite:///")  # in-memory database

    def test_init_creates_tables(self):
        inspector = inspect(self.db.engine)
        table_names = inspector.get_table_names()
        assert "programs" in table_names
        assert "scans" in table_names
        assert "vulnerabilities" in table_names
        assert "reports" in table_names
        assert "audit_logs" in table_names

    def test_session_scope_commit(self):
        with self.db.session_scope() as session:
            prog = Program(
                name="Test Program",
                platform="hackerone",
                url="https://hackerone.com/test",
            )
            session.add(prog)

        # Verify committed
        with self.db.session_scope() as session:
            result = session.query(Program).filter_by(name="Test Program").first()
            assert result is not None
            assert result.platform == "hackerone"

    def test_session_scope_rollback_on_error(self):
        try:
            with self.db.session_scope() as session:
                prog = Program(
                    name="Rollback Test",
                    platform="bugcrowd",
                    url="https://bugcrowd.com/test",
                )
                session.add(prog)
                raise ValueError("Simulated error")
        except ValueError:
            pass

        # Verify rolled back
        with self.db.session_scope() as session:
            result = session.query(Program).filter_by(name="Rollback Test").first()
            assert result is None

    def test_get_session(self):
        session = self.db.get_session()
        assert session is not None
        session.close()


class TestProgramModel:
    def setup_method(self):
        self.db = DatabaseManager()
        self.db.init_db("sqlite:///")

    def test_create_program(self):
        with self.db.session_scope() as session:
            prog = Program(
                name="Acme Corp",
                platform="hackerone",
                url="https://hackerone.com/acme",
                status="active",
                min_bounty=100.0,
                max_bounty=10000.0,
            )
            session.add(prog)

        with self.db.session_scope() as session:
            result = session.query(Program).first()
            assert result.name == "Acme Corp"
            assert result.status == "active"
            assert result.min_bounty == 100.0

    def test_program_defaults(self):
        with self.db.session_scope() as session:
            prog = Program(
                name="Default Test",
                platform="bugcrowd",
                url="https://bugcrowd.com/default",
            )
            session.add(prog)

        with self.db.session_scope() as session:
            result = session.query(Program).first()
            assert result.status == "active"
            assert result.min_bounty == 0.0
            assert result.reports_resolved == 0


class TestVulnerabilityModel:
    def setup_method(self):
        self.db = DatabaseManager()
        self.db.init_db("sqlite:///")

    def test_create_vulnerability(self):
        with self.db.session_scope() as session:
            prog = Program(
                name="Test", platform="hackerone", url="https://test.com"
            )
            session.add(prog)
            session.flush()

            scan = Scan(
                program_id=prog.id,
                scan_type="vulnerability",
                target="https://test.com/search",
            )
            session.add(scan)
            session.flush()

            vuln = Vulnerability(
                scan_id=scan.id,
                title="XSS in search",
                vulnerability_type="xss",
                severity="high",
                url="https://test.com/search",
            )
            session.add(vuln)

        with self.db.session_scope() as session:
            result = session.query(Vulnerability).first()
            assert result.title == "XSS in search"
            assert result.severity == "high"
            assert result.verified is False


class TestAuditLogModel:
    def setup_method(self):
        self.db = DatabaseManager()
        self.db.init_db("sqlite:///")

    def test_create_audit_log(self):
        with self.db.session_scope() as session:
            log = AuditLog(
                action="scan_started",
                resource_type="scan",
                resource_id=1,
                compliant=True,
            )
            session.add(log)

        with self.db.session_scope() as session:
            result = session.query(AuditLog).first()
            assert result.action == "scan_started"
            assert result.compliant is True
