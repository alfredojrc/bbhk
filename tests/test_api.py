"""Tests for web/backend/main.py API endpoints."""

import sqlite3
import tempfile
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def db_path(tmp_path):
    """Create a test SQLite database with schema and sample data."""
    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    cursor = conn.cursor()

    # Create schema
    cursor.executescript("""
        CREATE TABLE platforms (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        CREATE TABLE programs (
            id INTEGER PRIMARY KEY,
            platform_id INTEGER,
            program_name TEXT,
            program_url TEXT,
            max_bounty REAL DEFAULT 0,
            active INTEGER DEFAULT 1,
            vdp_only INTEGER DEFAULT 0,
            FOREIGN KEY (platform_id) REFERENCES platforms(id)
        );
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY,
            program_id INTEGER,
            asset_identifier TEXT,
            asset_type TEXT,
            in_scope INTEGER DEFAULT 1,
            FOREIGN KEY (program_id) REFERENCES programs(id)
        );
        CREATE TABLE rules (
            id INTEGER PRIMARY KEY,
            scope_type TEXT,
            rule_name TEXT,
            rule_value TEXT
        );

        INSERT INTO platforms (id, name) VALUES (1, 'hackerone');
        INSERT INTO platforms (id, name) VALUES (2, 'bugcrowd');

        INSERT INTO programs (id, platform_id, program_name, program_url, max_bounty)
        VALUES (1, 1, 'Acme Corp', 'https://hackerone.com/acme', 10000);
        INSERT INTO programs (id, platform_id, program_name, program_url, max_bounty)
        VALUES (2, 1, 'Beta Inc', 'https://hackerone.com/beta', 5000);
        INSERT INTO programs (id, platform_id, program_name, program_url, max_bounty, vdp_only)
        VALUES (3, 2, 'Gamma LLC', 'https://bugcrowd.com/gamma', 0, 1);

        INSERT INTO targets (id, program_id, asset_identifier, asset_type, in_scope)
        VALUES (1, 1, '*.acme.com', 'URL', 1);
        INSERT INTO targets (id, program_id, asset_identifier, asset_type, in_scope)
        VALUES (2, 1, 'api.acme.com', 'URL', 1);
        INSERT INTO targets (id, program_id, asset_identifier, asset_type, in_scope)
        VALUES (3, 2, '*.beta.com', 'URL', 1);
    """)
    conn.commit()
    conn.close()
    return str(db)


@pytest.fixture
def client(db_path, monkeypatch):
    """Create a test client with the test database."""
    monkeypatch.setenv("DATABASE_PATH", db_path)

    # Re-import to pick up the new env var
    import importlib
    import web.backend.main as api_module
    importlib.reload(api_module)

    return TestClient(api_module.app)


class TestRootEndpoint:
    def test_root(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "BBHK Dashboard API"
        assert data["status"] == "operational"
        assert "timestamp" in data


class TestStatsEndpoint:
    def test_get_stats(self, client):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_programs"] == 3
        assert data["programs_with_bounties"] == 2
        assert data["total_targets"] == 3


class TestProgramsEndpoint:
    def test_get_programs(self, client):
        response = client.get("/api/programs")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
        # Should be ordered by max_bounty DESC
        assert data[0]["name"] == "Acme Corp"

    def test_get_programs_with_limit(self, client):
        response = client.get("/api/programs?limit=1")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1

    def test_get_programs_with_offset(self, client):
        response = client.get("/api/programs?offset=2")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1

    def test_get_programs_search(self, client):
        response = client.get("/api/programs?search=Acme")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "Acme Corp"

    def test_get_programs_filter_platform(self, client):
        response = client.get("/api/programs?platform=bugcrowd")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "Gamma LLC"

    def test_get_programs_filter_bounty(self, client):
        response = client.get("/api/programs?has_bounty=true")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_get_programs_validation_limit_too_high(self, client):
        response = client.get("/api/programs?limit=5000")
        assert response.status_code == 422

    def test_get_programs_validation_limit_zero(self, client):
        response = client.get("/api/programs?limit=0")
        assert response.status_code == 422

    def test_get_programs_validation_negative_offset(self, client):
        response = client.get("/api/programs?offset=-1")
        assert response.status_code == 422

    def test_get_programs_validation_search_too_long(self, client):
        response = client.get(f"/api/programs?search={'x' * 201}")
        assert response.status_code == 422


class TestProgramDetailEndpoint:
    def test_get_program(self, client):
        response = client.get("/api/programs/1")
        assert response.status_code == 200
        data = response.json()
        assert data["program_name"] == "Acme Corp"
        assert len(data["targets"]) == 2

    def test_get_program_not_found(self, client):
        response = client.get("/api/programs/999")
        assert response.status_code == 404


class TestSearchEndpoint:
    def test_search(self, client):
        response = client.get("/api/search?q=acme")
        assert response.status_code == 200
        data = response.json()
        assert len(data["programs"]) >= 1
        assert len(data["targets"]) >= 1

    def test_search_no_results(self, client):
        response = client.get("/api/search?q=nonexistent")
        assert response.status_code == 200
        data = response.json()
        assert len(data["programs"]) == 0
        assert len(data["targets"]) == 0


class TestTargetsEndpoint:
    def test_get_all_targets(self, client):
        response = client.get("/api/targets")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3

    def test_get_targets_by_program(self, client):
        response = client.get("/api/targets?program_id=1")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
