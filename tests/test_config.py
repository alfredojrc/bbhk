"""Tests for src/core/config.py."""

import json
import os
import tempfile

import pytest

from src.core.config import Config, DatabaseConfig, MonitorConfig, ComplianceConfig


class TestDatabaseConfig:
    def test_defaults(self):
        cfg = DatabaseConfig()
        assert cfg.url == "sqlite:///bbhk.db"
        assert cfg.echo is False
        assert cfg.pool_size == 10
        assert cfg.max_overflow == 20


class TestMonitorConfig:
    def test_defaults(self):
        cfg = MonitorConfig()
        assert cfg.hackerone_enabled is True
        assert cfg.check_interval == 300
        assert cfg.max_concurrent_requests == 5


class TestComplianceConfig:
    def test_defaults(self):
        cfg = ComplianceConfig()
        assert cfg.enable_kill_switch is True
        assert cfg.respect_robots_txt is True
        assert cfg.emergency_contact is None


class TestConfig:
    def test_default_initialization(self):
        cfg = Config()
        assert isinstance(cfg.database, DatabaseConfig)
        assert isinstance(cfg.monitor, MonitorConfig)
        assert isinstance(cfg.compliance, ComplianceConfig)

    def test_is_safe_mode(self):
        cfg = Config()
        assert cfg.is_safe_mode is True

        cfg.compliance.enable_kill_switch = False
        assert cfg.is_safe_mode is False

    def test_load_from_json(self, tmp_path):
        config_data = {
            "database": {"url": "sqlite:///test.db", "echo": True},
            "monitor": {"check_interval": 600},
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        cfg = Config(config_file=str(config_file))
        assert cfg.database.url == "sqlite:///test.db"
        assert cfg.database.echo is True
        assert cfg.monitor.check_interval == 600

    def test_load_missing_config_file(self):
        cfg = Config(config_file="/nonexistent/config.json")
        # Should not raise, just use defaults
        assert cfg.database.url == "sqlite:///bbhk.db"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("BBHK_DB_URL", "postgresql://localhost/test")
        monkeypatch.setenv("BBHK_MONITOR_INTERVAL", "120")
        monkeypatch.setenv("BBHK_KILL_SWITCH", "false")

        cfg = Config(config_file="/nonexistent/config.json")
        assert cfg.database.url == "postgresql://localhost/test"
        assert cfg.monitor.check_interval == 120
        assert cfg.compliance.enable_kill_switch is False

    def test_save_config(self, tmp_path):
        cfg = Config(config_file="/nonexistent/config.json")
        cfg.database.url = "sqlite:///saved.db"

        output = tmp_path / "saved_config.json"
        cfg.save_config(str(output))

        loaded = json.loads(output.read_text())
        assert loaded["database"]["url"] == "sqlite:///saved.db"
        assert "monitor" in loaded
        assert "compliance" in loaded
