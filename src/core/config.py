"""Configuration management for the bug bounty framework."""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    url: str = "sqlite:///bbhk.db"
    echo: bool = False
    pool_size: int = 10
    max_overflow: int = 20

@dataclass
class MonitorConfig:
    """Program monitoring configuration."""
    hackerone_enabled: bool = True
    bugcrowd_enabled: bool = True
    intigriti_enabled: bool = True
    yeswehack_enabled: bool = True
    check_interval: int = 300  # seconds
    max_concurrent_requests: int = 5
    request_delay_min: float = 1.0
    request_delay_max: float = 3.0

@dataclass
class ScannerConfig:
    """Scanner configuration settings."""
    max_concurrent_scans: int = 3
    default_timeout: int = 30
    max_retries: int = 3
    user_agents: list = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ])
    proxy_rotation: bool = True
    stealth_mode: bool = True

@dataclass
class ComplianceConfig:
    """Compliance and safety configuration."""
    enable_kill_switch: bool = True
    max_requests_per_minute: int = 60
    respect_robots_txt: bool = True
    require_scope_validation: bool = True
    audit_trail_enabled: bool = True
    emergency_contact: Optional[str] = None

@dataclass
class AnalyticsConfig:
    """Analytics and ROI calculation settings."""
    ml_model_path: str = "models/"
    enable_ml_predictions: bool = True
    min_confidence_threshold: float = 0.7
    roi_calculation_method: str = "weighted"  # weighted, simple, complex

@dataclass
class ReportingConfig:
    """Report generation settings."""
    template_dir: str = "templates/"
    output_dir: str = "reports/"
    auto_screenshot: bool = True
    video_poc_enabled: bool = True
    max_report_size_mb: int = 25

class Config:
    """Main configuration class."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration from file or environment."""
        self.config_file = config_file or os.getenv('BBHK_CONFIG', 'config.json')
        
        # Initialize sub-configurations
        self.database = DatabaseConfig()
        self.monitor = MonitorConfig()
        self.scanner = ScannerConfig()
        self.compliance = ComplianceConfig()
        self.analytics = AnalyticsConfig()
        self.reporting = ReportingConfig()
        
        # Load custom configuration
        self._load_config()
        
        # Override with environment variables
        self._load_env_overrides()
    
    def _load_config(self):
        """Load configuration from JSON file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Update configurations
                for section, values in config_data.items():
                    if hasattr(self, section):
                        config_obj = getattr(self, section)
                        for key, value in values.items():
                            if hasattr(config_obj, key):
                                setattr(config_obj, key, value)
            except Exception as e:
                print(f"Warning: Could not load config file {self.config_file}: {e}")
    
    def _load_env_overrides(self):
        """Override configuration with environment variables."""
        env_mapping = {
            'BBHK_DB_URL': ('database', 'url'),
            'BBHK_MONITOR_INTERVAL': ('monitor', 'check_interval'),
            'BBHK_MAX_CONCURRENT_SCANS': ('scanner', 'max_concurrent_scans'),
            'BBHK_KILL_SWITCH': ('compliance', 'enable_kill_switch'),
            'BBHK_EMERGENCY_CONTACT': ('compliance', 'emergency_contact'),
        }
        
        for env_var, (section, key) in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                config_obj = getattr(self, section)
                # Type conversion based on current value type
                current_value = getattr(config_obj, key)
                if isinstance(current_value, bool):
                    value = value.lower() in ('true', '1', 'yes')
                elif isinstance(current_value, int):
                    value = int(value)
                elif isinstance(current_value, float):
                    value = float(value)
                setattr(config_obj, key, value)
    
    def save_config(self, filepath: Optional[str] = None):
        """Save current configuration to file."""
        filepath = filepath or self.config_file
        
        config_data = {
            'database': self.database.__dict__,
            'monitor': self.monitor.__dict__,
            'scanner': self.scanner.__dict__,
            'compliance': self.compliance.__dict__,
            'analytics': self.analytics.__dict__,
            'reporting': self.reporting.__dict__,
        }
        
        with open(filepath, 'w') as f:
            json.dump(config_data, f, indent=2)
    
    @property
    def is_safe_mode(self) -> bool:
        """Check if framework is in safe mode."""
        return (self.compliance.enable_kill_switch and 
                self.compliance.require_scope_validation and
                self.compliance.respect_robots_txt)

# Global configuration instance
config = Config()