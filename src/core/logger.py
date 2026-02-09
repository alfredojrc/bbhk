"""Logging configuration and utilities."""

import sys
from pathlib import Path
from loguru import logger
from .config import config

def setup_logging(log_level: str = "INFO", log_file: str = "logs/bbhk.log"):
    """Configure logging for the application."""
    
    # Remove default handler
    logger.remove()
    
    # Create logs directory
    log_path = Path(log_file)
    log_path.parent.mkdir(exist_ok=True)
    
    # Console handler with color
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=log_level,
        colorize=True
    )
    
    # File handler
    logger.add(
        log_file,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level="DEBUG",
        rotation="10 MB",
        retention="30 days",
        compression="gz"
    )
    
    # Audit log handler for compliance
    if config.compliance.audit_trail_enabled:
        logger.add(
            "logs/audit.log",
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | AUDIT | {extra[action]} | {extra[resource]} | {message}",
            level="INFO",
            filter=lambda record: "audit" in record["extra"],
            rotation="daily",
            retention="1 year",
            compression="gz"
        )

def get_audit_logger():
    """Get logger specifically for audit trail."""
    return logger.bind(audit=True)

# Deferred initialization - call setup_logging() explicitly from main.py