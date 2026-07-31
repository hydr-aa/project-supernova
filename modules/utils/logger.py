"""Structured JSON-line logger with file rotation.

Usage:
    from modules.utils.logger import get_logger
    logger = get_logger(config)
    logger.info("audit_started", domain="supernova.vulnlab")
"""

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path


class JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.name,
        }
        if hasattr(record, "extra_data"):
            entry.update(record.extra_data)
        return json.dumps(entry, default=str)


def _log_with_extra(logger, level, msg, **kwargs):
    """Wrapper that puts extra keyword args into record.extra_data."""
    extra_data = kwargs.pop("extra_data", {})
    logger.log(level, msg, extra={"extra_data": extra_data}, **kwargs)


def get_logger(config):
    log_cfg = config.get("logging", {})
    level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
    log_file = log_cfg.get("file", "./logs/supernova.log")
    max_mb = log_cfg.get("max_size_mb", 10)
    backups = log_cfg.get("backup_count", 3)

    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("supernova")
    logger.setLevel(level)
    logger.handlers.clear()

    handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_mb * 1024 * 1024,
        backupCount=backups,
        encoding="utf-8",
    )
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

    # Also log to console
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(console)

    # Patch logger to support extra_data kwarg
    original_info = logger.info
    original_warning = logger.warning
    original_error = logger.error

    def patched_info(msg, *args, **kwargs):
        extra_data = kwargs.pop("extra_data", {})
        original_info(msg, *args, extra={"extra_data": extra_data}, **kwargs)

    def patched_warning(msg, *args, **kwargs):
        extra_data = kwargs.pop("extra_data", {})
        original_warning(msg, *args, extra={"extra_data": extra_data}, **kwargs)

    def patched_error(msg, *args, **kwargs):
        extra_data = kwargs.pop("extra_data", {})
        original_error(msg, *args, extra={"extra_data": extra_data}, **kwargs)

    logger.info = patched_info
    logger.warning = patched_warning
    logger.error = patched_error

    return logger
