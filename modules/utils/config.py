"""Configuration loader — reads config.yaml with environment variable substitution.

Usage:
    from modules.utils.config import load_config
    cfg = load_config("config.yaml")
    print(cfg["ldap"]["server"])
"""

import os
import yaml
from pathlib import Path


def load_config(config_path="config.yaml"):
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path.absolute()}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    return _resolve_env_vars(raw)


def _resolve_env_vars(obj):
    """Recursively resolve 'env:VAR_NAME' strings to environment variables."""
    if isinstance(obj, dict):
        return {k: _resolve_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_env_vars(item) for item in obj]
    if isinstance(obj, str) and obj.startswith("env:"):
        var_name = obj[4:]
        value = os.environ.get(var_name)
        if value is None:
            raise ValueError(
                f"Environment variable '{var_name}' is not set. "
                f"Create a .env file or export the variable."
            )
        return value
    return obj
