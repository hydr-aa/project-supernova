"""Shared test fixtures for Project Supernova."""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from dotenv import load_dotenv

# Load .env for tests
load_dotenv()

from modules.utils.config import load_config
from modules.utils.logger import get_logger
from modules.ldap_client import LDAPClient


@pytest.fixture
def config():
    return load_config("config.yaml")


@pytest.fixture
def logger(config):
    return get_logger(config)


@pytest.fixture
def mock_ldap(config, logger):
    """Return an LDAP client in mock mode for unit tests."""
    return LDAPClient(config, mock=True, logger=logger)
