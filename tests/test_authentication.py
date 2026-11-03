"""
test_authentication.py - Unit and Integration Tests for Authentication & Session Lifecycle
PS-007: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
"""

import os
import sys
import tempfile
import time
import pytest

# Add backend and simulation directories to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "simulation")))

import database
from database import init_db, DatabaseManager, get_db_connection
from pseudonym_manager import PseudonymManager
from session_manager import SessionManager

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Create an isolated test database for each test run."""
    db_file = str(tmp_path / "test_auth.db")
    database.DB_PATH = db_file
    init_db(db_file)
    DatabaseManager.seed_initial_devices("tenant-alpha")
    yield
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except Exception:
            pass

def test_device_authentication_success():
    """Verify that a device can authenticate and receives a valid token and pseudonym."""
    pseudo_mgr = PseudonymManager(default_ttl_seconds=60)
    sess_mgr = SessionManager(pseudonym_mgr=pseudo_mgr, session_ttl_seconds=60)

    auth_res = sess_mgr.authenticate_device(
        tenant_id="tenant-alpha",
        device_id="dev-camera-01",
        ipv6_address="2001:db8:1::101",
        secret="secret_camera_key_7a9f",
        custom_pseudonym="DEV-P01"
    )

    assert auth_res["status"] == "SUCCESS"
    assert auth_res["device_id"] == "dev-camera-01"
    assert auth_res["pseudonym"] == "DEV-P01"
    assert auth_res["session_token"].startswith("tok_")
    assert auth_res["expires_at"] > time.time()

    # Verify device record was updated
    dev = DatabaseManager.get_device("dev-camera-01", "tenant-alpha")
    assert dev is not None
    assert dev["status"] == "AUTHENTICATED"
    assert dev["pseudonym"] == "DEV-P01"

def test_token_hash_stored_not_raw_token():
    """Verify raw session tokens are hashed with SHA-256 in the database."""
    pseudo_mgr = PseudonymManager(default_ttl_seconds=60)
    sess_mgr = SessionManager(pseudonym_mgr=pseudo_mgr, session_ttl_seconds=60)

    auth_res = sess_mgr.authenticate_device(
        tenant_id="tenant-alpha",
        device_id="dev-bulb-03",
        ipv6_address="2001:db8:1::103",
        secret="secret_bulb_key_9e1d"
    )

    raw_token = auth_res["session_token"]
    session_id = auth_res["session_id"]

    conn = get_db_connection()
    row = conn.execute("SELECT token_hash FROM sessions WHERE id = ?", (session_id,)).fetchone()
    conn.close()

    assert row is not None
    assert row["token_hash"] != raw_token
    assert len(row["token_hash"]) == 64  # SHA-256 hex length

def test_session_validation():
    """Verify valid tokens authenticate and forged tokens are rejected."""
    pseudo_mgr = PseudonymManager(default_ttl_seconds=60)
    sess_mgr = SessionManager(pseudonym_mgr=pseudo_mgr, session_ttl_seconds=60)

    auth_res = sess_mgr.authenticate_device(
        tenant_id="tenant-alpha",
        device_id="dev-tv-02",
        ipv6_address="2001:db8:1::102",
        secret="secret_tv_key_4b2c"
    )

    # Valid token passes
    valid_session = sess_mgr.validate_session(
        tenant_id="tenant-alpha",
        session_id=auth_res["session_id"],
        session_token=auth_res["session_token"]
    )
    assert valid_session is not None
    assert valid_session["device_id"] == "dev-tv-02"

    # Forged token fails
    invalid_session = sess_mgr.validate_session(
        tenant_id="tenant-alpha",
        session_id=auth_res["session_id"],
        session_token="tok_forged_invalid_token_12345"
    )
    assert invalid_session is None

def test_invalid_credentials_rejected():
    """Verify that incorrect device secrets are rejected."""
    pseudo_mgr = PseudonymManager(default_ttl_seconds=60)
    sess_mgr = SessionManager(pseudonym_mgr=pseudo_mgr, session_ttl_seconds=60)

    with pytest.raises(PermissionError):
        sess_mgr.authenticate_device(
            tenant_id="tenant-alpha",
            device_id="dev-camera-01",
            ipv6_address="2001:db8:1::101",
            secret="wrong_secret_123"
        )

