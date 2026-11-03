"""
test_privacy.py - Verification of Strict Privacy & Multi-Tenant Isolation
PS-007: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "simulation")))

import database
from database import init_db, DatabaseManager, get_db_connection
from pseudonym_manager import PseudonymManager
from session_manager import SessionManager

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    db_file = str(tmp_path / "test_priv.db")
    database.DB_PATH = db_file
    init_db(db_file)
    DatabaseManager.seed_initial_devices("tenant-alpha")
    yield
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except Exception:
            pass

def test_no_mac_address_or_hardware_id_in_schema():
    """Verify that NO hardware fingerprints, MAC addresses, or OUIs exist in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    for table in ["devices", "sessions", "pseudonyms", "address_rotations"]:
        cursor.execute(f"PRAGMA table_info({table});")
        columns = [row["name"].lower() for row in cursor.fetchall()]
        for col in columns:
            assert "mac" not in col, f"Forbidden MAC column found: {table}.{col}"
            assert "hardware" not in col, f"Forbidden hardware column found: {table}.{col}"
            assert "imei" not in col, f"Forbidden imei column found: {table}.{col}"
            assert "serial" not in col, f"Forbidden serial column found: {table}.{col}"

    conn.close()

def test_pseudonym_expiration_and_secure_purging():
    """
    TEST 6: Expire a pseudonym and verify that its mapping is deleted.
    """
    # Create manager with short 1-second TTL
    short_ttl = 1
    pseudo_mgr = PseudonymManager(default_ttl_seconds=short_ttl)
    sess_mgr = SessionManager(pseudonym_mgr=pseudo_mgr, session_ttl_seconds=short_ttl)

    auth = sess_mgr.authenticate_device(
        tenant_id="tenant-alpha",
        device_id="dev-camera-01",
        ipv6_address="2001:db8:1::101",
        secret="secret_camera_key_7a9f",
        custom_pseudonym="DEV-P01"
    )

    # Immediately after creation, resolution works
    assert pseudo_mgr.resolve_ipv6("tenant-alpha", "2001:db8:1::101") == "DEV-P01"

    # Wait for TTL to elapse
    time.sleep(1.2)

    # 1. Automatic expiration on resolution
    expired_res = pseudo_mgr.resolve_ipv6("tenant-alpha", "2001:db8:1::101")
    assert expired_res is None, "Expired pseudonym must not resolve!"

    # 2. Secure purging deletes the mapping completely from the database
    purged = pseudo_mgr.purge_expired_mappings()
    assert purged >= 1

    # Check database rows in pseudonyms table
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM pseudonyms WHERE pseudonym = 'DEV-P01'").fetchall()
    conn.close()
    assert len(rows) == 0, "Expired pseudonym mapping must be completely erased from disk!"

def test_multi_tenant_strict_isolation():
    """
    TEST 7: Simulate separate tenants and verify that cross-tenant correlation is prevented.
    """
    pseudo_mgr = PseudonymManager(default_ttl_seconds=120)
    sess_mgr = SessionManager(pseudonym_mgr=pseudo_mgr, session_ttl_seconds=120)

    # Setup Tenant Alpha
    DatabaseManager.seed_initial_devices("tenant-alpha")
    auth_alpha = sess_mgr.authenticate_device(
        tenant_id="tenant-alpha",
        device_id="dev-bulb-03",
        ipv6_address="2001:db8:1::103",
        secret="secret_bulb_key_9e1d",
        custom_pseudonym="ALPHA-BULB"
    )

    # Setup Tenant Beta with same device ID but different tenant and address
    DatabaseManager.seed_initial_devices("tenant-beta")
    auth_beta = sess_mgr.authenticate_device(
        tenant_id="tenant-beta",
        device_id="dev-bulb-03",
        ipv6_address="2001:db8:2::103",
        secret="secret_bulb_key_9e1d",
        custom_pseudonym="BETA-BULB"
    )

    # Tenant Alpha cannot resolve Tenant Beta's IP
    assert pseudo_mgr.resolve_ipv6("tenant-alpha", "2001:db8:2::103") is None

    # Tenant Beta cannot resolve Tenant Alpha's IP
    assert pseudo_mgr.resolve_ipv6("tenant-beta", "2001:db8:1::103") is None

    # Each tenant resolves only their own mapping
    assert pseudo_mgr.resolve_ipv6("tenant-alpha", "2001:db8:1::103") == "ALPHA-BULB"
    assert pseudo_mgr.resolve_ipv6("tenant-beta", "2001:db8:2::103") == "BETA-BULB"

    # Verify device query isolation
    alpha_devices = DatabaseManager.get_devices("tenant-alpha")
    beta_devices = DatabaseManager.get_devices("tenant-beta")
    assert all(d["tenant_id"] == "tenant-alpha" for d in alpha_devices)
    assert all(d["tenant_id"] == "tenant-beta" for d in beta_devices)

