"""
test_rotation.py - Verification of IPv6 Address Rotation & Pseudonym Persistence
PS-007: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "simulation")))

import database
from database import init_db, DatabaseManager
from pseudonym_manager import PseudonymManager
from session_manager import SessionManager
from address_rotation import AddressRotator, generate_rfc4941_ipv6

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    db_file = str(tmp_path / "test_rot.db")
    database.DB_PATH = db_file
    init_db(db_file)
    DatabaseManager.seed_initial_devices("tenant-alpha")
    yield
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except Exception:
            pass

def test_address_rotation_preserves_pseudonym():
    """
    TEST 3 from Acceptance Criteria:
    Rotate the Smart Camera IPv6 address and verify that its authenticated local pseudonym remains unchanged.
    """
    pseudo_mgr = PseudonymManager(default_ttl_seconds=120)
    sess_mgr = SessionManager(pseudonym_mgr=pseudo_mgr, session_ttl_seconds=120)
    rotator = AddressRotator(prefix="2001:db8:1")

    # Step 1: Initial Authentication
    initial_ip = "2001:db8:1::101"
    auth = sess_mgr.authenticate_device(
        tenant_id="tenant-alpha",
        device_id="dev-camera-01",
        ipv6_address=initial_ip,
        secret="secret_camera_key_7a9f",
        custom_pseudonym="DEV-P01"
    )

    initial_pseudonym = auth["pseudonym"]
    session_id = auth["session_id"]
    session_token = auth["session_token"]
    assert initial_pseudonym == "DEV-P01"

    # Verify initial address resolves to DEV-P01
    assert pseudo_mgr.resolve_ipv6("tenant-alpha", initial_ip) == "DEV-P01"

    # Step 2: Trigger Address Rotation to a new RFC 4941 address
    new_ip = "2001:db8:1::201"
    rotation_res = rotator.execute_rotation(
        session_mgr=sess_mgr,
        tenant_id="tenant-alpha",
        device_id="dev-camera-01",
        session_id=session_id,
        session_token=session_token,
        target_new_ipv6=new_ip
    )

    assert rotation_res["status"] == "SUCCESS"
    assert rotation_res["old_ipv6"] == initial_ip
    assert rotation_res["new_ipv6"] == new_ip

    # CRITICAL: Verify that the local pseudonym DEV-P01 remained EXACTLY unchanged!
    assert rotation_res["pseudonym"] == initial_pseudonym

    # Verify that the new IPv6 address now resolves to the SAME pseudonym DEV-P01
    resolved_pseudo = pseudo_mgr.resolve_ipv6("tenant-alpha", new_ip)
    assert resolved_pseudo == "DEV-P01"

    # Verify rotation event was logged in audit log
    rotations = DatabaseManager.get_rotations("tenant-alpha")
    assert len(rotations) == 1
    assert rotations[0]["device_id"] == "dev-camera-01"
    assert rotations[0]["old_ipv6"] == initial_ip
    assert rotations[0]["new_ipv6"] == new_ip
    assert rotations[0]["pseudonym"] == "DEV-P01"

    # Verify device record rotation count incremented
    dev = DatabaseManager.get_device("dev-camera-01", "tenant-alpha")
    assert dev["current_ipv6"] == new_ip
    assert dev["rotation_count"] == 1

def test_unauthorized_rotation_rejected():
    """Verify that rotation without a valid session token is rejected."""
    pseudo_mgr = PseudonymManager(default_ttl_seconds=120)
    sess_mgr = SessionManager(pseudonym_mgr=pseudo_mgr, session_ttl_seconds=120)
    rotator = AddressRotator(prefix="2001:db8:1")

    auth = sess_mgr.authenticate_device(
        tenant_id="tenant-alpha",
        device_id="dev-speaker-04",
        ipv6_address="2001:db8:1::104",
        secret="secret_speaker_key_3f8a"
    )

    with pytest.raises(PermissionError):
        rotator.execute_rotation(
            session_mgr=sess_mgr,
            tenant_id="tenant-alpha",
            device_id="dev-speaker-04",
            session_id=auth["session_id"],
            session_token="tok_attacker_invalid",
            target_new_ipv6="2001:db8:1::999"
        )

