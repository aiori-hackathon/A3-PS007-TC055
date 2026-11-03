"""
test_detection.py - Verification of Rogue RA, NDP Flood Detection, and Real Evaluation Metrics
PS-007: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "simulation")))

# Clean Scapy configuration
import scapy.config
scapy.config.conf.nameservers = ['8.8.8.8']
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA

import database
from database import init_db, DatabaseManager
from pseudonym_manager import PseudonymManager
from session_manager import SessionManager
from attack_detector import AttackDetector
from packet_monitor import PacketMonitor

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    db_file = str(tmp_path / "test_detect.db")
    database.DB_PATH = db_file
    init_db(db_file)
    DatabaseManager.seed_initial_devices("tenant-alpha")
    yield
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except Exception:
            pass

def test_rogue_router_advertisement_detection():
    """
    TEST 4: Launch rogue RA simulation and verify that the detection engine generates an alert.
    """
    pseudo_mgr = PseudonymManager(default_ttl_seconds=120)
    detector = AttackDetector(pseudonym_mgr=pseudo_mgr, tenant_id="tenant-alpha")

    # Legitimate RA from trusted default router: NO alert should be returned
    trusted_ra = detector.inspect_ra_packet(
        src_ipv6="2001:db8:1::1",
        dst_ipv6="ff02::1",
        advertised_prefix="2001:db8:1::/64",
        is_ground_truth_attack=False
    )
    assert trusted_ra is None

    # Malicious RA from unauthorized rogue router
    rogue_src = "2001:db8:1::bad:1"
    alert = detector.inspect_ra_packet(
        src_ipv6=rogue_src,
        dst_ipv6="ff02::1",
        advertised_prefix="2001:db8:666::/64",
        is_ground_truth_attack=True
    )

    assert alert is not None
    assert alert["severity"] == "CRITICAL"
    assert alert["attack_type"] == "ROGUE_ROUTER_ADVERTISEMENT"
    assert alert["src_ipv6"] == rogue_src
    assert "Rogue Router Advertisement detected" in alert["reason"]
    assert alert["latency_ms"] >= 0.0

    # Verify alert was saved in DB
    alerts_in_db = DatabaseManager.get_alerts("tenant-alpha")
    assert len(alerts_in_db) == 1
    assert alerts_in_db[0]["attack_type"] == "ROGUE_ROUTER_ADVERTISEMENT"
    assert alerts_in_db[0]["severity"] == "CRITICAL"

def test_abnormal_ndp_flood_detection_and_pseudonym_correlation():
    """
    TEST 5: Launch NDP flooding simulation and verify abnormal message rates are detected
    and correctly correlated with device pseudonym.
    """
    pseudo_mgr = PseudonymManager(default_ttl_seconds=120)
    sess_mgr = SessionManager(pseudonym_mgr=pseudo_mgr, session_ttl_seconds=120)
    detector = AttackDetector(pseudonym_mgr=pseudo_mgr, tenant_id="tenant-alpha")

    # Register Smart Speaker with IPv6 and pseudonym DEV-P04
    dev_ip = "2001:db8:1::104"
    auth = sess_mgr.authenticate_device(
        tenant_id="tenant-alpha",
        device_id="dev-speaker-04",
        ipv6_address=dev_ip,
        secret="secret_speaker_key_3f8a",
        custom_pseudonym="DEV-P04"
    )
    assert auth["pseudonym"] == "DEV-P04"

    # Simulate normal low-rate NDP messages (1-2 packets): NO alert
    res1 = detector.inspect_ndp_packet(src_ipv6=dev_ip, icmpv6_type=135, is_ground_truth_attack=False)
    assert res1 is None

    # Simulate rapid high-volume NDP flood (send 25 packets rapidly exceeding threshold)
    flood_alert = None
    for _ in range(25):
        alert = detector.inspect_ndp_packet(src_ipv6=dev_ip, icmpv6_type=135, is_ground_truth_attack=True)
        if alert:
            flood_alert = alert

    assert flood_alert is not None
    assert flood_alert["severity"] == "HIGH"
    assert flood_alert["attack_type"] == "ABNORMAL_NDP_FLOODING"
    assert flood_alert["src_ipv6"] == dev_ip
    # Check pseudonym correlation: identified DEV-P04 without hardware fingerprinting!
    assert flood_alert["pseudonym"] == "DEV-P04"
    assert flood_alert["rate_pps"] > detector.ndp_rate_threshold_pps

def test_actual_evaluation_metrics_computation():
    """
    TEST 8: Verify actual detection evaluation metrics (TP, FP, TN, FN, Precision, Recall, Latency)
    are calculated accurately from real events.
    """
    pseudo_mgr = PseudonymManager(default_ttl_seconds=120)
    detector = AttackDetector(pseudonym_mgr=pseudo_mgr, tenant_id="tenant-alpha")

    # 10 benign packets
    for _ in range(10):
        detector.inspect_ra_packet(src_ipv6="2001:db8:1::1", dst_ipv6="ff02::1", is_ground_truth_attack=False)

    # 5 rogue RA attacks
    for _ in range(5):
        detector.inspect_ra_packet(src_ipv6="2001:db8:1::bad:1", dst_ipv6="ff02::1", is_ground_truth_attack=True)

    metrics = detector.calculate_evaluation_metrics()
    assert metrics["true_positives"] >= 5
    assert metrics["false_positives"] == 0
    assert metrics["true_negatives"] >= 10
    assert metrics["false_negatives"] == 0
    assert metrics["detection_rate"] == 100.0  # 100% recall
    assert metrics["precision"] == 100.0       # 100% precision
    assert metrics["avg_detection_latency_ms"] > 0.0

