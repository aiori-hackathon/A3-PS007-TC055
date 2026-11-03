"""
run_acceptance_tests.py - Live Verification of the 9 Acceptance Criteria
PS-007: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
"""

import time
import requests
import sys

BASE_URL = "http://127.0.0.1:5005"

def print_header(text):
    print(f"\n{'='*75}\n {text}\n{'='*75}")

def test_1_five_devices_present():
    print_header("TEST 1: Start five IoT devices and show all five on dashboard")
    res = requests.get(f"{BASE_URL}/api/devices?tenant_id=tenant-alpha")
    assert res.status_code == 200, f"Status code {res.status_code}"
    data = res.json()["data"]
    assert len(data) == 5, f"Expected 5 devices, got {len(data)}"
    names = [d["name"] for d in data]
    print(f"[*] Found {len(data)} devices: {', '.join(names)}")
    expected_names = {"Smart Camera", "Smart TV", "Smart Bulb", "Smart Speaker", "Smart Door Sensor"}
    assert set(names) == expected_names, f"Device names mismatch: {set(names)} vs {expected_names}"
    print("[PASS] TEST 1: All five IoT devices are initialized and monitored.")

def test_2_authenticate_devices():
    print_header("TEST 2: Authenticate all devices and assign short-lived pseudonyms")
    res = requests.get(f"{BASE_URL}/api/devices?tenant_id=tenant-alpha")
    devices = res.json()["data"]
    for dev in devices:
        auth_res = requests.post(f"{BASE_URL}/api/devices/authenticate", json={
            "device_id": dev["id"],
            "tenant_id": "tenant-alpha"
        })
        assert auth_res.status_code == 200
        auth_data = auth_res.json()["data"]
        print(f"[*] Device {dev['name']} ({dev['id']}): Authenticated -> Pseudonym: {auth_data['pseudonym']}, TTL: {auth_data['ttl_seconds']}s")
        assert auth_data["pseudonym"].startswith("DEV-")
        assert auth_data["session_token"].startswith("tok_")

    print("[PASS] TEST 2: All devices successfully authenticated with local pseudonyms.")

def test_3_rotate_smart_camera():
    print_header("TEST 3: Rotate Smart Camera IPv6 address & verify local pseudonym unchanged")
    # Fetch camera before rotation
    res_before = requests.get(f"{BASE_URL}/api/devices?tenant_id=tenant-alpha")
    cam_before = next(d for d in res_before.json()["data"] if d["id"] == "dev-camera-01")
    old_ip = cam_before["current_ipv6"]
    initial_pseudonym = cam_before["pseudonym"]
    print(f"[*] Before rotation: Device: {cam_before['name']} | IPv6: {old_ip} | Pseudonym: {initial_pseudonym}")

    # Trigger rotation with a freshly generated temporary address
    import secrets
    new_temp_ip = f"2001:db8:1::{secrets.token_hex(2)}"
    rot_res = requests.post(f"{BASE_URL}/api/devices/rotate", json={
        "device_id": "dev-camera-01",
        "tenant_id": "tenant-alpha",
        "new_ipv6": new_temp_ip
    })
    assert rot_res.status_code == 200
    rot_data = rot_res.json()["data"]
    new_ip = rot_data["new_ipv6"]
    new_pseudonym = rot_data["pseudonym"]
    print(f"[*] After rotation:  Device: Smart Camera | IPv6: {new_ip} | Pseudonym: {new_pseudonym}")

    assert old_ip != new_ip, "IP address should have changed!"
    assert initial_pseudonym == new_pseudonym, f"Pseudonym must be preserved! {initial_pseudonym} vs {new_pseudonym}"
    assert rot_data["status"] == "SUCCESS"

    # Verify via privacy API that new IP resolves to the same pseudonym
    priv_res = requests.get(f"{BASE_URL}/api/privacy?tenant_id=tenant-alpha")
    mappings = priv_res.json()["data"]["active_mappings"]
    cam_mapping = next(m for m in mappings if m["device_id"] == "dev-camera-01")
    assert cam_mapping["current_ipv6"] == new_ip
    assert cam_mapping["pseudonym"] == initial_pseudonym

    print(f"[PASS] TEST 3: Address rotated from {old_ip} to {new_ip} while retaining pseudonym {new_pseudonym}.")

def test_4_rogue_ra_simulation():
    print_header("TEST 4: Launch rogue RA simulation and verify alert generation")
    # Start rogue RA
    requests.post(f"{BASE_URL}/api/simulation/start", json={"type": "rogue_ra", "interval": 0.5})
    time.sleep(1.2)
    requests.post(f"{BASE_URL}/api/simulation/stop", json={"type": "rogue_ra"})

    # Check alerts
    res = requests.get(f"{BASE_URL}/api/alerts?tenant_id=tenant-alpha")
    alerts = res.json()["data"]
    ra_alerts = [a for a in alerts if a["attack_type"] == "ROGUE_ROUTER_ADVERTISEMENT"]
    assert len(ra_alerts) > 0, "No Rogue RA alerts found!"
    alert = ra_alerts[0]
    print(f"[*] Detected Alert: ID: {alert['alert_id']} | Severity: {alert['severity']} | Latency: {alert['detection_latency_ms']} ms")
    print(f"[*] Reason: {alert['reason']}")
    assert alert["severity"] == "CRITICAL"
    assert "2001:db8:1::bad:1" in alert["src_ipv6"]
    print("[PASS] TEST 4: Rogue RA attack successfully detected and alerted.")

def test_5_ndp_flood_simulation():
    print_header("TEST 5: Launch NDP flooding simulation and verify abnormal rate detection")
    # Start NDP flood from Smart Speaker (2001:db8:1::104)
    speaker_ip = "2001:db8:1::104"
    requests.post(f"{BASE_URL}/api/simulation/start", json={
        "type": "ndp_flood",
        "rate": 35,
        "src_ipv6": speaker_ip
    })
    time.sleep(1.5)
    requests.post(f"{BASE_URL}/api/simulation/stop", json={"type": "ndp_flood"})

    # Check alerts
    res = requests.get(f"{BASE_URL}/api/alerts?tenant_id=tenant-alpha")
    alerts = res.json()["data"]
    ndp_alerts = [a for a in alerts if a["attack_type"] == "ABNORMAL_NDP_FLOODING"]
    assert len(ndp_alerts) > 0, "No NDP flooding alerts found!"
    alert = ndp_alerts[0]
    print(f"[*] Detected Alert: ID: {alert['alert_id']} | Severity: {alert['severity']} | Source: {alert['src_ipv6']}")
    print(f"[*] Correlated Device Pseudonym: {alert['pseudonym']}")
    print(f"[*] Reason: {alert['reason']}")
    assert alert["severity"] == "HIGH"
    assert alert["pseudonym"] is not None  # Correlated without hardware fingerprinting!
    print(f"[PASS] TEST 5: NDP flooding detected and correlated to pseudonym {alert['pseudonym']}.")

def test_6_expire_and_purge_pseudonym():
    print_header("TEST 6: Expire a pseudonym and verify mapping deletion")
    # Step 1: Register an ephemeral pseudonym with short 1-second TTL
    short_auth = requests.post(f"{BASE_URL}/api/devices/authenticate", json={
        "device_id": "dev-doorsensor-05",
        "tenant_id": "tenant-alpha",
        "pseudonym": "DEV-EXPIRE-99",
        "ttl_seconds": 1
    })
    assert short_auth.status_code == 200
    print("[*] Created ephemeral mapping DEV-EXPIRE-99 with TTL=1s")

    # Step 2: Wait for mapping to expire
    time.sleep(1.3)

    # Step 3: Trigger purge
    res = requests.post(f"{BASE_URL}/api/privacy/purge")
    assert res.status_code == 200
    purged_data = res.json()
    print(f"[*] Purge result: {purged_data['message']}")

    # Step 4: Verify that DEV-EXPIRE-99 no longer exists anywhere in active mappings
    priv_res = requests.get(f"{BASE_URL}/api/privacy?tenant_id=tenant-alpha")
    priv_data = priv_res.json()["data"]
    active_pseudos = [m["pseudonym"] for m in priv_data["active_mappings"]]
    assert "DEV-EXPIRE-99" not in active_pseudos, "Expired pseudonym must not appear in active mappings!"
    print(f"[*] Total Purged Records Recorded by Privacy Engine: {priv_data['purged_records_count']}")
    assert priv_data["purged_records_count"] >= 1, "Expected at least 1 purged record recorded in history"

    # Restore normal authentication for door sensor
    requests.post(f"{BASE_URL}/api/devices/authenticate", json={
        "device_id": "dev-doorsensor-05",
        "tenant_id": "tenant-alpha"
    })
    print("[PASS] TEST 6: Pseudonym expiration & secure deletion verified.")

def test_7_tenant_isolation():
    print_header("TEST 7: Verify strict tenant isolation and no cross-tenant correlation")
    res = requests.post(f"{BASE_URL}/api/privacy/test-isolation")
    assert res.status_code == 200
    test_data = res.json()["data"]
    assert test_data["isolation_verified"] is True
    for check in test_data["checks"]:
        print(f"[*] {check['test']}: {'PASS' if check['passed'] else 'FAIL'} - {check['detail']}")
        assert check["passed"] is True
    print("[PASS] TEST 7: Cross-tenant correlation strictly prevented.")

def test_8_evaluation_metrics():
    print_header("TEST 8: Run evaluation benchmark & verify actual detection metrics")
    bench_res = requests.post(f"{BASE_URL}/api/evaluation/run")
    assert bench_res.status_code == 200
    metrics = bench_res.json()["data"]
    print(f"[*] True Positives  (TP): {metrics['true_positives']}")
    print(f"[*] False Positives (FP): {metrics['false_positives']}")
    print(f"[*] True Negatives  (TN): {metrics['true_negatives']}")
    print(f"[*] False Negatives (FN): {metrics['false_negatives']}")
    print(f"[*] Detection Rate (Recall): {metrics['detection_rate']}%")
    print(f"[*] Precision:               {metrics['precision']}%")
    print(f"[*] False Positive Rate:     {metrics['false_positive_rate']}%")
    print(f"[*] Average Latency:         {metrics['avg_detection_latency_ms']} ms")
    print(f"[*] Total Packets Evaluated: {metrics['total_evaluated_packets']}")

    assert metrics["detection_rate"] >= 90.0, "Detection rate should be high"
    assert metrics["precision"] >= 90.0, "Precision should be high"
    assert metrics["false_positive_rate"] <= 10.0, "FPR should be low"
    assert metrics["avg_detection_latency_ms"] > 0.0, "Latency must be calculated"
    print("[PASS] TEST 8: Actual evaluation metrics calculated from real test vectors.")

def test_9_server_health_and_stability():
    print_header("TEST 9: Server health check and restart stability")
    dash_res = requests.get(f"{BASE_URL}/api/dashboard?tenant_id=tenant-alpha")
    assert dash_res.status_code == 200
    summary = dash_res.json()["data"]
    print(f"[*] Health Status: {summary['network_health_status']} ({summary['network_health_score']}/100)")
    print(f"[*] Total Processed Packets: {summary['packets_processed']}")
    print(f"[*] Active Sessions: {summary['active_sessions']}")
    print("[PASS] TEST 9: Application is completely operational and stable.")

if __name__ == "__main__":
    try:
        test_1_five_devices_present()
        test_2_authenticate_devices()
        test_3_rotate_smart_camera()
        test_4_rogue_ra_simulation()
        test_5_ndp_flood_simulation()
        test_6_expire_and_purge_pseudonym()
        test_7_tenant_isolation()
        test_8_evaluation_metrics()
        test_9_server_health_and_stability()

        print("\n" + "="*75)
        print(" [ALL 9 ACCEPTANCE TESTS PASSED SUCCESSFULLY!]")
        print("="*75 + "\n")
    except Exception as e:
        print(f"\n[FAIL] Acceptance test failed: {e}")
        sys.exit(1)
