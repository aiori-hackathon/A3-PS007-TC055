"""
ipv6_monitor.py - Central IPv6 Monitoring Orchestrator
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

Coordinates:
- Packet Monitor
- Attack Detector
- Session & Pseudonym Lifecycle
- Live Health Scoring & Aggregate Metrics
"""

import time
import threading
from typing import Dict, Any, List, Optional
from database import DatabaseManager, init_db
from pseudonym_manager import PseudonymManager
from session_manager import SessionManager
from attack_detector import AttackDetector
from packet_monitor import PacketMonitor

class IPv6SecurityMonitor:
    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls, tenant_id: str = "tenant-alpha") -> 'IPv6SecurityMonitor':
        with cls._lock:
            if cls._instance is None:
                cls._instance = IPv6SecurityMonitor(tenant_id=tenant_id)
            return cls._instance

    def __init__(self, tenant_id: str = "tenant-alpha"):
        self.tenant_id = tenant_id
        init_db()

        # Core subsystems
        self.pseudonym_mgr = PseudonymManager(default_ttl_seconds=120)
        self.session_mgr = SessionManager(pseudonym_mgr=self.pseudonym_mgr, session_ttl_seconds=120)
        self.attack_detector = AttackDetector(pseudonym_mgr=self.pseudonym_mgr, tenant_id=self.tenant_id)
        self.packet_monitor = PacketMonitor(
            pseudonym_mgr=self.pseudonym_mgr,
            attack_detector=self.attack_detector,
            tenant_id=self.tenant_id
        )

        # Seed initial 5 devices
        DatabaseManager.seed_initial_devices(tenant_id=self.tenant_id)

        # Start monitoring engine
        self.packet_monitor.start()

        # Background maintenance thread (auto-purge expired mappings every 10 seconds)
        self._maintenance_running = True
        self._maintenance_thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        self._maintenance_thread.start()

    def _maintenance_loop(self) -> None:
        """Periodic background garbage collection of expired pseudonyms to enforce privacy."""
        while self._maintenance_running:
            try:
                self.pseudonym_mgr.purge_expired_mappings()
            except Exception:
                pass
            time.sleep(10.0)

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Generate high-level dashboard metrics for the Overview page."""
        devices = DatabaseManager.get_devices(tenant_id=self.tenant_id)
        active_sessions = self.session_mgr.get_active_sessions(tenant_id=self.tenant_id)
        rotations = DatabaseManager.get_rotations(tenant_id=self.tenant_id, limit=100)
        alerts = DatabaseManager.get_alerts(tenant_id=self.tenant_id, limit=50)
        pkt_status = self.packet_monitor.get_status()

        rogue_ra_count = sum(1 for a in alerts if a["attack_type"] == "ROGUE_ROUTER_ADVERTISEMENT")
        ndp_anomalies_count = sum(1 for a in alerts if a["attack_type"] == "ABNORMAL_NDP_FLOODING")

        # Network Health Score (100 is pristine; deductions for critical and high alerts)
        health_score = 100
        health_score -= min(50, rogue_ra_count * 15)
        health_score -= min(40, ndp_anomalies_count * 10)
        health_score = max(10, health_score)

        if health_score >= 85:
            health_status = "HEALTHY"
            health_color = "success"
        elif health_score >= 60:
            health_status = "WARNING"
            health_color = "warning"
        else:
            health_status = "CRITICAL RISK"
            health_color = "danger"

        return {
            "total_devices": len(devices),
            "active_sessions": len(active_sessions),
            "ipv6_rotations_count": len(rotations),
            "total_alerts": len(alerts),
            "rogue_ra_detections": rogue_ra_count,
            "ndp_anomalies": ndp_anomalies_count,
            "network_health_score": health_score,
            "network_health_status": health_status,
            "network_health_color": health_color,
            "monitoring_mode": pkt_status["mode"],
            "platform": pkt_status["platform"],
            "packets_processed": pkt_status["total_packets_processed"],
            "packets_per_second": pkt_status["packets_per_second"],
            "type_distribution": pkt_status["type_distribution"],
            "recent_alerts": alerts[:5]
        }

    def get_device_overview(self) -> List[Dict[str, Any]]:
        """Return all 5 devices with real-time NDP rates, pseudonym, and security status."""
        devices = DatabaseManager.get_devices(tenant_id=self.tenant_id)
        alerts = DatabaseManager.get_alerts(tenant_id=self.tenant_id, limit=50)

        # Map alerts to IPs/pseudonyms
        alert_ips = {a["src_ipv6"]: a["severity"] for a in alerts if not a.get("acknowledged")}
        alert_pseudos = {a["pseudonym"]: a["severity"] for a in alerts if a.get("pseudonym") and not a.get("acknowledged")}

        for d in devices:
            ip = d["current_ipv6"]
            pseudo = d.get("pseudonym")
            # Calculate live NDP message rate
            d["ndp_message_rate"] = self.attack_detector.get_source_ndp_rate(ip)

            # Security status
            if ip in alert_ips or (pseudo and pseudo in alert_pseudos):
                d["security_status"] = "ALERT"
            elif d["status"] == "AUTHENTICATED":
                d["security_status"] = "SECURE"
            else:
                d["security_status"] = "IDLE"

        return devices

