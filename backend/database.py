"""
database.py - SQLite Database Manager for PS-007
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
"""

import sqlite3
import os
import threading
import time
from typing import List, Dict, Any, Optional

DB_PATH = os.environ.get("PS007_DB_PATH", os.path.join(os.path.dirname(__file__), "iot_monitor.db"))

_db_lock = threading.RLock()

def get_db_connection() -> sqlite3.Connection:
    """Get a thread-safe SQLite connection with dictionary-like row access."""
    conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path: Optional[str] = None) -> None:
    """Initialize database tables with schema and indexes."""
    global DB_PATH
    if db_path:
        DB_PATH = db_path

    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)

    with _db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Tenants table for multi-tenant isolation
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        """)

        # IoT Devices table (NO MAC addresses or permanent hardware IDs stored)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            device_type TEXT NOT NULL,
            current_ipv6 TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'UNREGISTERED',
            rotation_count INTEGER NOT NULL DEFAULT 0,
            registered_at REAL NOT NULL,
            last_active_at REAL NOT NULL,
            PRIMARY KEY (id, tenant_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
        """)

        # Sessions table (short-lived authenticated sessions)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            pseudonym TEXT NOT NULL,
            ipv6_address TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
        """)

        # Pseudonyms table (local ephemeral pseudonyms)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS pseudonyms (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            pseudonym TEXT NOT NULL,
            session_id TEXT NOT NULL,
            current_ipv6 TEXT NOT NULL,
            assigned_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );
        """)

        # Address Rotations log
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS address_rotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            pseudonym TEXT NOT NULL,
            old_ipv6 TEXT NOT NULL,
            new_ipv6 TEXT NOT NULL,
            rotated_at REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'SUCCESS',
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
        """)

        # Network Events log
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            timestamp REAL NOT NULL,
            src_ipv6 TEXT NOT NULL,
            dst_ipv6 TEXT NOT NULL,
            icmpv6_type INTEGER NOT NULL,
            icmpv6_name TEXT NOT NULL,
            length INTEGER NOT NULL DEFAULT 0,
            pseudonym TEXT,
            is_attack INTEGER NOT NULL DEFAULT 0,
            metadata TEXT DEFAULT '{}',
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
        """)

        # Security Alerts table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            alert_id TEXT UNIQUE NOT NULL,
            severity TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            src_ipv6 TEXT NOT NULL,
            pseudonym TEXT,
            timestamp REAL NOT NULL,
            reason TEXT NOT NULL,
            detection_latency_ms REAL NOT NULL DEFAULT 0.0,
            acknowledged INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
        );
        """)

        # Evaluation Metrics History
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS evaluation_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            test_run_name TEXT NOT NULL DEFAULT 'benchmark',
            true_positives INTEGER NOT NULL DEFAULT 0,
            false_positives INTEGER NOT NULL DEFAULT 0,
            true_negatives INTEGER NOT NULL DEFAULT 0,
            false_negatives INTEGER NOT NULL DEFAULT 0,
            detection_rate REAL NOT NULL DEFAULT 0.0,
            precision REAL NOT NULL DEFAULT 0.0,
            fpr REAL NOT NULL DEFAULT 0.0,
            avg_latency_ms REAL NOT NULL DEFAULT 0.0,
            total_packets INTEGER NOT NULL DEFAULT 0
        );
        """)

        # Create indexes for fast lookup and tenant isolation
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_lookup ON sessions(tenant_id, ipv6_address, is_active);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pseudonyms_lookup ON pseudonyms(tenant_id, current_ipv6, is_active);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON network_events(timestamp DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp DESC);")

        # Insert default tenant if missing
        cursor.execute("INSERT OR IGNORE INTO tenants (id, name, created_at) VALUES ('tenant-alpha', 'Primary Enterprise IoT Tenant', ?)", (time.time(),))
        cursor.execute("INSERT OR IGNORE INTO tenants (id, name, created_at) VALUES ('tenant-beta', 'Isolated Guest IoT Tenant', ?)", (time.time(),))

        conn.commit()
        conn.close()

class DatabaseManager:
    """Helper class providing typed query methods."""

    @staticmethod
    def seed_initial_devices(tenant_id: str = "tenant-alpha") -> None:
        """Seed the 5 standard IoT devices for the tenant if not already present."""
        initial_devices = [
            ("dev-camera-01", "Smart Camera", "Security Camera", "2001:db8:1::101"),
            ("dev-tv-02", "Smart TV", "Entertainment Hub", "2001:db8:1::102"),
            ("dev-bulb-03", "Smart Bulb", "Lighting Device", "2001:db8:1::103"),
            ("dev-speaker-04", "Smart Speaker", "Voice Assistant", "2001:db8:1::104"),
            ("dev-doorsensor-05", "Smart Door Sensor", "Access Control", "2001:db8:1::105"),
        ]
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            for dev_id, name, dev_type, ipv6 in initial_devices:
                conn.execute("""
                INSERT OR IGNORE INTO devices
                (id, tenant_id, name, device_type, current_ipv6, status, rotation_count, registered_at, last_active_at)
                VALUES (?, ?, ?, ?, ?, 'UNREGISTERED', 0, ?, ?)
                """, (dev_id, tenant_id, name, dev_type, ipv6, now, now))
            conn.commit()
            conn.close()

    @staticmethod
    def get_devices(tenant_id: str = "tenant-alpha") -> List[Dict[str, Any]]:
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT d.id, d.tenant_id, d.name, d.device_type, d.current_ipv6, d.status,
                   d.rotation_count, d.registered_at, d.last_active_at,
                   s.pseudonym, s.expires_at as session_expires_at,
                   s.id as session_id
            FROM devices d
            LEFT JOIN sessions s ON d.id = s.device_id AND d.tenant_id = s.tenant_id AND s.is_active = 1
            WHERE d.tenant_id = ?
            GROUP BY d.id
            ORDER BY d.id ASC
            """, (tenant_id,))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    @staticmethod
    def get_device(device_id: str, tenant_id: str = "tenant-alpha") -> Optional[Dict[str, Any]]:
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT d.*, s.id as session_id, s.pseudonym, s.expires_at as session_expires_at
            FROM devices d
            LEFT JOIN sessions s ON d.id = s.device_id AND d.tenant_id = s.tenant_id AND s.is_active = 1
            WHERE d.id = ? AND d.tenant_id = ?
            ORDER BY s.created_at DESC
            LIMIT 1
            """, (device_id, tenant_id))
            row = cursor.fetchone()
            conn.close()
            return dict(row) if row else None

    @staticmethod
    def update_device_ip(device_id: str, new_ipv6: str, tenant_id: str = "tenant-alpha") -> None:
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            conn.execute("""
            UPDATE devices
            SET current_ipv6 = ?, rotation_count = rotation_count + 1, last_active_at = ?
            WHERE id = ? AND tenant_id = ?
            """, (new_ipv6, now, device_id, tenant_id))
            conn.commit()
            conn.close()

    @staticmethod
    def update_device_status(device_id: str, status: str, tenant_id: str = "tenant-alpha") -> None:
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            conn.execute("""
            UPDATE devices
            SET status = ?, last_active_at = ?
            WHERE id = ? AND tenant_id = ?
            """, (status, now, device_id, tenant_id))
            conn.commit()
            conn.close()

    @staticmethod
    def log_rotation(tenant_id: str, device_id: str, pseudonym: str, old_ipv6: str, new_ipv6: str, status: str = "SUCCESS") -> None:
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            conn.execute("""
            INSERT INTO address_rotations (tenant_id, device_id, pseudonym, old_ipv6, new_ipv6, rotated_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (tenant_id, device_id, pseudonym, old_ipv6, new_ipv6, now, status))
            conn.commit()
            conn.close()

    @staticmethod
    def get_rotations(tenant_id: str = "tenant-alpha", limit: int = 50) -> List[Dict[str, Any]]:
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT r.*, d.name as device_name
            FROM address_rotations r
            JOIN devices d ON r.device_id = d.id AND r.tenant_id = d.tenant_id
            WHERE r.tenant_id = ?
            ORDER BY r.rotated_at DESC
            LIMIT ?
            """, (tenant_id, limit))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    @staticmethod
    def log_network_event(tenant_id: str, src_ipv6: str, dst_ipv6: str, icmpv6_type: int,
                          icmpv6_name: str, length: int, pseudonym: Optional[str] = None,
                          is_attack: int = 0, metadata: str = "{}") -> None:
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            conn.execute("""
            INSERT INTO network_events (tenant_id, timestamp, src_ipv6, dst_ipv6, icmpv6_type, icmpv6_name, length, pseudonym, is_attack, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tenant_id, now, src_ipv6, dst_ipv6, icmpv6_type, icmpv6_name, length, pseudonym, is_attack, metadata))
            conn.commit()
            conn.close()

    @staticmethod
    def get_network_events(tenant_id: str = "tenant-alpha", limit: int = 100) -> List[Dict[str, Any]]:
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM network_events
            WHERE tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """, (tenant_id, limit))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    @staticmethod
    def log_alert(tenant_id: str, alert_id: str, severity: str, attack_type: str,
                  src_ipv6: str, pseudonym: Optional[str], reason: str,
                  detection_latency_ms: float = 0.0) -> None:
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            conn.execute("""
            INSERT OR IGNORE INTO security_alerts
            (tenant_id, alert_id, severity, attack_type, src_ipv6, pseudonym, timestamp, reason, detection_latency_ms, acknowledged)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (tenant_id, alert_id, severity, attack_type, src_ipv6, pseudonym, now, reason, detection_latency_ms))
            conn.commit()
            conn.close()

    @staticmethod
    def get_alerts(tenant_id: str = "tenant-alpha", limit: int = 50) -> List[Dict[str, Any]]:
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM security_alerts
            WHERE tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """, (tenant_id, limit))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    @staticmethod
    def log_evaluation_metrics(tp: int, fp: int, tn: int, fn: int,
                               detection_rate: float, precision: float, fpr: float,
                               avg_latency_ms: float, total_packets: int,
                               test_run_name: str = "benchmark") -> None:
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            conn.execute("""
            INSERT INTO evaluation_metrics
            (timestamp, test_run_name, true_positives, false_positives, true_negatives, false_negatives,
             detection_rate, precision, fpr, avg_latency_ms, total_packets)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (now, test_run_name, tp, fp, tn, fn, detection_rate, precision, fpr, avg_latency_ms, total_packets))
            conn.commit()
            conn.close()

    @staticmethod
    def get_latest_evaluation() -> Optional[Dict[str, Any]]:
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM evaluation_metrics
            ORDER BY timestamp DESC
            LIMIT 1
            """)
            row = cursor.fetchone()
            conn.close()
            return dict(row) if row else None
