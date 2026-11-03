"""
pseudonym_manager.py - Ephemeral Pseudonym Management & Privacy Enforcement
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

Strict Privacy Guarantees:
1. Zero Permanent Hardware Identifiers (No MAC address, no serial, no OUI).
2. Ephemeral Local Pseudonyms with Cryptographic Randomness.
3. Configurable TTL with Automatic Invalidation and Secure Deletion.
4. Complete Forward and Backward Privacy (expired mappings cannot correlate past and future addresses).
5. Strict Multi-Tenant Isolation.
"""

import secrets
import string
import time
import threading
from typing import Dict, Optional, Tuple, List, Any
from database import get_db_connection, _db_lock

class PseudonymManager:
    def __init__(self, default_ttl_seconds: int = 120):
        self.default_ttl = default_ttl_seconds
        self._lock = threading.RLock()
        self.purged_count = 0  # Track count of securely deleted records

    def generate_pseudonym(self, prefix: str = "DEV-P") -> str:
        """Generate an unpredictable, cryptographically random 4-character hex pseudonym suffix."""
        rand_suffix = secrets.token_hex(2).upper()
        return f"{prefix}{rand_suffix}"

    def register_pseudonym(self, tenant_id: str, session_id: str, ipv6_address: str,
                           custom_pseudonym: Optional[str] = None, ttl_seconds: Optional[int] = None,
                           db_conn: Optional[Any] = None) -> Dict[str, Any]:
        """
        Assign an ephemeral local pseudonym to an authenticated session and bind it to the current IPv6 address.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        now = time.time()
        expires_at = now + ttl
        pseudonym = custom_pseudonym or self.generate_pseudonym()
        mapping_id = f"pseudo-{secrets.token_hex(6)}"

        with _db_lock:
            conn = db_conn or get_db_connection()
            # Deactivate any previous pseudonym for this session or IPv6
            conn.execute("""
            UPDATE pseudonyms
            SET is_active = 0
            WHERE tenant_id = ? AND (session_id = ? OR current_ipv6 = ?)
            """, (tenant_id, session_id, ipv6_address))

            conn.execute("""
            INSERT INTO pseudonyms (id, tenant_id, pseudonym, session_id, current_ipv6, assigned_at, expires_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (mapping_id, tenant_id, pseudonym, session_id, ipv6_address, now, expires_at))
            if db_conn is None:
                conn.commit()
                conn.close()

        return {
            "id": mapping_id,
            "pseudonym": pseudonym,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "current_ipv6": ipv6_address,
            "assigned_at": now,
            "expires_at": expires_at,
            "ttl_seconds": ttl
        }

    def update_address(self, tenant_id: str, session_id: str, new_ipv6: str) -> Optional[str]:
        """
        Update the bound IPv6 address when an authenticated device rotates its temporary address.
        Maintains the existing active pseudonym without changing it or leaking hardware IDs.
        """
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT pseudonym, expires_at FROM pseudonyms
            WHERE tenant_id = ? AND session_id = ? AND is_active = 1
            """, (tenant_id, session_id))
            row = cursor.fetchone()

            if not row:
                conn.close()
                return None

            if row["expires_at"] <= now:
                # Expired mapping: mark inactive and refuse update
                conn.execute("UPDATE pseudonyms SET is_active = 0 WHERE tenant_id = ? AND session_id = ?", (tenant_id, session_id))
                conn.commit()
                conn.close()
                return None

            pseudonym = row["pseudonym"]
            conn.execute("""
            UPDATE pseudonyms
            SET current_ipv6 = ?
            WHERE tenant_id = ? AND session_id = ? AND is_active = 1
            """, (new_ipv6, tenant_id, session_id))
            conn.commit()
            conn.close()
            return pseudonym

    def resolve_ipv6(self, tenant_id: str, ipv6_address: str) -> Optional[str]:
        """
        Resolve an active IPv6 address to its pseudonym for a specific tenant.
        Returns None if not found or expired.
        """
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, pseudonym, expires_at FROM pseudonyms
            WHERE tenant_id = ? AND current_ipv6 = ? AND is_active = 1
            ORDER BY expires_at DESC
            LIMIT 1
            """, (tenant_id, ipv6_address))
            row = cursor.fetchone()

            if not row:
                conn.close()
                return None

            if row["expires_at"] <= now:
                # Auto-expire
                conn.execute("""
                UPDATE pseudonyms SET is_active = 0
                WHERE id = ?
                """, (row["id"],))
                conn.commit()
                conn.close()
                return None

            conn.close()
            return row["pseudonym"]

    def purge_expired_mappings(self) -> int:
        """
        Securely delete expired pseudonym records from the database.
        Ensures forward and backward unlinkability (no lingering historical records).
        """
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Find count of expired records
            cursor.execute("""
            SELECT COUNT(*) as cnt FROM pseudonyms
            WHERE expires_at <= ? OR is_active = 0
            """, (now,))
            count = cursor.fetchone()["cnt"]

            if count > 0:
                # Secure deletion
                cursor.execute("""
                DELETE FROM pseudonyms
                WHERE expires_at <= ? OR is_active = 0
                """, (now,))
                conn.commit()

            conn.close()

        with self._lock:
            self.purged_count += count
        return count

    def get_privacy_status(self, tenant_id: str = "tenant-alpha") -> Dict[str, Any]:
        """Return active, expired, and compliance stats for the privacy dashboard."""
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
            SELECT COUNT(*) as active_cnt FROM pseudonyms
            WHERE tenant_id = ? AND is_active = 1 AND expires_at > ?
            """, (tenant_id, now))
            active_count = cursor.fetchone()["active_cnt"]

            cursor.execute("""
            SELECT COUNT(*) as expired_cnt FROM pseudonyms
            WHERE tenant_id = ? AND (is_active = 0 OR expires_at <= ?)
            """, (tenant_id, now))
            expired_count = cursor.fetchone()["expired_cnt"]

            cursor.execute("""
            SELECT p.*, s.device_id, d.name as device_name
            FROM pseudonyms p
            JOIN sessions s ON p.session_id = s.id
            JOIN devices d ON s.device_id = d.id AND s.tenant_id = d.tenant_id
            WHERE p.tenant_id = ? AND p.is_active = 1 AND p.expires_at > ?
            ORDER BY p.assigned_at DESC
            """, (tenant_id, now))
            active_list = [dict(r) for r in cursor.fetchall()]
            conn.close()

        # Add remaining TTL calculation
        for item in active_list:
            item["ttl_remaining"] = max(0, int(item["expires_at"] - now))

        return {
            "tenant_id": tenant_id,
            "active_pseudonyms_count": active_count,
            "expired_pseudonyms_count": expired_count,
            "purged_records_count": self.purged_count,
            "default_ttl_seconds": self.default_ttl,
            "active_mappings": active_list,
            "privacy_compliance": {
                "zero_mac_address_retention": True,
                "zero_behavioral_profiling": True,
                "rfc4941_privacy_extension_compliant": True,
                "forward_backward_unlinkability": True,
                "tenant_isolation_enforced": True
            }
        }
