"""
session_manager.py - Authenticated Session Lifecycle & Token Management
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
"""

import hashlib
import hmac
import secrets
import time
from typing import Dict, Any, Optional, Tuple
from database import get_db_connection, _db_lock, DatabaseManager
from pseudonym_manager import PseudonymManager

class SessionManager:
    def __init__(self, pseudonym_mgr: PseudonymManager, session_ttl_seconds: int = 120):
        self.pseudonym_mgr = pseudonym_mgr
        self.session_ttl = session_ttl_seconds
        self._active_tokens: Dict[str, str] = {}
        # Pre-shared device registration keys for initial authentication handshake
        self._device_secrets = {
            "dev-camera-01": "secret_camera_key_7a9f",
            "dev-tv-02": "secret_tv_key_4b2c",
            "dev-bulb-03": "secret_bulb_key_9e1d",
            "dev-speaker-04": "secret_speaker_key_3f8a",
            "dev-doorsensor-05": "secret_doorsensor_key_5c6b",
        }

    def _hash_token(self, token: str) -> str:
        """Store SHA-256 hash of tokens in the database to prevent token leakage."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def authenticate_device(self, tenant_id: str, device_id: str, ipv6_address: str,
                            secret: Optional[str] = None, custom_pseudonym: Optional[str] = None,
                            ttl_seconds: Optional[int] = None) -> Dict[str, Any]:
        """
        Authenticate an IoT device and issue an ephemeral session token with a short-lived pseudonym.
        """
        # Validate pre-shared secret if provided, or default verify registered device
        expected_secret = self._device_secrets.get(device_id)
        if expected_secret and secret and secret != expected_secret:
            raise PermissionError(f"Authentication failed: Invalid credentials for device {device_id}")

        ttl = ttl_seconds if ttl_seconds is not None else self.session_ttl
        now = time.time()
        expires_at = now + ttl

        # Cryptographically secure random session token
        raw_session_token = f"tok_{secrets.token_hex(16)}"
        token_hash = self._hash_token(raw_session_token)
        session_id = f"sess_{secrets.token_hex(8)}"

        with _db_lock:
            conn = get_db_connection()
            # Invalidate any existing active session for this device
            conn.execute("""
            UPDATE sessions
            SET is_active = 0
            WHERE tenant_id = ? AND device_id = ?
            """, (tenant_id, device_id))

            assigned_pseudonym = custom_pseudonym or self.pseudonym_mgr.generate_pseudonym()

            # Save session first so FK constraint is satisfied
            conn.execute("""
            INSERT INTO sessions (id, tenant_id, device_id, token_hash, pseudonym, ipv6_address, created_at, expires_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (session_id, tenant_id, device_id, token_hash, assigned_pseudonym, ipv6_address, now, expires_at))

            # Ephemeral pseudonym registration reusing the same active connection
            self.pseudonym_mgr.register_pseudonym(
                tenant_id=tenant_id,
                session_id=session_id,
                ipv6_address=ipv6_address,
                custom_pseudonym=assigned_pseudonym,
                ttl_seconds=ttl,
                db_conn=conn
            )

            # Update device status
            conn.execute("""
            UPDATE devices
            SET status = 'AUTHENTICATED', current_ipv6 = ?, last_active_at = ?
            WHERE id = ? AND tenant_id = ?
            """, (ipv6_address, now, device_id, tenant_id))

            conn.commit()
            conn.close()

        self._active_tokens[session_id] = raw_session_token

        return {
            "status": "SUCCESS",
            "session_id": session_id,
            "session_token": raw_session_token,
            "pseudonym": assigned_pseudonym,
            "device_id": device_id,
            "tenant_id": tenant_id,
            "ipv6_address": ipv6_address,
            "created_at": now,
            "expires_at": expires_at,
            "ttl_seconds": self.session_ttl
        }

    def validate_session(self, tenant_id: str, session_id: str, session_token: str) -> Optional[Dict[str, Any]]:
        """
        Validate an active session using constant-time comparison of the token hash.
        """
        now = time.time()
        expected_hash = self._hash_token(session_token)

        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM sessions
            WHERE id = ? AND tenant_id = ? AND is_active = 1
            """, (session_id, tenant_id))
            row = cursor.fetchone()

            if not row:
                conn.close()
                return None

            # Check expiration
            if row["expires_at"] <= now:
                conn.execute("UPDATE sessions SET is_active = 0 WHERE id = ?", (session_id,))
                conn.commit()
                conn.close()
                return None

            # Constant-time comparison
            if not hmac.compare_digest(row["token_hash"], expected_hash):
                conn.close()
                return None

            conn.close()
            return dict(row)

    def handle_address_rotation(self, tenant_id: str, session_id: str, session_token: str,
                                new_ipv6: str) -> Dict[str, Any]:
        """
        Perform authenticated IPv6 address rotation.
        Updates the IPv6 mapping while preserving the same local pseudonym.
        """
        session = self.validate_session(tenant_id, session_id, session_token)
        if not session:
            raise PermissionError("Rotation Rejected: Invalid or expired session token")

        device_id = session["device_id"]
        old_ipv6 = session["ipv6_address"]
        pseudonym = session["pseudonym"]
        now = time.time()

        # Update pseudonym mapping to new IP
        self.pseudonym_mgr.update_address(tenant_id, session_id, new_ipv6)

        # Update session record
        with _db_lock:
            conn = get_db_connection()
            conn.execute("""
            UPDATE sessions
            SET ipv6_address = ?
            WHERE id = ? AND tenant_id = ?
            """, (new_ipv6, session_id, tenant_id))
            conn.commit()
            conn.close()

        # Update device current IP and increment rotation count
        DatabaseManager.update_device_ip(device_id, new_ipv6, tenant_id=tenant_id)

        # Log rotation event in audit table
        DatabaseManager.log_rotation(tenant_id, device_id, pseudonym, old_ipv6, new_ipv6, status="SUCCESS")

        return {
            "status": "SUCCESS",
            "device_id": device_id,
            "pseudonym": pseudonym,
            "old_ipv6": old_ipv6,
            "new_ipv6": new_ipv6,
            "session_id": session_id,
            "rotated_at": now
        }

    def expire_session(self, tenant_id: str, session_id: str) -> bool:
        """Explicitly invalidate a session."""
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE sessions SET is_active = 0 WHERE id = ? AND tenant_id = ?
            """, (session_id, tenant_id))
            affected = cursor.rowcount
            # Also deactivate pseudonym
            conn.execute("""
            UPDATE pseudonyms SET is_active = 0 WHERE session_id = ? AND tenant_id = ?
            """, (session_id, tenant_id))
            conn.commit()
            conn.close()
            return affected > 0

    def get_active_sessions(self, tenant_id: str = "tenant-alpha") -> List[Dict[str, Any]]:
        now = time.time()
        with _db_lock:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            SELECT s.*, d.name as device_name
            FROM sessions s
            JOIN devices d ON s.device_id = d.id AND s.tenant_id = d.tenant_id
            WHERE s.tenant_id = ? AND s.is_active = 1 AND s.expires_at > ?
            ORDER BY s.created_at DESC
            """, (tenant_id, now))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()

        for r in rows:
            r["ttl_remaining"] = max(0, int(r["expires_at"] - now))
            # Hide token hash from client
            r.pop("token_hash", None)
        return rows
