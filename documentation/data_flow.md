# Data Flow & Protocol Sequences: PS-007
## Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

---

## 1. Initial Device Bootstrap & Ephemeral Pseudonym Assignment

When an IoT device boots, it configures a temporary SLAAC IPv6 address and initiates a mutual authentication handshake with the monitoring server.

```mermaid
sequenceDiagram
    autonumber
    participant D as IoT Device (Smart Camera)
    participant M as Session Manager
    participant P as Pseudonym Manager
    participant DB as SQLite Storage

    Note over D: Configures RFC 4941 IPv6 (2001:db8:1::101)
    D->>M: POST /api/devices/authenticate (device_id, secret, IPv6)
    M->>M: Verify pre-shared credential / signature
    M->>M: Generate raw session token (tok_hex32)
    M->>M: Compute SHA-256 token hash
    M->>P: Request local pseudonym (session_id, IPv6, TTL=120s)
    P->>P: Generate cryptographically random pseudonym (DEV-P01)
    P->>DB: INSERT into pseudonyms (DEV-P01, IPv6, expires_at)
    M->>DB: INSERT into sessions (token_hash, DEV-P01, IPv6, expires_at)
    M-->>D: Return {session_id, session_token, pseudonym: "DEV-P01", TTL: 120s}
    Note over D: Stores session token locally in volatile RAM
```

---

## 2. RFC 4941 Address Rotation Handshake

When the device's temporary address rotation timer expires, the device rotates its address without exposing hardware identifiers.

```mermaid
sequenceDiagram
    autonumber
    participant D as IoT Device (Smart Camera)
    participant R as Address Rotator (RFC 4941)
    participant M as Session Manager
    participant P as Pseudonym Manager
    participant DB as SQLite Storage

    Note over D: Previous IPv6: 2001:db8:1::101, Pseudonym: DEV-P01
    D->>R: Generate next random 64-bit Interface Identifier
    R-->>D: New IPv6: 2001:db8:1::201
    D->>M: POST /api/devices/rotate (session_id, session_token, new_ipv6)
    M->>M: Constant-time HMAC comparison (SHA-256 token_hash)
    alt Invalid or Expired Token
        M-->>D: 403 Forbidden: Session Expired / Unauthorized
    else Valid Active Session
        M->>P: update_address(session_id, new_ipv6: 2001:db8:1::201)
        P->>DB: UPDATE pseudonyms SET current_ipv6 = '2001:db8:1::201' WHERE session_id = ?
        M->>DB: UPDATE sessions SET ipv6_address = '2001:db8:1::201' WHERE id = ?
        M->>DB: INSERT INTO address_rotations (old_ipv6, new_ipv6, pseudonym: "DEV-P01")
        M-->>D: Return {status: "SUCCESS", pseudonym: "DEV-P01", new_ipv6: "2001:db8:1::201"}
        Note over D,M: Local Pseudonym DEV-P01 remains seamlessly bound!
    end
```

---

## 3. Rogue Router Advertisement (RA) Detection Flow

An attacker virtual router broadcasts unauthorized ICMPv6 RA packets.

```mermaid
sequenceDiagram
    autonumber
    participant Atk as Rogue Router (2001:db8:1::bad:1)
    participant Net as IPv6 Virtual LAN (br-iot0)
    participant Scapy as Scapy DPI Sniffer
    participant Det as Attack Detector
    participant DB as SQLite Storage
    participant UI as Cybersecurity Dashboard

    Atk->>Net: Broadcast ICMPv6 RA (Type 134, prefix: 2001:db8:666::/64)
    Net->>Scapy: Raw Packet Captured on Bridge
    Scapy->>Det: inspect_ra_packet(src="2001:db8:1::bad:1", advertised_prefix)
    Det->>Det: Compare src against Trusted Whitelist {"2001:db8:1::1", "fe80::1"}
    Note over Det: Source NOT in whitelist! Malicious Prefix Detected.
    Det->>Det: Measure latency = (t_now - t_packet) [e.g. 0.85 ms]
    Det->>DB: INSERT INTO security_alerts (severity: CRITICAL, attack_type: "ROGUE_ROUTER_ADVERTISEMENT")
    Det-->>Scapy: Security Alert Object Created
    Scapy->>DB: Log network event
    UI->>DB: GET /api/alerts (Live Polling)
    UI-->>UI: Trigger Red Alert Badge & Visual Intrusion Notification
```

---

## 4. Abnormal NDP Flooding Detection & Pseudonym Correlation Flow

A compromised IoT device or attacker floods Neighbor Solicitations (NS).

```mermaid
sequenceDiagram
    autonumber
    participant Dev as Flooding Node (2001:db8:1::104)
    participant Net as IPv6 LAN
    participant Scapy as Scapy DPI
    participant Det as Attack Detector
    participant P as Pseudonym Manager
    participant DB as SQLite Storage
    participant UI as Dashboard

    loop 25 packets / sec
        Dev->>Net: ICMPv6 NS (Type 135, tgt: 2001:db8:1::1)
        Net->>Scapy: Enqueue Packet into Monitoring Pipeline
        Scapy->>Det: inspect_ndp_packet(src="2001:db8:1::104", type=135)
        Det->>Det: Append timestamp to sliding-window buffer (window: 3.0s)
        Det->>Det: Calculate rate: len(timestamps) / 3.0s
    end
    Note over Det: Rate = 25.0 pkts/s > Threshold (6.0 pkts/s)!
    Det->>P: resolve_ipv6("tenant-alpha", "2001:db8:1::104")
    P-->>Det: Return Pseudonym: "DEV-P04" (Identified without MAC!)
    Det->>DB: INSERT INTO security_alerts (severity: HIGH, attack_type: "ABNORMAL_NDP_FLOODING", pseudonym: "DEV-P04")
    UI->>DB: GET /api/alerts & GET /api/devices
    UI-->>UI: Highlight Smart Speaker status as "ALERT" & display correlated pseudonym
```

---

## 5. Ephemeral Mapping Expiration & Secure Deletion Flow

Enforcing forward and backward unlinkability by deleting expired pseudonym records.

```mermaid
sequenceDiagram
    autonumber
    participant Timer as Background Maintenance Sweeper
    participant P as Pseudonym Manager
    participant DB as SQLite Storage

    Note over Timer: Runs every 10 seconds in background
    Timer->>P: purge_expired_mappings()
    P->>DB: SELECT COUNT(*) WHERE expires_at <= now OR is_active = 0
    DB-->>P: Count of expired records
    alt Expired Records Exist
        P->>DB: DELETE FROM pseudonyms WHERE expires_at <= now OR is_active = 0
        DB-->>P: Deleted rowcount
        Note over P,DB: Expired records completely erased from disk (Zero identity history)
    end
    P-->>Timer: Total Purged Count Updated
```

