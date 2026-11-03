# System Architecture: PS-007
## Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

---

## 1. Executive Summary

Modern IPv6 internet-of-things (IoT) devices periodically rotate their temporary 64-bit interface identifiers (IIDs) via **RFC 4941 Privacy Extensions** to protect consumer privacy against ISP and internet-wide surveillance. However, this creates a significant challenge for network security administrators: when a device changes its IPv6 address, security correlation mechanisms lose track of the device's session state. Traditional solutions resort to permanent hardware identifiers (MAC addresses, EUI-64, hardware serial numbers) or behavioral profiling—both of which defeat user privacy.

**PS-007** solves this dilemma through **Authenticated Short-Lived Ephemeral Pseudonyms**. The system decouples network identity from global hardware addresses while allowing local, authorized security monitors to track devices across address rotations without permanent fingerprints, cross-tenant linkability, or historical identity retention.

---

## 2. Architectural Topology

```
+----------------------------------------------------------------------------------------------------+
|                                    IPv6 LAN Subnet: 2001:db8:1::/64                                |
|                                                                                                    |
|  +--------------------+   +--------------------+   +--------------------+   +--------------------+ |
|  |    Smart Camera    |   |      Smart TV      |   |     Smart Bulb     |   |   Smart Speaker    | |
|  | 2001:db8:1::101    |   | 2001:db8:1::102    |   | 2001:db8:1::103    |   | 2001:db8:1::104    | |
|  | Pseudonym: DEV-P01 |   | Pseudonym: DEV-P02 |   | Pseudonym: DEV-P03 |   | Pseudonym: DEV-P04 | |
|  +---------+----------+   +---------+----------+   +---------+----------+   +---------+----------+ |
|            |                        |                        |                        |            |
|            +------------------------+------------------------+------------------------+            |
|                                     |                                                              |
|                                     v                                                              |
|                     +-------------------------------+                                              |
|                     |       Linux Bridge br-iot0    |                                              |
|                     |     IPv6: 2001:db8:1::1/64    |                                              |
|                     +---------------+---------------+                                              |
|                                     |                                                              |
|                                     v                                                              |
|                 +---------------------------------------+                                          |
|                 |    Packet Monitor Engine (Scapy)      |                                          |
|                 |  - Linux: AsyncSniffer (Raw Capture)  |                                          |
|                 |  - macOS: Safe Simulated Packet Queue |                                          |
|                 +-------------------+-------------------+                                          |
|                                     |                                                              |
+-------------------------------------|--------------------------------------------------------------+
                                      v
+----------------------------------------------------------------------------------------------------+
|                                   MONITORING BACKEND SUBSYSTEM                                     |
|                                                                                                    |
|   +--------------------------+  +--------------------------+  +--------------------------------+   |
|   |    Pseudonym Manager     |  |     Session Manager      |  |         Attack Detector        |   |
|   | - Cryptographic Nonces   |  | - SHA-256 Hashed Tokens  |  | - Rogue RA Whitelist Check     |   |
|   | - Ephemeral Pseudonyms   |  | - TTL Lifecycle (120s)   |  | - Sliding-Window NDP Flooding  |   |
|   | - Forward/Backward Priv  |  | - Rotation Handshake     |  | - Pseudonym Correlation        |   |
|   | - Auto-Purge of Expired  |  | - Tamper Rejection       |  | - Real-time TP/FP/TN/FN Metric |   |
|   +-------------+------------+  +-------------+------------+  +---------------+----------------+   |
|                 |                             |                               |                    |
|                 +----------------------+------+-------------------------------+                    |
|                                        v                                                           |
|                       +---------------------------------+                                          |
|                       |   SQLite Isolation Store        |                                          |
|                       | - Multi-Tenant Namespaces       |                                          |
|                       | - Zero MAC Address Retention    |                                          |
|                       | - WAL Mode & Foreign Key Casc   |                                          |
|                       +----------------+----------------+                                          |
|                                        |                                                           |
|                                        v                                                           |
|                       +---------------------------------+                                          |
|                       |        Flask REST APIs          |                                          |
|                       | /api/dashboard, /api/devices    |                                          |
|                       | /api/traffic, /api/alerts       |                                          |
|                       +----------------+----------------+                                          |
+----------------------------------------|-----------------------------------------------------------+
                                         v
+----------------------------------------------------------------------------------------------------+
|                                 CYBERSECURITY FRONTEND DASHBOARD                                   |
| - Enterprise Light Theme (White / Slate / Tech Blue)                                               |
| - Responsive Bootstrap 5 + Modular Vanilla ES6 (dashboard.js, devices.js, monitoring.js, alerts.js) |
| - Real-time Chart.js Visualizations (Traffic Line Chart, ICMPv6 Doughnut, Evaluation Bar Chart)   |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Core Subsystems

### 3.1 Five Virtual IoT Devices
- **Smart Camera** (`dev-camera-01`): High-priority security camera node.
- **Smart TV** (`dev-tv-02`): Entertainment hub streaming telemetry.
- **Smart Bulb** (`dev-bulb-03`): Low-power smart lighting node.
- **Smart Speaker** (`dev-speaker-04`): Voice assistant node.
- **Smart Door Sensor** (`dev-doorsensor-05`): Access control telemetry node.

Each device maintains:
- Active RFC 4941 IPv6 address (e.g., `2001:db8:1::101`, rotating to `2001:db8:1::201`).
- Ephemeral cryptographic session token (`tok_<hex32>`).
- Local pseudonym (e.g., `DEV-P01`).
- Rotation counter and session TTL.

### 3.2 Ephemeral Pseudonym & Privacy Architecture
1. **Zero Permanent Fingerprints**: The system does not inspect, parse, or store MAC addresses, EUI-64 addresses, vendor OUIs, or hardware serial numbers.
2. **Forward and Backward Unlinkability**: When an address rotates, the previous IP binding is purged upon session expiration. An external adversary observing traffic on the WAN cannot link past temporary IPv6 addresses to future addresses.
3. **Automated Secure Purging**: A background thread continuously sweeps expired mappings and erases them from SQLite using atomic transactions.

### 3.3 Deep Packet Inspection (Scapy)
The system leverages Scapy for ICMPv6 protocol analysis:
- **Router Advertisement (RA, Type 134)**: Inspected for authorized router whitelist compliance.
- **Router Solicitation (RS, Type 133)**: Monitored for baseline network discovery.
- **Neighbor Solicitation (NS, Type 135)**: Tracked for sliding-window rate metering.
- **Neighbor Advertisement (NA, Type 136)**: Tracked for sliding-window rate metering.
- **Echo Request / Reply (Types 128 / 129)**: Verified for node reachability.

### 3.4 Multi-Tenant Namespace Isolation
Each database table (`tenants`, `devices`, `sessions`, `pseudonyms`, `address_rotations`, `network_events`, `security_alerts`) is partitioned by `tenant_id`.
- Tenant Alpha (`tenant-alpha`) has full autonomy over its 5 IoT devices.
- Tenant Beta (`tenant-beta`) operates in a cryptographically isolated namespace.
- Queries, address resolution, and pseudonym lookups across tenant boundaries return `None`, guaranteeing zero data leakage.

