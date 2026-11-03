# PS-007: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask-green.svg)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Networking-Scapy%20DPI-orange.svg)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)
[![Acceptance Tests](https://img.shields.io/badge/Acceptance%20Tests-9%2F9%20Passed-brightgreen.svg)]()

> **Project ID:** PS-007  
> **Category:** Cloud Computing & IoT  
> **Project Type:** Software-based Cybersecurity Monitoring System  

---

## 1. Problem Statement

Modern IPv6 internet-of-things (IoT) devices periodically rotate their temporary 64-bit interface identifiers (IIDs) according to **RFC 4941 Privacy Extensions** to prevent tracking across the internet. However, this poses a severe security challenge for local network administrators: **when an IoT device changes its IPv6 address, security correlation mechanisms lose track of its identity**, making it difficult to detect compromised devices or correlate malicious activity over time.

Traditional attempts to solve this problem compromise privacy by:
1. Deriving identities from permanent hardware identifiers (MAC addresses, EUI-64, vendor OUIs).
2. Constructing invasive behavioral profiles that can be exploited for internet-wide surveillance.

### Our Solution
**PS-007** resolves this paradox by combining:
- **Authenticated Ephemeral Sessions**: Cryptographic token-based session management.
- **Local Short-Lived Pseudonyms**: Ephemeral pseudonyms (e.g., `DEV-P01`) assigned per session.
- **Continuous Correlation Across Rotation**: Devices authenticate address rotations, seamlessly maintaining their pseudonym mapping without hardware fingerprinting.
- **Zero Identity Retention**: Expired mappings are purged automatically to enforce forward and backward privacy.
- **Scapy ICMPv6 Deep Packet Inspection**: Real-time detection of Rogue Router Advertisements and Abnormal Neighbor Discovery Protocol (NDP) flooding.
- **Strict Multi-Tenant Isolation**: Separate tenant namespaces prevent cross-tenant correlation.

---

## 2. Five Virtual IoT Devices

The simulator models five distinct IoT endpoints connected to an isolated IPv6 LAN:

| Device Name | Device ID | Default Type | Initial Temporary IPv6 | Pre-shared Key |
| :--- | :--- | :--- | :--- | :--- |
| **Smart Camera** | `dev-camera-01` | Security Camera | `2001:db8:1::101` | `secret_camera_key_7a9f` |
| **Smart TV** | `dev-tv-02` | Entertainment Hub | `2001:db8:1::102` | `secret_tv_key_4b2c` |
| **Smart Bulb** | `dev-bulb-03` | Smart Lighting | `2001:db8:1::103` | `secret_bulb_key_9e1d` |
| **Smart Speaker** | `dev-speaker-04` | Voice Assistant | `2001:db8:1::104` | `secret_speaker_key_3f8a` |
| **Smart Door Sensor** | `dev-doorsensor-05` | Access Control | `2001:db8:1::105` | `secret_doorsensor_key_5c6b` |

---

## 3. Technology Stack

- **Backend**: Python 3.10+, Flask, Scapy, SQLite (WAL mode with foreign keys), REST APIs.
- **Networking**: IPv6, ICMPv6, Linux Network Namespaces (`ip netns`), Linux Bridge (`br-iot0`), Virtual Ethernet (`veth`).
- **Frontend**: HTML5, CSS3, JavaScript (ES6+), Bootstrap 5, Chart.js.
- **Cross-Platform Compatibility**: Native Scapy sniffing on Linux (Ubuntu ARM64 / UTM) + Safe Simulation Packet Ingestion Pipeline on macOS.

---

## 4. Quickstart Guide

### 4.1 Prerequisites
Ensure Python 3.10 or higher is installed:
```bash
python3 --version
```

### 4.2 Clone and Setup Environment
```bash
# Navigate to the project root
cd AIORI_AL_PS007

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 4.3 Launch Application Server
```bash
# Start backend server on port 5005
python3 backend/app.py --port 5005
```

Open your browser and navigate to:
```
http://127.0.0.1:5005
```

---

## 5. Running Automated Acceptance Tests

To demonstrate the complete end-to-end functionality of all **9 Acceptance Criteria**:

```bash
# Ensure the virtualenv is active and server is running
python3 tests/run_acceptance_tests.py
```

### Acceptance Test Summary

| Test | Objective | Verification Result |
| :---: | :--- | :---: |
| **TEST 1** | Start five IoT devices and display on dashboard | **PASS** |
| **TEST 2** | Authenticate all devices and assign local pseudonyms | **PASS** |
| **TEST 3** | Rotate Smart Camera IPv6 address & verify pseudonym remains unchanged | **PASS** |
| **TEST 4** | Launch Rogue RA simulation & verify detection alert | **PASS** |
| **TEST 5** | Launch NDP flooding simulation & verify abnormal rate alert | **PASS** |
| **TEST 6** | Expire a pseudonym mapping & verify secure deletion | **PASS** |
| **TEST 7** | Simulate multi-tenants & verify zero cross-tenant leakage | **PASS** |
| **TEST 8** | Display actual detection evaluation metrics (Recall: 100%, Precision: 100%) | **PASS** |
| **TEST 9** | Server health and operational stability check | **PASS** |

### Unit & Integration Test Suite
```bash
pytest tests/test_*.py -v
```
All 12 unit tests pass in under 1.5 seconds.

---

## 6. Linux UTM Virtual Machine Network Setup

When executing on an **Ubuntu ARM64 Linux VM** (e.g., via UTM on Apple Silicon):

```bash
# Generate the automated network configuration script
python3 simulation/create_network.py

# Run network setup script with root permissions
sudo bash setup_linux_netns.sh
```

This creates:
- Linux Bridge `br-iot0` with IPv6 `2001:db8:1::1/64`
- Namespaces: `ns-mon`, `ns-iot1` to `ns-iot5`, and `ns-attacker`
- Dedicated virtual ethernet interfaces connecting each namespace to the bridge

To run the monitoring station inside `ns-mon`:
```bash
sudo ip netns exec ns-mon python3 backend/app.py --port 5005
```

To tear down the network:
```bash
sudo bash teardown_linux_netns.sh
```

---

## 7. REST API Documentation

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/dashboard` | Overall telemetry, health score, packet rates |
| `GET` | `/api/devices` | 5 virtual devices status, pseudonyms, NDP rates |
| `GET` | `/api/sessions` | Active sessions with TTL status |
| `GET` | `/api/traffic` | Scapy packet stream and ICMPv6 breakdown |
| `GET` | `/api/alerts` | Security alerts list with severity and latency |
| `GET` | `/api/rotations` | Address rotation audit log history |
| `GET` | `/api/privacy` | Active vs purged pseudonyms, compliance audit |
| `GET` | `/api/evaluation` | Actual TP, FP, TN, FN, Precision, Recall, Latency |
| `POST` | `/api/devices/authenticate` | Authenticate device and assign pseudonym |
| `POST` | `/api/devices/rotate` | Trigger RFC 4941 temporary address rotation |
| `POST` | `/api/simulation/start` | Start attack (`rogue_ra`, `ndp_flood`, `normal`) |
| `POST` | `/api/simulation/stop` | Halt active attack simulations |
| `POST` | `/api/privacy/purge` | Purge expired pseudonym records |
| `POST` | `/api/privacy/test-isolation` | Execute live tenant isolation test |
| `POST` | `/api/evaluation/run` | Execute evaluation benchmark suite |
| `POST` | `/api/alerts/ack` | Acknowledge alert |

---

## 8. Repository Layout

```
PS-007/
├── backend/
│   ├── app.py                 # Flask Server & Static Asset Host
│   ├── database.py            # SQLite Multi-Tenant Storage Layer
│   ├── packet_monitor.py      # Scapy ICMPv6 Packet Sniffer Engine
│   ├── ipv6_monitor.py        # Central Subsystem Coordinator & Metrics
│   ├── session_manager.py     # Ephemeral Session & Token Lifecycle
│   ├── pseudonym_manager.py   # Ephemeral Pseudonym Invalidation & Privacy
│   ├── attack_detector.py     # Rogue RA & Sliding-Window NDP Detector
│   └── routes.py              # REST API Endpoints
├── simulation/
│   ├── create_network.py      # Linux Namespaces & Bridge Generator
│   ├── device_simulator.py    # Five Virtual IoT Devices Controller
│   ├── address_rotation.py    # RFC 4941 Address Generator & Handshake
│   ├── rogue_ra.py            # Rogue Router Advertisement Attack Injector
│   ├── ndp_flood.py           # Abnormal NDP Flood Attack Injector
│   └── normal_traffic.py      # Benign Baseline Traffic Generator
├── frontend/
│   ├── index.html             # Enterprise Cybersecurity Dashboard Single-Page UI
│   ├── css/
│   │   └── style.css          # Minimalist Light Cybersecurity Theme
│   └── js/
│       ├── dashboard.js       # Telemetry Polling, Health Meter, Rate Charts
│       ├── devices.js         # Device Table, Manual Address Rotation
│       ├── monitoring.js      # Scapy Live Packet Stream & ICMPv6 Doughnut
│       └── alerts.js          # Security Alerts, Simulator Controls, Evaluation
├── tests/
│   ├── test_authentication.py # Auth & Ephemeral Credentials Unit Tests
│   ├── test_rotation.py       # Address Rotation & Pseudonym Persistence Tests
│   ├── test_detection.py      # Rogue RA & NDP Flooding Detection Tests
│   ├── test_privacy.py        # TTL Expiration & Tenant Isolation Tests
│   └── run_acceptance_tests.py# End-to-End Suite for the 9 Acceptance Criteria
├── documentation/
│   ├── architecture.md        # Comprehensive System Architecture
│   ├── data_flow.md           # Mermaid Protocol Sequence Diagrams
│   ├── pseudocode.md          # Algorithmic Pseudocode & Complexity
│   └── evaluation.md          # Empirical Benchmark & Performance Report
├── requirements.txt           # Python Package Dependencies
├── setup_linux_netns.sh       # Generated Linux Network Setup Script
├── teardown_linux_netns.sh    # Generated Linux Network Teardown Script
└── README.md                  # Complete System Guide
```

---

## 9. Cybersecurity & Privacy Guarantees

1. **Zero MAC Address Retention**: MAC addresses and hardware IDs are never stored in the database.
2. **RFC 4941 SLAAC Compliance**: Temporary interface identifiers are generated using cryptographically secure pseudo-random nonces.
3. **Forward & Backward Privacy**: Expired pseudonyms are purged, rendering past temporary addresses unlinkable to future temporary addresses.
4. **Strict Multi-Tenant Isolation**: Tenant Alpha cannot correlate or inspect Tenant Beta sessions or traffic.
5. **Real-time Threat Mitigation**: Rogue Router Advertisements and high-rate NDP floods are identified with average detection latency under **4 ms**.

