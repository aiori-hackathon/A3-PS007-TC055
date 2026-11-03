"""
packet_monitor.py - Scapy-Powered IPv6 ICMPv6 Deep Packet Inspection Engine
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

Dual Execution Architecture:
- Linux Host / UTM Ubuntu VM: Live Scapy AsyncSniffer on br-iot0 or veth-mon.
- Cross-Platform / macOS Simulation: Safe Scapy Packet Queue executing identical
  decoding, metadata extraction, pseudonym resolution, and attack detection routines.
"""

import os
import sys
import time
import platform
import threading
import queue
from typing import Dict, Any, Optional, List, Callable

# Clean Scapy configuration to avoid DNS resolver permission issues on macOS/sandboxes
import scapy.config
scapy.config.conf.nameservers = ['2001:4860:4860::8888', '8.8.8.8']
try:
    import scapy.arch.common
    scapy.arch.common.read_nameservers = lambda: ['2001:4860:4860::8888', '8.8.8.8']
except Exception:
    pass

from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    _ICMPv6
)
from scapy.packet import Packet

from database import DatabaseManager
from pseudonym_manager import PseudonymManager
from attack_detector import AttackDetector

ICMPV6_TYPE_MAP = {
    133: "Router Solicitation (RS)",
    134: "Router Advertisement (RA)",
    135: "Neighbor Solicitation (NS)",
    136: "Neighbor Advertisement (NA)",
    128: "Echo Request (Ping)",
    129: "Echo Reply (Pong)",
}

class PacketMonitor:
    def __init__(self, pseudonym_mgr: PseudonymManager, attack_detector: AttackDetector,
                 tenant_id: str = "tenant-alpha", interface: str = "br-iot0"):
        self.pseudonym_mgr = pseudonym_mgr
        self.attack_detector = attack_detector
        self.tenant_id = tenant_id
        self.interface = interface

        self.os_type = platform.system()
        self.is_linux = (self.os_type == "Linux")
        self.is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        self.can_raw_sniff = self.is_linux and self.is_root

        self.mode = "LINUX_RAW_CAPTURE" if self.can_raw_sniff else "SIMULATION_PIPELINE"
        self.is_running = False

        self._packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._worker_thread: Optional[threading.Thread] = None
        self._sniffer = None
        self._lock = threading.RLock()

        # Telemetry & Statistics
        self.total_packets_processed = 0
        self.type_counts = {
            "RA": 0,
            "RS": 0,
            "NS": 0,
            "NA": 0,
            "ECHO": 0,
            "OTHER": 0
        }
        self.recent_packets_buffer: List[Dict[str, Any]] = []
        self.start_time = time.time()

    def start(self) -> None:
        """Start the packet monitoring engine."""
        with self._lock:
            if self.is_running:
                return
            self.is_running = True

        # Start the internal packet processing consumer thread
        self._worker_thread = threading.Thread(target=self._process_queue_loop, daemon=True)
        self._worker_thread.start()

        # If on Linux with raw capture rights, start Scapy AsyncSniffer
        if self.can_raw_sniff:
            try:
                from scapy.sendrecv import AsyncSniffer
                self._sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter="icmp6",
                    prn=self.enqueue_packet,
                    store=False
                )
                self._sniffer.start()
            except Exception as e:
                # Fall back to simulation pipeline safely
                self.mode = "SIMULATION_PIPELINE"
                self.can_raw_sniff = False

    def stop(self) -> None:
        """Stop packet monitoring engine."""
        with self._lock:
            self.is_running = False

        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    def enqueue_packet(self, packet: Any, is_ground_truth_attack: Optional[bool] = None) -> None:
        """Enqueue a packet (either live Scapy packet or simulated packet)."""
        try:
            self._packet_queue.put_nowait((packet, time.time(), is_ground_truth_attack))
        except queue.Full:
            pass  # Avoid memory exhaustion under heavy flood

    def _process_queue_loop(self) -> None:
        """Continuously process packets from queue."""
        while self.is_running:
            try:
                item = self._packet_queue.get(timeout=0.2)
                packet, enqueue_time, is_attack = item
                self._parse_and_inspect_packet(packet, enqueue_time, is_attack)
                self._packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                pass

    def _parse_and_inspect_packet(self, packet: Any, enqueue_time: float,
                                  is_attack: Optional[bool] = None) -> Optional[Dict[str, Any]]:
        """Parse packet with Scapy layers and run through detection rules."""
        if not isinstance(packet, Packet) and not hasattr(packet, "haslayer"):
            return None

        # Verify it has IPv6 layer
        if not packet.haslayer(IPv6):
            return None

        ipv6_layer = packet[IPv6]
        src_ip = ipv6_layer.src
        dst_ip = ipv6_layer.dst
        pkt_len = len(packet)

        icmp_type = None
        icmp_name = "Unknown ICMPv6"
        advertised_prefix = None

        if packet.haslayer(ICMPv6ND_RA):
            icmp_type = 134
            icmp_name = "Router Advertisement (RA)"
            with self._lock:
                self.type_counts["RA"] += 1

            # Extract advertised prefix if present
            if packet.haslayer(ICMPv6NDOptPrefixInfo):
                prefix_opt = packet[ICMPv6NDOptPrefixInfo]
                advertised_prefix = f"{prefix_opt.prefix}/{prefix_opt.prefixlen}"

            # Pass to Rogue RA detector
            self.attack_detector.inspect_ra_packet(
                src_ipv6=src_ip,
                dst_ipv6=dst_ip,
                advertised_prefix=advertised_prefix,
                packet_timestamp=enqueue_time,
                is_ground_truth_attack=is_attack
            )

        elif packet.haslayer(ICMPv6ND_RS):
            icmp_type = 133
            icmp_name = "Router Solicitation (RS)"
            with self._lock:
                self.type_counts["RS"] += 1

        elif packet.haslayer(ICMPv6ND_NS):
            icmp_type = 135
            icmp_name = "Neighbor Solicitation (NS)"
            with self._lock:
                self.type_counts["NS"] += 1

            # Pass to NDP flood detector
            self.attack_detector.inspect_ndp_packet(
                src_ipv6=src_ip,
                icmpv6_type=135,
                packet_timestamp=enqueue_time,
                is_ground_truth_attack=is_attack
            )

        elif packet.haslayer(ICMPv6ND_NA):
            icmp_type = 136
            icmp_name = "Neighbor Advertisement (NA)"
            with self._lock:
                self.type_counts["NA"] += 1

            # Pass to NDP flood detector
            self.attack_detector.inspect_ndp_packet(
                src_ipv6=src_ip,
                icmpv6_type=136,
                packet_timestamp=enqueue_time,
                is_ground_truth_attack=is_attack
            )

        elif packet.haslayer(ICMPv6EchoRequest):
            icmp_type = 128
            icmp_name = "Echo Request"
            with self._lock:
                self.type_counts["ECHO"] += 1

        elif packet.haslayer(ICMPv6EchoReply):
            icmp_type = 129
            icmp_name = "Echo Reply"
            with self._lock:
                self.type_counts["ECHO"] += 1
        else:
            with self._lock:
                self.type_counts["OTHER"] += 1
            return None

        # Resolve local pseudonym
        pseudonym = self.pseudonym_mgr.resolve_ipv6(self.tenant_id, src_ip)

        metadata_dict = {
            "mode": self.mode,
            "hop_limit": ipv6_layer.hlim,
            "advertised_prefix": advertised_prefix
        }

        # Save to database
        DatabaseManager.log_network_event(
            tenant_id=self.tenant_id,
            src_ipv6=src_ip,
            dst_ipv6=dst_ip,
            icmpv6_type=icmp_type,
            icmpv6_name=icmp_name,
            length=pkt_len,
            pseudonym=pseudonym,
            is_attack=1 if is_attack else 0,
            metadata=str(metadata_dict)
        )

        event_obj = {
            "timestamp": enqueue_time,
            "src_ipv6": src_ip,
            "dst_ipv6": dst_ip,
            "icmpv6_type": icmp_type,
            "icmpv6_name": icmp_name,
            "length": pkt_len,
            "pseudonym": pseudonym,
            "is_attack": bool(is_attack)
        }

        with self._lock:
            self.total_packets_processed += 1
            self.recent_packets_buffer.insert(0, event_obj)
            if len(self.recent_packets_buffer) > 100:
                self.recent_packets_buffer.pop()

        return event_obj

    def get_status(self) -> Dict[str, Any]:
        """Get live monitoring telemetry."""
        now = time.time()
        elapsed = max(1.0, now - self.start_time)
        with self._lock:
            return {
                "status": "RUNNING" if self.is_running else "STOPPED",
                "mode": self.mode,
                "platform": f"{self.os_type} ({'Linux Raw Sniff' if self.can_raw_sniff else 'Safe Simulation Pipeline'})",
                "interface": self.interface if self.can_raw_sniff else "virtual-lo0",
                "total_packets_processed": self.total_packets_processed,
                "packets_per_second": round(self.total_packets_processed / elapsed, 2),
                "type_distribution": dict(self.type_counts),
                "recent_packets": list(self.recent_packets_buffer[:20])
            }
