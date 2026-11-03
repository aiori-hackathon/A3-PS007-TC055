"""
ndp_flood.py - Abnormal Neighbor Discovery Protocol (NDP) Flood Attack Simulator
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

Simulates high-volume Neighbor Solicitation (NS) or Neighbor Advertisement (NA)
bursts designed to exhaust neighbor caches and disrupt IPv6 connectivity.
"""

import time
import threading
from typing import Optional, Callable

# Clean Scapy configuration
import scapy.config
scapy.config.conf.nameservers = ['8.8.8.8']
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA

class NDPFloodSimulator:
    def __init__(self, packet_sink: Optional[Callable[[any, bool], None]] = None,
                 src_ipv6: str = "2001:db8:1::104",  # Default: Smart Speaker or attacker
                 target_ipv6: str = "2001:db8:1::1",
                 flood_rate_pps: int = 20):
        self.packet_sink = packet_sink
        self.src_ipv6 = src_ipv6
        self.target_ipv6 = target_ipv6
        self.flood_rate_pps = flood_rate_pps
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.packets_sent = 0

    def craft_ns_packet(self, src: Optional[str] = None):
        """Craft Neighbor Solicitation packet."""
        s = src or self.src_ipv6
        return IPv6(src=s, dst="ff02::1:ff00:1", hlim=255) / ICMPv6ND_NS(tgt=self.target_ipv6)

    def craft_na_packet(self, src: Optional[str] = None):
        """Craft Neighbor Advertisement packet."""
        s = src or self.src_ipv6
        return IPv6(src=s, dst="ff02::1", hlim=255) / ICMPv6ND_NA(tgt=s, R=0, S=0, O=1)

    def start(self, src_ipv6: Optional[str] = None, rate_pps: Optional[int] = None) -> None:
        """Start NDP flood thread."""
        if self.is_running:
            return
        if src_ipv6:
            self.src_ipv6 = src_ipv6
        if rate_pps:
            self.flood_rate_pps = rate_pps

        self.is_running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop NDP flood thread."""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

    def trigger_burst(self, count: int = 25, src_ipv6: Optional[str] = None):
        """Send a quick concentrated burst of packets."""
        src = src_ipv6 or self.src_ipv6
        for i in range(count):
            pkt = self.craft_ns_packet(src) if i % 2 == 0 else self.craft_na_packet(src)
            self.packets_sent += 1
            if self.packet_sink:
                self.packet_sink(pkt, True)
            time.sleep(0.01)

    def _run_loop(self) -> None:
        delay = 1.0 / max(1, self.flood_rate_pps)
        i = 0
        while self.is_running:
            pkt = self.craft_ns_packet() if i % 2 == 0 else self.craft_na_packet()
            self.packets_sent += 1
            if self.packet_sink:
                self.packet_sink(pkt, True)
            i += 1
            time.sleep(delay)

