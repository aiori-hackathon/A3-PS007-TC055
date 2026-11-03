"""
normal_traffic.py - Benign Baseline IPv6 Traffic Generator
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

Generates legitimate ICMPv6 traffic:
- Periodic RA from the trusted default router (2001:db8:1::1).
- Periodic RS / NS / NA exchanges from authenticated IoT devices.
- Standard ICMPv6 Echo Request / Reply health pings.
"""

import time
import random
import threading
from typing import Optional, Callable, List

# Clean Scapy configuration
import scapy.config
scapy.config.conf.nameservers = ['8.8.8.8']
from scapy.layers.inet6 import (
    IPv6, ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6ND_NS, ICMPv6ND_NA,
    ICMPv6NDOptPrefixInfo, ICMPv6EchoRequest
)

class NormalTrafficSimulator:
    def __init__(self, packet_sink: Optional[Callable[[any, bool], None]] = None,
                 trusted_router_ip: str = "2001:db8:1::1",
                 trusted_prefix: str = "2001:db8:1::"):
        self.packet_sink = packet_sink
        self.trusted_router_ip = trusted_router_ip
        self.trusted_prefix = trusted_prefix
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.packets_sent = 0

    def craft_trusted_ra(self):
        """Build legitimate RA from trusted router."""
        return (
            IPv6(src=self.trusted_router_ip, dst="ff02::1", hlim=255) /
            ICMPv6ND_RA(chlim=64, routerlifetime=1800) /
            ICMPv6NDOptPrefixInfo(prefix=self.trusted_prefix, prefixlen=64, L=1, A=1, validlifetime=86400)
        )

    def craft_device_traffic(self, device_ipv6: str):
        """Randomly choose between benign RS, NS, NA, or Echo ping."""
        choice = random.choice(["RS", "NS", "NA", "ECHO"])
        if choice == "RS":
            return IPv6(src=device_ipv6, dst="ff02::2", hlim=255) / ICMPv6ND_RS()
        elif choice == "NS":
            return IPv6(src=device_ipv6, dst="ff02::1:ff00:1", hlim=255) / ICMPv6ND_NS(tgt=self.trusted_router_ip)
        elif choice == "NA":
            return IPv6(src=device_ipv6, dst="ff02::1", hlim=255) / ICMPv6ND_NA(tgt=device_ipv6, R=0, S=1, O=1)
        else:
            return IPv6(src=device_ipv6, dst=self.trusted_router_ip, hlim=64) / ICMPv6EchoRequest(data=b"HEALTH_PING")

    def start(self, device_ips_provider: Optional[Callable[[], List[str]]] = None) -> None:
        """Start benign background traffic generator."""
        if self.is_running:
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._run_loop, args=(device_ips_provider,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop benign traffic generator."""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

    def trigger_batch(self, count: int = 10, device_ips: Optional[List[str]] = None):
        """Send a batch of benign packets on demand (used for evaluation)."""
        ips = device_ips or ["2001:db8:1::101", "2001:db8:1::102", "2001:db8:1::103", "2001:db8:1::104", "2001:db8:1::105"]
        for i in range(count):
            if i % 4 == 0:
                pkt = self.craft_trusted_ra()
            else:
                ip = ips[i % len(ips)]
                pkt = self.craft_device_traffic(ip)
            self.packets_sent += 1
            if self.packet_sink:
                self.packet_sink(pkt, False)  # marked as benign (NOT an attack)
            time.sleep(0.08)

    def _run_loop(self, device_ips_provider: Optional[Callable[[], List[str]]]) -> None:
        while self.is_running:
            # 1 in 5 times send trusted router RA
            if random.random() < 0.2:
                pkt = self.craft_trusted_ra()
            else:
                ips = ["2001:db8:1::101", "2001:db8:1::102", "2001:db8:1::103", "2001:db8:1::104", "2001:db8:1::105"]
                if device_ips_provider:
                    try:
                        active_ips = device_ips_provider()
                        if active_ips:
                            ips = active_ips
                    except Exception:
                        pass
                dev_ip = random.choice(ips)
                pkt = self.craft_device_traffic(dev_ip)

            self.packets_sent += 1
            if self.packet_sink:
                self.packet_sink(pkt, False)

            time.sleep(random.uniform(0.8, 1.8))
