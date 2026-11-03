"""
device_simulator.py - Five Virtual IoT Device Simulator
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation

Simulates 5 distinct virtual IoT devices:
1. Smart Camera
2. Smart TV
3. Smart Bulb
4. Smart Speaker
5. Smart Door Sensor

Each device handles:
- IPv6 SLAAC address configuration & RFC 4941 rotation.
- Cryptographic authentication & session token caching.
- Ephemeral pseudonym binding.
- Periodic benign ICMPv6 telemetry.
"""

import time
import threading
from typing import Dict, Any, List, Optional, Callable
from address_rotation import AddressRotator

DEVICE_CONFIGS = [
    {
        "id": "dev-camera-01",
        "name": "Smart Camera",
        "type": "Security Camera",
        "initial_ipv6": "2001:db8:1::101",
        "secret": "secret_camera_key_7a9f",
        "preferred_pseudonym": "DEV-P01",
        "heartbeat_interval": 3.0
    },
    {
        "id": "dev-tv-02",
        "name": "Smart TV",
        "type": "Entertainment Hub",
        "initial_ipv6": "2001:db8:1::102",
        "secret": "secret_tv_key_4b2c",
        "preferred_pseudonym": "DEV-P02",
        "heartbeat_interval": 4.0
    },
    {
        "id": "dev-bulb-03",
        "name": "Smart Bulb",
        "type": "Lighting Device",
        "initial_ipv6": "2001:db8:1::103",
        "secret": "secret_bulb_key_9e1d",
        "preferred_pseudonym": "DEV-P03",
        "heartbeat_interval": 5.0
    },
    {
        "id": "dev-speaker-04",
        "name": "Smart Speaker",
        "type": "Voice Assistant",
        "initial_ipv6": "2001:db8:1::104",
        "secret": "secret_speaker_key_3f8a",
        "preferred_pseudonym": "DEV-P04",
        "heartbeat_interval": 3.5
    },
    {
        "id": "dev-doorsensor-05",
        "name": "Smart Door Sensor",
        "type": "Access Control",
        "initial_ipv6": "2001:db8:1::105",
        "secret": "secret_doorsensor_key_5c6b",
        "preferred_pseudonym": "DEV-P05",
        "heartbeat_interval": 6.0
    }
]

class VirtualIoTDevice:
    def __init__(self, config: Dict[str, Any], session_mgr, address_rotator: AddressRotator,
                 packet_sink: Optional[Callable[[Any, bool], None]] = None, tenant_id: str = "tenant-alpha"):
        self.config = config
        self.device_id = config["id"]
        self.name = config["name"]
        self.device_type = config["type"]
        self.current_ipv6 = config["initial_ipv6"]
        self.secret = config["secret"]
        self.preferred_pseudonym = config["preferred_pseudonym"]
        self.heartbeat_interval = config["heartbeat_interval"]

        self.session_mgr = session_mgr
        self.rotator = address_rotator
        self.packet_sink = packet_sink
        self.tenant_id = tenant_id

        # Internal state
        self.session_id: Optional[str] = None
        self.session_token: Optional[str] = None
        self.pseudonym: Optional[str] = None
        self.session_expires_at: float = 0.0
        self.rotation_count = 0
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def authenticate(self) -> Dict[str, Any]:
        """Perform initial authentication handshake with the monitoring server."""
        with self._lock:
            auth_res = self.session_mgr.authenticate_device(
                tenant_id=self.tenant_id,
                device_id=self.device_id,
                ipv6_address=self.current_ipv6,
                secret=self.secret,
                custom_pseudonym=self.preferred_pseudonym
            )
            self.session_id = auth_res["session_id"]
            self.session_token = auth_res["session_token"]
            self.pseudonym = auth_res["pseudonym"]
            self.session_expires_at = auth_res["expires_at"]
            return auth_res

    def rotate_address(self, new_address: Optional[str] = None) -> Dict[str, Any]:
        """Perform authenticated temporary address rotation."""
        with self._lock:
            if not self.session_id or not self.session_token:
                self.authenticate()

            target_ip = new_address or self.rotator.generate_next_address()
            res = self.rotator.execute_rotation(
                session_mgr=self.session_mgr,
                tenant_id=self.tenant_id,
                device_id=self.device_id,
                session_id=self.session_id,
                session_token=self.session_token,
                target_new_ipv6=target_ip
            )
            self.current_ipv6 = target_ip
            self.rotation_count += 1
            return res

    def start(self) -> None:
        """Start device loop."""
        if self.is_running:
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop device loop."""
        self.is_running = False
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

    def _run_loop(self) -> None:
        # Initial authentication
        try:
            self.authenticate()
        except Exception:
            pass

        while self.is_running:
            time.sleep(self.heartbeat_interval)
            if not self.is_running:
                break

            # Send benign heartbeat packet if packet_sink is wired
            if self.packet_sink:
                try:
                    from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
                    pkt = IPv6(src=self.current_ipv6, dst="ff02::1:ff00:1", hlim=255) / ICMPv6ND_NS(tgt="2001:db8:1::1")
                    self.packet_sink(pkt, False)
                except Exception:
                    pass

class DeviceSimulatorController:
    """Manages all 5 virtual IoT devices."""
    def __init__(self, session_mgr, address_rotator: AddressRotator,
                 packet_sink: Optional[Callable[[Any, bool], None]] = None, tenant_id: str = "tenant-alpha"):
        self.session_mgr = session_mgr
        self.rotator = address_rotator
        self.packet_sink = packet_sink
        self.tenant_id = tenant_id

        self.devices: Dict[str, VirtualIoTDevice] = {}
        for cfg in DEVICE_CONFIGS:
            dev = VirtualIoTDevice(
                config=cfg,
                session_mgr=self.session_mgr,
                address_rotator=self.rotator,
                packet_sink=self.packet_sink,
                tenant_id=self.tenant_id
            )
            self.devices[cfg["id"]] = dev

        self.auto_rotation_interval = 0  # 0 means manual or disabled periodic rotation
        self._auto_rotate_thread: Optional[threading.Thread] = None
        self.is_running = False

    def start_all(self, auto_rotation_interval: int = 0) -> None:
        """Start all 5 devices and optionally background auto-rotation."""
        self.is_running = True
        self.auto_rotation_interval = auto_rotation_interval
        for dev in self.devices.values():
            dev.start()

        if self.auto_rotation_interval > 0:
            self._auto_rotate_thread = threading.Thread(target=self._auto_rotate_loop, daemon=True)
            self._auto_rotate_thread.start()

    def stop_all(self) -> None:
        """Stop all 5 devices."""
        self.is_running = False
        for dev in self.devices.values():
            dev.stop()
        if self._auto_rotate_thread:
            self._auto_rotate_thread = None

    def authenticate_all(self) -> List[Dict[str, Any]]:
        """Authenticate all 5 devices immediately."""
        results = []
        for dev in self.devices.values():
            res = dev.authenticate()
            results.append(res)
        return results

    def rotate_device(self, device_id: str, new_ipv6: Optional[str] = None) -> Dict[str, Any]:
        """Manually rotate address for a specific device."""
        dev = self.devices.get(device_id)
        if not dev:
            raise KeyError(f"Device {device_id} not found")
        return dev.rotate_address(new_ipv6)

    def get_device_current_ips(self) -> List[str]:
        return [dev.current_ipv6 for dev in self.devices.values()]

    def _auto_rotate_loop(self) -> None:
        while self.is_running and self.auto_rotation_interval > 0:
            time.sleep(self.auto_rotation_interval)
            if not self.is_running:
                break
            for dev in self.devices.values():
                try:
                    dev.rotate_address()
                except Exception:
                    pass

