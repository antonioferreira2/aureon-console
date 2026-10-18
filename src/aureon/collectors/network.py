"""Network: interfaces, addresses, traffic counters and listening sockets."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..util import Result, human_bytes, human_duration, read_text
from .base import Collector

PROC_NET_DEV = Path("/proc/net/dev")
PROC_NET_ROUTE = Path("/proc/net/route")


@dataclass
class InterfaceInfo:
    name: str
    state: str = "unknown"
    mac: str = ""
    mtu: Optional[int] = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0
    addresses: List[str] = field(default_factory=list)
    rx_rate: Optional[float] = None   # bytes/s
    tx_rate: Optional[float] = None
    source: str = "/proc/net/dev"


@dataclass
class SocketInfo:
    protocol: str
    local_address: str
    local_port: int
    state: str
    inode: Optional[int] = None


@dataclass
class NetworkInfo:
    hostname: str = ""
    interfaces: List[InterfaceInfo] = field(default_factory=list)
    listening: List[SocketInfo] = field(default_factory=list)
    established: int = 0
    tcp_errors: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    default_route: Optional[str] = None


def _read_interfaces() -> List[InterfaceInfo]:
    text = read_text(PROC_NET_DEV)
    if not text:
        return []
    interfaces: List[InterfaceInfo] = []
    lines = text.splitlines()
    for line in lines[2:]:
        name, _, rest = line.partition(":")
        if not rest.strip():
            continue
        fields = rest.split()
        if len(fields) < 16:
            continue

        def num(index: int) -> int:
            try:
                return int(fields[index])
            except (IndexError, ValueError):
                return 0

        iface = InterfaceInfo(
            name=name.strip(),
            rx_bytes=num(0),
            rx_errors=num(2),
            rx_dropped=num(3),
            tx_bytes=num(8),
            tx_errors=num(10),
            tx_dropped=num(11),
        )
        iface.addresses = _addresses_for(iface.name)
        mtu = read_text(f"/sys/class/net/{iface.name}/mtu", 16)
        if mtu:
            try:
                iface.mtu = int(mtu.strip())
            except ValueError:
                pass
        operstate = read_text(f"/sys/class/net/{iface.name}/operstate", 32)
        iface.state = operstate.strip() if operstate else "unknown"
        interfaces.append(iface)
    return interfaces


def _addresses_for(name: str) -> List[str]:
    """Best-effort address lookup using stdlib only (no ip command needed)."""
    try:
        import fcntl

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = struct.pack("256s", name.encode()[:15])
            out = bytearray(1500)
            # SIOCGIFADDR only returns IPv4; IPv6 comes from /proc/net/if_inet6.
            fcntl.ioctl(sock.fileno(), 0x8915, out)
            ip = socket.inet_ntoa(out[20:24])
            addrs = [ip]
        finally:
            sock.close()
    except OSError:
        addrs = []
    for line in (read_text("/proc/net/if_inet6") or "").splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[5] == name:
            addrs.append(":".join(parts[0][i:i + 4] for i in range(0, 32, 4)))
    return addrs


def _read_sockets() -> tuple:
    listening: List[SocketInfo] = []
    established = 0
    text = read_text("/proc/net/tcp") or ""
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local_hex, state_hex = parts[1], parts[3]
        try:
            host, port_hex = local_hex.split(":")
            port = int(port_hex, 16)
            raw = bytes.fromhex(host)
            address = socket.inet_ntoa(raw[::-1])
        except (ValueError, OSError):
            continue
        state = {"0A": "LISTEN", "01": "ESTABLISHED", "06": "TIME_WAIT", "08": "CLOSE_WAIT"}.get(
            state_hex.upper(), state_hex.upper()
        )
        if state == "LISTEN":
            listening.append(SocketInfo("tcp", address, port, state))
        elif state == "ESTABLISHED":
            established += 1
    text6 = read_text("/proc/net/tcp6") or ""
    for line in text6.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        host, port_hex = parts[1].split(":")
        if parts[3].upper() != "0A":
            continue
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        listening.append(SocketInfo("tcp6", "[::]", port, "LISTEN"))
    return listening, established


def _tcp_errors() -> Dict[str, int]:
    snmp = read_text("/proc/net/snmp")
    errors: Dict[str, int] = {}
    if not snmp:
        return errors
    lines = snmp.splitlines()
    for index in range(0, len(lines) - 1, 2):
        header = lines[index].split()
        values = lines[index + 1].split()
        if not header or not header[0].upper().startswith("TCP"):
            continue
        for key, value in zip(header[1:], values[1:]):
            if "Err" in key or "Retrans" in key:
                try:
                    errors[key] = int(value)
                except ValueError:
                    continue
    return errors


class NetworkCollector(Collector):
    key = "network"
    title = "Network"
    source = "/proc/net/dev, /proc/net/tcp"

    def collect(self) -> Result:
        info = NetworkInfo()
        info.interfaces = _read_interfaces()
        if not info.interfaces:
            info.warnings.append("/proc/net/dev unreadable")
        listening, established = _read_sockets()
        info.listening = listening
        info.established = established
        info.tcp_errors = _tcp_errors()
        info.default_route = self._default_route()
        self._rates(info)
        result = Result.ok_result(info, self.source)
        result.warnings = info.warnings
        return result

    def _default_route(self) -> Optional[str]:
        text = read_text(PROC_NET_ROUTE)
        if not text:
            return None
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) > 2 and parts[1] == "00000000":
                try:
                    raw = bytes.fromhex(parts[2])
                    return socket.inet_ntoa(raw[::-1])
                except (ValueError, OSError):
                    continue
        return None

    def _rates(self, info: NetworkInfo) -> None:
        previous = self.ctx.cache.get("net-counters") or {}
        now_values = {i.name: (i.rx_bytes, i.tx_bytes) for i in info.interfaces}
        timestamps = self.ctx.cache.get("net-timestamp")
        import time

        now_ts = time.monotonic()
        for iface in info.interfaces:
            current = now_values[iface.name]
            prior = previous.get(iface.name)
            if prior and timestamps:
                delta = now_ts - timestamps
                if delta > 0:
                    iface.rx_rate = max(0.0, (current[0] - prior[0]) / delta)
                    iface.tx_rate = max(0.0, (current[1] - prior[1]) / delta)
        self.ctx.cache["net-counters"] = now_values
        self.ctx.cache["net-timestamp"] = now_ts

    def rate_history_label(self, value: Optional[float]) -> str:
        return "n/a" if value is None else f"{human_bytes(value)}/s"

    @staticmethod
    def duration(value: Optional[float]) -> str:
        return human_duration(value)
