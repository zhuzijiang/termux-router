"""IPv4 / MAC 小工具。

刻意不引入 ``ipaddress`` 之外的依赖——``ipaddress`` 是标准库，但这里仍然
手写了几个常用换算，因为 DHCP 里要频繁做整数与字符串互转，手写更快也更直观。
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

_IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def ip_to_int(ip: str) -> int:
    m = _IP_RE.match(ip.strip())
    if not m:
        raise ValueError(f"非法 IPv4 地址: {ip!r}")
    parts = [int(g) for g in m.groups()]
    if any(p > 255 for p in parts):
        raise ValueError(f"非法 IPv4 地址: {ip!r}")
    value = 0
    for p in parts:
        value = (value << 8) | p
    return value


def int_to_ip(value: int) -> str:
    value &= 0xFFFFFFFF
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def is_valid_ip(ip: str) -> bool:
    try:
        ip_to_int(ip)
        return True
    except (ValueError, AttributeError):
        return False


def netmask_str(prefix: int) -> str:
    if not 0 <= prefix <= 32:
        raise ValueError(f"非法前缀长度: {prefix}")
    if prefix == 0:
        return "0.0.0.0"
    return int_to_ip(((1 << prefix) - 1) << (32 - prefix))


def wildcard_str(prefix: int) -> str:
    return int_to_ip(~(((1 << prefix) - 1) << (32 - prefix)) & 0xFFFFFFFF)


def parse_cidr(cidr: str) -> Tuple[int, int]:
    """``"192.168.43.0/24"`` -> ``(network_int, prefix)``。"""
    if "/" not in cidr:
        raise ValueError(f"缺少前缀长度: {cidr!r}")
    addr, _, plen = cidr.partition("/")
    prefix = int(plen)
    if not 0 <= prefix <= 32:
        raise ValueError(f"非法前缀长度: {plen!r}")
    network = ip_to_int(addr) & (((1 << prefix) - 1) << (32 - prefix)) if prefix else 0
    return network, prefix


def network_address(cidr: str) -> int:
    return parse_cidr(cidr)[0]


def broadcast_address(cidr: str) -> int:
    net, prefix = parse_cidr(cidr)
    host_bits = 32 - prefix
    return net | ((1 << host_bits) - 1) if host_bits else net


def in_cidr(ip: str, cidr: str) -> bool:
    net, prefix = parse_cidr(cidr)
    return (ip_to_int(ip) >> (32 - prefix) if prefix else 0) == (net >> (32 - prefix) if prefix else 0)


def ip_range(start: str, end: str):
    """生成 [start, end] 之间的所有地址（含端点）。"""
    a, b = ip_to_int(start), ip_to_int(end)
    if b < a:
        raise ValueError("地址池起点大于终点")
    for v in range(a, b + 1):
        yield int_to_ip(v)


def normalize_mac(mac: str) -> str:
    """统一成小写、冒号分隔的 MAC。"""
    if not _MAC_RE.match(mac.strip()):
        raise ValueError(f"非法 MAC 地址: {mac!r}")
    return mac.strip().lower().replace("-", ":")


def is_valid_mac(mac: str) -> bool:
    try:
        normalize_mac(mac)
        return True
    except (ValueError, AttributeError):
        return False


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in normalize_mac(mac).split(":"))


def bytes_to_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def is_valid_port(port: int) -> bool:
    return isinstance(port, int) and 0 < port < 65536


def is_multicast_or_broadcast(ip: str) -> bool:
    value = ip_to_int(ip)
    return value == 0xFFFFFFFF or (0xE0000000 <= value <= 0xEFFFFFFF)
