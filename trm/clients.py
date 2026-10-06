"""客户端（上网设备）聚合视图。

把四路信息拼成一张"谁在用我的网"的表：

1. **DHCP 租约** —— 谁拿到了哪个地址、主机名是什么
2. **ARP / 邻居表** —— 谁真的在线（比租约准确：租约还在但设备走了很常见）
3. **conntrack** —— 每台设备上下行了多少字节
4. **配置** —— 用户起的备注名、限速值

诚实说明：**没有 root 就没有 2 和 3**。这时表里只有租约信息
（而租约又需要 DHCP 服务，也就是需要 root），所以监控模式下这张表
会是空的，而不是编造出来的数据。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import iputil, net

ARP_PATH = "/proc/net/arp"


@dataclass
class Client:
    ip: str
    mac: str = ""
    hostname: str = ""
    name: str = ""            # 用户备注，优先显示
    online: Optional[bool] = None   # None = 无法判断（没 root），而不是"离线"
    static: bool = False
    lease_remaining: int = 0
    up: int = 0
    down: int = 0
    conns: int = 0
    down_kbps: int = 0
    up_kbps: int = 0
    last_seen: float = 0.0

    @property
    def label(self) -> str:
        return self.name or self.hostname or self.mac or self.ip

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "name": self.name,
            "label": self.label,
            "online": self.online,
            "static": self.static,
            "lease_remaining": self.lease_remaining,
            "up": self.up,
            "down": self.down,
            "total": self.up + self.down,
            "conns": self.conns,
            "down_kbps": self.down_kbps,
            "up_kbps": self.up_kbps,
            "limited": bool(self.down_kbps or self.up_kbps),
            "last_seen": self.last_seen,
        }


def read_arp_table(path: str = ARP_PATH) -> Dict[str, str]:
    """解析 ``/proc/net/arp``，只保留状态完整的表项。"""
    out: Dict[str, str] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    for line in lines[1:]:
        cols = line.split()
        if len(cols) < 6:
            continue
        ip, _hwtype, flags, mac = cols[0], cols[1], cols[2], cols[3]
        if mac in ("00:00:00:00:00:00", ""):
            continue
        try:
            if int(flags, 16) & 0x2 == 0:  # 0x2 = ATF_COM，即已完成解析
                continue
        except ValueError:
            continue
        out[ip] = mac.lower()
    return out


def read_neighbors(runner, ip_cmd: Optional[str] = None) -> Dict[str, str]:
    """``ip neigh`` 回退方案（有些内核对 /proc/net/arp 有隐藏）。"""
    cmd = ip_cmd or runner.which("ip")
    if not cmd:
        return {}
    res = runner.run([cmd, "neigh", "show"], timeout=6)
    out: Dict[str, str] = {}
    for line in res.lines():
        cols = line.split()
        if len(cols) >= 5 and cols[1] == "dev":
            continue
        if len(cols) >= 5 and ":" in cols[4]:
            out[cols[0]] = cols[4].lower()
    return out


def collect_clients(
    cfg,
    leases: Optional[List[Dict[str, Any]]] = None,
    arp: Optional[Dict[str, str]] = None,
    traffic: Optional[Dict[str, Dict[str, int]]] = None,
    subnet: Optional[str] = None,
    now: Optional[float] = None,
) -> List[Client]:
    """把各路数据合并成客户端列表。

    参数都可注入，方便单元测试（``tests/test_clients.py``）。
    """
    now = now if now is not None else time.time()
    arp = arp or {}
    traffic = traffic or {}
    subnet = subnet or str(cfg.get("lan.subnet", "192.168.43.0/24"))
    names = {str(k): str(v) for k, v in (cfg.get("client_names") or {}).items()}
    limits = cfg.get("limits") or {}

    by_ip: Dict[str, Client] = {}

    for lease in leases or []:
        ip = str(lease.get("ip", ""))
        if not ip:
            continue
        by_ip[ip] = Client(
            ip=ip,
            mac=str(lease.get("mac", "")),
            hostname=str(lease.get("hostname", "")),
            static=bool(lease.get("static", False)),
            lease_remaining=int(lease.get("remaining", 0) or 0),
        )

    # ARP 里出现、但没有租约的设备也要列出来（例如手动配了静态 IP 的设备）
    for ip, mac in arp.items():
        if subnet and not iputil.in_cidr(ip, subnet):
            continue
        node = by_ip.get(ip)
        if node is None:
            node = Client(ip=ip, mac=mac, online=True)
            by_ip[ip] = node
        else:
            if not node.mac:
                node.mac = mac
            node.online = True

    for ip, stat in traffic.items():
        node = by_ip.get(ip)
        if node is None:
            if subnet and not iputil.in_cidr(ip, subnet):
                continue
            node = Client(ip=ip)
            by_ip[ip] = node
        node.up = int(stat.get("up", 0))
        node.down = int(stat.get("down", 0))
        node.conns = int(stat.get("conns", 0))
        if node.conns > 0 and node.online is None:
            node.online = True

    for ip, node in by_ip.items():
        node.name = names.get(ip, "")
        limit = limits.get(ip) or {}
        if isinstance(limit, dict):
            node.down_kbps = int(limit.get("down_kbps", 0) or 0)
            node.up_kbps = int(limit.get("up_kbps", 0) or 0)
        if node.online is None and node.lease_remaining > 0:
            # 有活跃租约但看不到 ARP：只能说"可能在线"，不撒谎
            node.online = None
        if node.online is True:
            node.last_seen = now

    return sorted(by_ip.values(), key=lambda c: iputil.ip_to_int(c.ip) if iputil.is_valid_ip(c.ip) else 0)


def collect_from_system(cfg, responder=None, runner=None, caps=None) -> List[Client]:
    """从真实系统读取（需要 root 才能拿到 ARP 与 conntrack）。"""
    leases = responder.snapshot()["leases"] if responder is not None else []
    arp: Dict[str, str] = read_arp_table()
    if not arp and runner is not None:
        arp = read_neighbors(runner)
    entries = net.read_conntrack()
    traffic = net.aggregate_lan_traffic(entries)
    return collect_clients(cfg, leases=leases, arp=arp, traffic=traffic)


def summarize(clients: List[Client]) -> Dict[str, Any]:
    online = [c for c in clients if c.online is True]
    unknown = [c for c in clients if c.online is None]
    return {
        "total": len(clients),
        "online": len(online),
        "unknown": len(unknown),
        "offline": len([c for c in clients if c.online is False]),
        "limited": len([c for c in clients if c.down_kbps or c.up_kbps]),
        "up": sum(c.up for c in clients),
        "down": sum(c.down for c in clients),
    }
