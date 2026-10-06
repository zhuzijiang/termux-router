"""纯 Python DHCP 服务器（RFC 2131 / 2132）。

为什么不直接用 dnsmasq？因为本项目的第一原则是**零依赖**：
手机上每多装一个包就多占一份存储和内存。DHCP 是极低频协议
（一台设备一天几十个包），Python 完全扛得住，而真正的转发压力
在内核 netfilter 里，跟这里无关。

架构上刻意拆成三层，方便测试：

1. :func:`parse_packet` / :func:`build_reply` —— 纯字节编解码，无副作用
2. :class:`DHCPResponder` —— 纯逻辑：拿到包决定回什么，**不碰套接字**
3. :class:`DHCPServer` —— 只负责收发包（UDP 或 AF_PACKET 原始帧）

于是 ``tests/test_dhcp.py`` 可以在没有 root、没有网络的机器上
完整验证 OFFER/ACK/NAK/RELEASE 的全部行为。

一个容易被忽略的工程细节：客户端在拿到 IP **之前**没有 IP，所以
DHCPOFFER 不能靠普通 UDP 单播（内核会因为 ARP 不到目标而丢包）。
正确做法是用 AF_PACKET 直接构造以太网帧，目的 MAC 填客户端的 MAC。
本项目优先走这条路，拿不到原始套接字权限时才退回 UDP 广播。
"""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import iputil, paths, store

MAGIC_COOKIE = b"\x63\x82\x53\x63"
BOOTREQUEST, BOOTREPLY = 1, 2
HTYPE_ETHERNET = 1
FLAG_BROADCAST = 0x8000
MIN_PACKET = 300

# DHCP 消息类型
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = 1, 2, 3, 4, 5, 6, 7, 8
MSG_NAMES = {
    DISCOVER: "DISCOVER", OFFER: "OFFER", REQUEST: "REQUEST", DECLINE: "DECLINE",
    ACK: "ACK", NAK: "NAK", RELEASE: "RELEASE", INFORM: "INFORM",
}

# 选项码
OPT_NETMASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_DOMAIN = 15
OPT_MTU = 26
OPT_BROADCAST = 28
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_LIST = 55
OPT_RENEWAL_T1 = 58
OPT_REBIND_T2 = 59
OPT_CLIENT_ID = 61
OPT_END = 255
OPT_PAD = 0

ETH_P_IP = 0x0800


# --------------------------------------------------------------- 字节编解码


def ip_checksum(data: bytes) -> int:
    """标准 16 位反码校验和。"""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_udp_ip_frame(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload: bytes,
) -> bytes:
    """构造完整的以太网 + IPv4 + UDP 帧。

    DHCPOFFER 必须这样发：客户端此时还没有 IP，普通 UDP 单播会因
    无法 ARP 解析而发不出去。
    """
    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", sport, dport, udp_len, 0)
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
    )
    udp_sum = ip_checksum(pseudo + udp_header + payload) or 0xFFFF
    udp = struct.pack("!HHHH", sport, dport, udp_len, udp_sum) + payload

    total_len = 20 + len(udp)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0, 64, socket.IPPROTO_UDP, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip_sum = ip_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_sum) + ip_header[12:]

    eth = dst_mac + src_mac + struct.pack("!H", ETH_P_IP)
    frame = eth + ip_header + udp
    if len(frame) < 60:  # 以太网最小帧长
        frame += b"\x00" * (60 - len(frame))
    return frame


@dataclass
class Packet:
    """解析后的 DHCP 报文。"""

    op: int = BOOTREQUEST
    htype: int = HTYPE_ETHERNET
    hlen: int = 6
    hops: int = 0
    xid: int = 0
    secs: int = 0
    flags: int = 0
    ciaddr: str = "0.0.0.0"
    yiaddr: str = "0.0.0.0"
    siaddr: str = "0.0.0.0"
    giaddr: str = "0.0.0.0"
    chaddr: bytes = b"\x00" * 16
    options: Dict[int, bytes] = field(default_factory=dict)

    @property
    def mac(self) -> str:
        return iputil.bytes_to_mac(self.chaddr[: self.hlen or 6])

    @property
    def msg_type(self) -> int:
        raw = self.options.get(OPT_MSG_TYPE, b"")
        return raw[0] if raw else 0

    @property
    def broadcast_requested(self) -> bool:
        return bool(self.flags & FLAG_BROADCAST)

    def opt_ip(self, code: int) -> Optional[str]:
        raw = self.options.get(code)
        if raw and len(raw) == 4:
            return socket.inet_ntoa(raw)
        return None

    def opt_str(self, code: int) -> str:
        raw = self.options.get(code, b"")
        return raw.decode("utf-8", "replace").strip("\x00").strip()

    def opt_int(self, code: int, default: int = 0) -> int:
        raw = self.options.get(code, b"")
        if len(raw) >= 4:
            return struct.unpack("!I", raw[:4])[0]
        if len(raw) == 2:
            return struct.unpack("!H", raw[:2])[0]
        if len(raw) == 1:
            return raw[0]
        return default

    def client_id(self) -> str:
        raw = self.options.get(OPT_CLIENT_ID)
        if raw:
            return raw.hex()
        return self.mac


def parse_options(data: bytes) -> Dict[int, bytes]:
    opts: Dict[int, bytes] = {}
    i = 0
    while i < len(data):
        code = data[i]
        if code == OPT_PAD:
            i += 1
            continue
        if code == OPT_END:
            break
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        value = data[i + 2 : i + 2 + length]
        if len(value) < length and code != OPT_END:
            break
        opts[code] = value
        i += 2 + length
    return opts


def parse_packet(data: bytes) -> Packet:
    if len(data) < 240:
        raise ValueError(f"报文太短: {len(data)}")
    if data[236:240] != MAGIC_COOKIE:
        raise ValueError("缺少 DHCP magic cookie")
    fields = struct.unpack("!BBBBIHHIIII16s64s128s", data[:236])
    pkt = Packet(
        op=fields[0], htype=fields[1], hlen=fields[2], hops=fields[3],
        xid=fields[4], secs=fields[5], flags=fields[6],
        ciaddr=socket.inet_ntoa(struct.pack("!I", fields[7])),
        yiaddr=socket.inet_ntoa(struct.pack("!I", fields[8])),
        siaddr=socket.inet_ntoa(struct.pack("!I", fields[9])),
        giaddr=socket.inet_ntoa(struct.pack("!I", fields[10])),
        chaddr=fields[11],
    )
    pkt.options = parse_options(data[240:])
    return pkt


def encode_options(options: Dict[int, bytes]) -> bytes:
    out = bytearray()
    for code in sorted(options):
        value = options[code]
        if not value:
            continue
        out.append(code)
        out.append(len(value))
        out.extend(value)
    out.append(OPT_END)
    return bytes(out)


def build_reply(
    request: Packet,
    msg_type: int,
    yiaddr: str,
    server_ip: str,
    options: Optional[Dict[int, bytes]] = None,
) -> bytes:
    """构造 DHCP 回包（BOOTREPLY）。"""
    header = struct.pack(
        "!BBBBIHHIIII16s64s128s",
        BOOTREPLY, request.htype, request.hlen, 0,
        request.xid, 0, request.flags,
        0,
        iputil.ip_to_int(yiaddr),
        iputil.ip_to_int(server_ip),
        iputil.ip_to_int(request.giaddr),
        request.chaddr, b"\x00" * 64, b"\x00" * 128,
    )
    opts: Dict[int, bytes] = {OPT_MSG_TYPE: bytes([msg_type])}
    if options:
        for code, value in options.items():
            if code != OPT_MSG_TYPE:
                opts[code] = value
    # 服务器标识符必须在每个回包里（RFC 2131 §4.3.1）
    opts.setdefault(OPT_SERVER_ID, socket.inet_aton(server_ip))
    body = header + MAGIC_COOKIE + encode_options(opts)
    if len(body) < MIN_PACKET:
        body += b"\x00" * (MIN_PACKET - len(body))
    return body


# ------------------------------------------------------------------ 租约管理


@dataclass
class Lease:
    ip: str
    mac: str
    hostname: str = ""
    client_id: str = ""
    expires: float = 0.0
    state: str = "offered"  # offered | bound
    static: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip, "mac": self.mac, "hostname": self.hostname,
            "client_id": self.client_id, "expires": self.expires,
            "state": self.state, "static": self.static,
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Lease":
        return cls(
            ip=str(raw.get("ip", "")),
            mac=str(raw.get("mac", "")),
            hostname=str(raw.get("hostname", "")),
            client_id=str(raw.get("client_id", "")),
            expires=float(raw.get("expires", 0) or 0),
            state=str(raw.get("state", "bound")),
            static=bool(raw.get("static", False)),
        )

    @property
    def remaining(self) -> int:
        return max(0, int(self.expires - time.time()))


class LeaseStore:
    """租约表，落盘为 JSON。写盘做了脏标记，避免每个包都写一次磁盘。"""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else paths.leases_file()
        self.leases: Dict[str, Lease] = {}   # ip -> Lease
        self._dirty = False
        self._last_save = 0.0

    def load(self) -> "LeaseStore":
        raw = store.read_json(self.path, default={}) or {}
        for item in raw.get("leases", []) if isinstance(raw, dict) else []:
            try:
                lease = Lease.from_dict(item)
            except (TypeError, ValueError):
                continue
            if lease.ip:
                self.leases[lease.ip] = lease
        return self

    def mark_dirty(self) -> None:
        self._dirty = True

    def save(self, force: bool = False, min_interval: float = 5.0) -> bool:
        if not self._dirty and not force:
            return False
        if not force and (time.time() - self._last_save) < min_interval:
            return False
        store.write_json(self.path, {"leases": [l.to_dict() for l in self.leases.values()]})
        self._dirty = False
        self._last_save = time.time()
        return True

    # ------------------------------------------------------------- 查询/分配
    def active(self, now: Optional[float] = None) -> List[Lease]:
        now = now if now is not None else time.time()
        return [l for l in self.leases.values() if l.expires > now]

    def by_mac(self, mac: str, now: Optional[float] = None) -> Optional[Lease]:
        now = now if now is not None else time.time()
        for lease in self.leases.values():
            if lease.mac == mac and lease.expires > now:
                return lease
        return None

    def by_ip(self, ip: str) -> Optional[Lease]:
        return self.leases.get(ip)

    def used_ips(self, now: Optional[float] = None) -> set:
        return {l.ip for l in self.active(now)}

    def put(self, lease: Lease) -> Lease:
        self.leases[lease.ip] = lease
        self.mark_dirty()
        return lease

    def remove_ip(self, ip: str) -> bool:
        if ip in self.leases:
            del self.leases[ip]
            self.mark_dirty()
            return True
        return False

    def remove_mac(self, mac: str) -> int:
        victims = [ip for ip, l in self.leases.items() if l.mac == mac]
        for ip in victims:
            del self.leases[ip]
        if victims:
            self.mark_dirty()
        return len(victims)

    def sweep(self, now: Optional[float] = None, keep_offered: float = 0.0) -> int:
        """清理过期租约，返回清理数量。"""
        now = now if now is not None else time.time()
        dead = [
            ip for ip, l in self.leases.items()
            if l.expires <= now and not (l.state == "offered" and l.expires > now - keep_offered)
        ]
        for ip in dead:
            del self.leases[ip]
        if dead:
            self.mark_dirty()
        return len(dead)


# ---------------------------------------------------------------- 响应逻辑


class DHCPResponder:
    """纯逻辑层：输入一个 DHCP 报文，输出该回什么。**不碰套接字。**

    这样协议行为可以被完整单元测试，不需要 root、不需要网络。
    """

    def __init__(
        self,
        server_ip: str,
        subnet: str,
        pool_start: str,
        pool_end: str,
        lease_time: int = 3600,
        dns: Optional[List[str]] = None,
        domain: str = "lan",
        mtu: int = 1500,
        static_leases: Optional[Dict[str, str]] = None,
        store_obj: Optional[LeaseStore] = None,
        now_fn: Callable[[], float] = time.time,
        events: Optional[store.RingBuffer] = None,
    ) -> None:
        self.server_ip = server_ip
        self.subnet = subnet
        self.pool_start = pool_start
        self.pool_end = pool_end
        self.lease_time = max(60, int(lease_time))
        self.dns = list(dns or [server_ip])
        self.domain = domain
        self.mtu = int(mtu)
        _, self.prefix = iputil.parse_cidr(subnet)
        self.netmask = iputil.netmask_str(self.prefix)
        self.broadcast = iputil.int_to_ip(iputil.broadcast_address(subnet))
        self.leases = store_obj or LeaseStore()
        self.now = now_fn
        self.events = events or store.RingBuffer(200)
        self.static: Dict[str, str] = {}
        for mac, ip in (static_leases or {}).items():
            try:
                self.static[iputil.normalize_mac(mac)] = str(ip)
            except ValueError:
                continue
        self.declined: Dict[str, float] = {}
        self.counters = {"discover": 0, "request": 0, "release": 0, "decline": 0, "inform": 0, "nak": 0, "ignored": 0}

    # ------------------------------------------------------------ 地址池
    def pool(self) -> List[str]:
        reserved = {self.server_ip, *self.static.values()}
        out = []
        for ip in iputil.ip_range(self.pool_start, self.pool_end):
            if ip in reserved:
                continue
            out.append(ip)
        return out

    def _free_ip(self, mac: str, requested: Optional[str], now: float) -> Optional[str]:
        static_ip = self.static.get(mac)
        if static_ip:
            holder = self.leases.by_ip(static_ip)
            if holder is None or holder.mac == mac:
                return static_ip

        if requested and iputil.is_valid_ip(requested):
            if self._ip_available(requested, mac, now):
                return requested

        used = self.leases.used_ips(now)
        for ip in self.pool():
            if ip in used or ip in self.declined:
                continue
            return ip
        return None

    def _ip_available(self, ip: str, mac: str, now: float) -> bool:
        if ip in self.declined and self.declined[ip] > now:
            return False
        if ip == self.server_ip:
            return False
        if not iputil.in_cidr(ip, self.subnet):
            return False
        if ip not in set(self.pool()) and ip not in self.static.values():
            return False
        holder = self.leases.by_ip(ip)
        if holder and holder.expires > now and holder.mac != mac:
            return False
        return True

    # ------------------------------------------------------------ 主入口
    def respond(self, data: bytes, now: Optional[float] = None) -> Optional[Tuple[bytes, str, str]]:
        """返回 ``(回包字节, 动作描述, 客户端 MAC)``；不需要回应时返回 ``None``。"""
        now = now if now is not None else self.now()
        try:
            pkt = parse_packet(data)
        except ValueError as exc:
            self.events.add({"t": now, "event": "parse_error", "detail": str(exc)})
            return None

        if pkt.op != BOOTREQUEST:
            return None

        mac = pkt.mac
        mtype = pkt.msg_type
        hostname = pkt.opt_str(OPT_HOSTNAME)

        if mtype == DISCOVER:
            self.counters["discover"] += 1
            return self._on_discover(pkt, mac, hostname, now)
        if mtype == REQUEST:
            self.counters["request"] += 1
            return self._on_request(pkt, mac, hostname, now)
        if mtype == RELEASE:
            self.counters["release"] += 1
            released = pkt.ciaddr if pkt.ciaddr != "0.0.0.0" else self._lease_ip_for(mac)
            if released:
                self.leases.remove_ip(released)
                self._event("release", mac, released, hostname, now)
            return None
        if mtype == DECLINE:
            self.counters["decline"] += 1
            bad = pkt.opt_ip(OPT_REQUESTED_IP) or pkt.ciaddr
            if bad and iputil.is_valid_ip(bad):
                self.declined[bad] = now + 3600
                self.leases.remove_ip(bad)
                self._event("decline", mac, bad, hostname, now)
            return None
        if mtype == INFORM:
            self.counters["inform"] += 1
            reply = build_reply(pkt, ACK, "0.0.0.0", self.server_ip, self._config_options())
            self._event("inform", mac, pkt.ciaddr, hostname, now)
            return reply, f"INFORM -> {mac}", mac

        self.counters["ignored"] += 1
        return None

    def _lease_ip_for(self, mac: str) -> Optional[str]:
        for lease in self.leases.leases.values():
            if lease.mac == mac:
                return lease.ip
        return None

    def _on_discover(self, pkt: Packet, mac: str, hostname: str, now: float) -> Optional[Tuple[bytes, str, str]]:
        requested = pkt.opt_ip(OPT_REQUESTED_IP)
        ip = self._free_ip(mac, requested, now)
        if not ip:
            self.counters["ignored"] += 1
            self._event("pool_exhausted", mac, "", hostname, now)
            return None

        static = mac in self.static
        self.leases.put(Lease(
            ip=ip, mac=mac, hostname=hostname, client_id=pkt.client_id(),
            expires=now + 60, state="offered", static=static,
        ))
        options = self._config_options()
        options[OPT_LEASE_TIME] = struct.pack("!I", self.lease_time)
        reply = build_reply(pkt, OFFER, ip, self.server_ip, options)
        self._event("offer", mac, ip, hostname, now)
        return reply, f"OFFER {ip}", mac

    def _on_request(self, pkt: Packet, mac: str, hostname: str, now: float) -> Optional[Tuple[bytes, str, str]]:
        server_id = pkt.opt_ip(OPT_SERVER_ID)
        if server_id and server_id != self.server_ip:
            # 客户端选了别的 DHCP 服务器，我们安静退场
            self.counters["ignored"] += 1
            return None

        requested = pkt.opt_ip(OPT_REQUESTED_IP)
        if not requested or requested == "0.0.0.0":
            requested = pkt.ciaddr if pkt.ciaddr != "0.0.0.0" else None

        static_ip = self.static.get(mac)
        if static_ip and requested and requested != static_ip:
            return self._nak(pkt, mac, requested, hostname, now, "请求的不是固定租约地址")

        if requested is None:
            requested = self._free_ip(mac, None, now)
            if requested is None:
                return None

        holder = self.leases.by_ip(requested)
        renewing = holder is not None and holder.mac == mac

        if not renewing and not self._ip_available(requested, mac, now) and static_ip != requested:
            return self._nak(pkt, mac, requested, hostname, now, "地址已被占用或不在地址池内")

        options = self._config_options()
        options[OPT_LEASE_TIME] = struct.pack("!I", self.lease_time)
        options[OPT_RENEWAL_T1] = struct.pack("!I", self.lease_time // 2)
        options[OPT_REBIND_T2] = struct.pack("!I", int(self.lease_time * 0.875))
        self.leases.put(Lease(
            ip=requested, mac=mac, hostname=hostname, client_id=pkt.client_id(),
            expires=now + self.lease_time, state="bound", static=bool(static_ip),
        ))
        reply = build_reply(pkt, ACK, requested, self.server_ip, options)
        self._event("ack", mac, requested, hostname, now)
        return reply, f"ACK {requested}", mac

    def _nak(self, pkt: Packet, mac: str, ip: str, hostname: str, now: float, why: str) -> Tuple[bytes, str, str]:
        self.counters["nak"] += 1
        reply = build_reply(pkt, NAK, "0.0.0.0", self.server_ip)
        self._event("nak", mac, ip, hostname, now, why)
        return reply, f"NAK {ip}（{why}）", mac

    def _config_options(self) -> Dict[int, bytes]:
        opts: Dict[int, bytes] = {
            OPT_NETMASK: socket.inet_aton(self.netmask),
            OPT_ROUTER: socket.inet_aton(self.server_ip),
            OPT_BROADCAST: socket.inet_aton(self.broadcast),
        }
        if self.dns:
            opts[OPT_DNS] = b"".join(socket.inet_aton(ip) for ip in self.dns)
        if self.domain:
            opts[OPT_DOMAIN] = self.domain.encode("utf-8")
        if self.mtu:
            opts[OPT_MTU] = struct.pack("!H", self.mtu)
        return opts

    def _event(self, event: str, mac: str, ip: str, hostname: str, now: float, detail: str = "") -> None:
        self.events.add({
            "t": now, "event": event, "mac": mac, "ip": ip,
            "hostname": hostname, "detail": detail,
        })

    # ------------------------------------------------------------ 状态快照
    def snapshot(self, now: Optional[float] = None) -> Dict[str, Any]:
        now = now if now is not None else self.now()
        leases = sorted(self.leases.active(now), key=lambda l: iputil.ip_to_int(l.ip))
        return {
            "server_ip": self.server_ip,
            "subnet": self.subnet,
            "netmask": self.netmask,
            "pool": [self.pool_start, self.pool_end],
            "pool_size": len(self.pool()),
            "pool_used": len([l for l in leases if l.ip in set(self.pool())]),
            "lease_time": self.lease_time,
            "counters": dict(self.counters),
            "leases": [
                {**l.to_dict(), "remaining": l.remaining} for l in leases
            ],
        }


# ------------------------------------------------------------------- 服务层


class DHCPServer(threading.Thread):
    """套接字层：收包交给 :class:`DHCPResponder`，回包按需走原始帧或 UDP。"""

    def __init__(
        self,
        responder: DHCPResponder,
        iface: Optional[str] = None,
        bind: str = "0.0.0.0",
        port: int = 67,
        log: Optional[Callable[[str], None]] = None,
        use_raw: bool = True,
    ) -> None:
        super().__init__(name="dhcpd", daemon=True)
        self.responder = responder
        self.iface = iface
        self.bind = bind
        self.port = port
        self.log = log or (lambda _m: None)
        self.use_raw = use_raw
        self.sock: Optional[socket.socket] = None
        self.raw: Optional[socket.socket] = None
        self.src_mac: bytes = b"\x00" * 6
        self._stop = threading.Event()
        self.last_error: str = ""
        self.stats = {"rx": 0, "tx": 0, "errors": 0, "raw_frames": 0, "udp_replies": 0}

    # ------------------------------------------------------------ 生命周期
    def open(self) -> bool:
        """绑定 67 端口并尝试打开原始套接字。失败时把原因写进 ``last_error``。"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if self.iface:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface.encode() + b"\x00")
                except OSError as exc:
                    self.log(f"SO_BINDTODEVICE({self.iface}) 失败，仍继续: {exc}")
            sock.bind((self.bind, self.port))
            sock.settimeout(1.0)
            self.sock = sock
        except OSError as exc:
            self.last_error = f"绑定 {self.bind}:{self.port} 失败: {exc}（端口 <1024 需要 root）"
            return False

        if self.use_raw and self.iface:
            self.src_mac = self._read_iface_mac(self.iface)
            try:
                raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
                raw.bind((self.iface, 0))
                raw.settimeout(1.0)
                self.raw = raw
            except OSError as exc:
                self.log(f"原始套接字不可用，退回 UDP 广播方式: {exc}")
                self.raw = None
        return True

    @staticmethod
    def _read_iface_mac(iface: str) -> bytes:
        try:
            text = Path(f"/sys/class/net/{iface}/address").read_text(encoding="utf-8").strip()
            return iputil.mac_to_bytes(text)
        except (OSError, ValueError):
            return b"\x00" * 6

    def stop(self) -> None:
        self._stop.set()
        for sock in (self.sock, self.raw):
            try:
                if sock:
                    sock.close()
            except OSError:
                pass
        self.sock = None
        self.raw = None

    # ---------------------------------------------------------------- 主循环
    def run(self) -> None:  # pragma: no cover - 需要真实网络环境
        if not self.sock and not self.open():
            return
        assert self.sock is not None
        self.log(f"DHCP 已启动：{self.bind}:{self.port} 接口={self.iface or '全部'}"
                 f" 原始帧={'开' if self.raw else '关'}")
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                self.responder.leases.save()
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            self.stats["rx"] += 1
            result = self.responder.respond(data)
            if result is None:
                continue
            reply, action, mac = result
            try:
                self._send(reply, data, addr)
                self.stats["tx"] += 1
                self.log(f"DHCP {action} ({mac})")
            except OSError as exc:
                self.stats["errors"] += 1
                self.log(f"DHCP 回包失败: {exc}")

    def _send(self, reply: bytes, request: bytes, addr: Tuple[str, int]) -> None:
        try:
            pkt = parse_packet(request)
            dst_mac = pkt.chaddr[:6]
            broadcast = pkt.broadcast_requested or pkt.ciaddr == "0.0.0.0"
        except ValueError:
            dst_mac = b"\xff" * 6
            broadcast = True

        if self.raw and self.src_mac != b"\x00" * 6:
            eth_dst = b"\xff" * 6 if broadcast else dst_mac
            frame = build_udp_ip_frame(
                self.src_mac, eth_dst, self.responder.server_ip, "255.255.255.255",
                self.port, 68, reply,
            )
            self.raw.send(frame)
            self.stats["raw_frames"] += 1
            return

        assert self.sock is not None
        if broadcast:
            self.sock.sendto(reply, ("255.255.255.255", 68))
        else:
            try:
                self.sock.sendto(reply, (addr[0], 68))
            except OSError:
                self.sock.sendto(reply, ("255.255.255.255", 68))
        self.stats["udp_replies"] += 1

    def snapshot(self) -> Dict[str, Any]:
        return {
            "running": self.is_alive() and self.sock is not None,
            "iface": self.iface,
            "port": self.port,
            "mode": "raw" if self.raw else "udp",
            "stats": dict(self.stats),
            "last_error": self.last_error,
        }


def build_responder(cfg, events: Optional[store.RingBuffer] = None) -> DHCPResponder:
    """按配置构造 responder（供 daemon 与 CLI 共用）。"""
    return DHCPResponder(
        server_ip=str(cfg.get("lan.gateway")),
        subnet=str(cfg.get("lan.subnet")),
        pool_start=str(cfg.get("lan.pool_start")),
        pool_end=str(cfg.get("lan.pool_end")),
        lease_time=int(cfg.get("lan.lease_time", 3600)),
        dns=cfg.dns_servers(),
        domain=str(cfg.get("dhcp.domain", "lan")),
        mtu=int(cfg.get("dhcp.mtu", 1500)),
        static_leases=dict(cfg.get("static_leases") or {}),
        store_obj=LeaseStore().load(),
        events=events,
    )
