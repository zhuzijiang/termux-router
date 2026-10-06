"""纯 Python DNS 转发器（带缓存与广告拦截）。

又一个"零依赖"决定：不用 dnsmasq，自己实现。DNS 是低速协议
（一台设备每秒几个查询），Python 足够，而省下的一个软件包对手机更值钱。

实现要点：

* **转发不解析**：拿到客户端查询后，除了解析出 qname 用于查拦截规则，
  其余字节**原样转发**给上游。解析整个响应报文再重组是 bug 温床
  （EDNS0、未知 RR 类型、DNSSEC 记录都会踩坑），原样转发最安全。
* **缓存**用 ``(qname, qtype)`` 做键，命中后只改事务 ID 和 TTL 字段，
  不改结构。TTL 重写需要正确跳过压缩指针，见 :func:`walk_ttl_offsets`。
* **拦截**同时处理 A/AAAA 与 HTTPS/SVCB 记录。只拦 A 记录是个经典漏洞：
  现代浏览器会优先用 HTTPS(65) 记录里的地址绕过拦截。
* **TCP 回退**：上游响应被截断（TC 位置位）时自动改用 TCP 重查。
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import store

# 记录类型
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_AAAA = 28
TYPE_HTTPS = 65
TYPE_SVCB = 64

TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}

# 应被拦截的查询：这些类型的答案会携带真实 IP，必须一并处理
BLOCK_TYPES = {TYPE_A, TYPE_AAAA, TYPE_HTTPS, TYPE_SVCB}

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5

DEFAULT_MAX_TTL = 3600
DEFAULT_MIN_TTL = 5
MAX_UDP_SIZE = 4096


# --------------------------------------------------------------- 报文解析


def _skip_name(data: bytes, offset: int) -> int:
    """跳过一个（可能带压缩指针的）域名，返回紧随其后的偏移。"""
    while True:
        if offset >= len(data):
            raise ValueError("域名越界")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("压缩指针越界")
            return offset + 2
        if length & 0xC0:
            raise ValueError(f"非法标签长度: {length}")
        offset += length + 1


def decode_name(data: bytes, offset: int, max_jumps: int = 16) -> Tuple[str, int]:
    """解码域名，返回 ``(名字, 下一个偏移)``。支持压缩指针。"""
    labels: List[str] = []
    jumps = 0
    next_offset: Optional[int] = None
    pos = offset
    while True:
        if pos >= len(data):
            raise ValueError("域名越界")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("压缩指针越界")
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if next_offset is None:
                next_offset = pos + 2
            jumps += 1
            if jumps > max_jumps:
                raise ValueError("压缩指针成环")
            pos = pointer
            continue
        if length & 0xC0:
            raise ValueError(f"非法标签长度: {length}")
        label = data[pos + 1 : pos + 1 + length]
        labels.append(label.decode("ascii", "replace"))
        pos += length + 1
    if next_offset is not None:
        pos = next_offset
    return ".".join(labels), pos


@dataclass
class Question:
    name: str
    qtype: int
    qclass: int
    end: int

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.qtype, str(self.qtype))


def parse_question(data: bytes) -> Question:
    """只解析头部与第一个问题——这已经足够做拦截判断。"""
    if len(data) < 12:
        raise ValueError("DNS 报文太短")
    qdcount = struct.unpack("!H", data[4:6])[0]
    if qdcount < 1:
        raise ValueError("没有查询段")
    name, offset = decode_name(data, 12)
    if offset + 4 > len(data):
        raise ValueError("查询段被截断")
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    return Question(name=name.lower().rstrip("."), qtype=qtype, qclass=qclass, end=offset + 4)


def transaction_id(data: bytes) -> int:
    return struct.unpack("!H", data[:2])[0]


def set_transaction_id(data: bytes, xid: int) -> bytes:
    return struct.pack("!H", xid) + data[2:]


def walk_ttl_offsets(data: bytes) -> List[int]:
    """返回报文中所有 RR 的 TTL 字段偏移（用于缓存命中时递减 TTL）。"""
    if len(data) < 12:
        return []
    qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
    offsets: List[int] = []
    try:
        offset = 12
        for _ in range(qd):
            offset = _skip_name(data, offset) + 4
        for count in (an, ns, ar):
            for _ in range(count):
                offset = _skip_name(data, offset)
                if offset + 10 > len(data):
                    return offsets
                offsets.append(offset + 4)
                rdlength = struct.unpack("!H", data[offset + 8 : offset + 10])[0]
                offset += 10 + rdlength
    except ValueError:
        return offsets
    return offsets


def min_ttl(data: bytes) -> int:
    """取报文里最小的 TTL；没有 RR 时返回 0。"""
    values = []
    for off in walk_ttl_offsets(data):
        if off + 4 <= len(data):
            values.append(struct.unpack("!I", data[off : off + 4])[0])
    return min(values) if values else 0


def rewrite_ttls(data: bytes, ttl: int) -> bytes:
    """把所有 RR 的 TTL 统一改写成 ``ttl``。"""
    buf = bytearray(data)
    packed = struct.pack("!I", max(0, int(ttl)))
    for off in walk_ttl_offsets(data):
        if off + 4 <= len(buf):
            buf[off : off + 4] = packed
    return bytes(buf)


def build_response(query: bytes, rcode: int = RCODE_NOERROR, answers: bytes = b"",
                   ancount: int = 0) -> bytes:
    """构造一个最小响应：回显问题段，按需附加答案。"""
    question = parse_question(query)
    qdcount = 1
    flags = 0x8180 | (rcode & 0x0F)  # QR=1, RD=1, RA=1
    header = struct.pack("!HHHHHH", transaction_id(query), flags, qdcount, ancount, 0, 0)
    return header + query[12 : question.end] + answers


def build_a_answer(query: bytes, ip: str) -> Tuple[bytes, int]:
    """为 A 查询构造一个指向 ``ip`` 的答案，名字用压缩指针指向问题段。"""
    question = parse_question(query)
    # 指针 0xC00C 指向报文偏移 12（即问题段里的 qname）
    name = b"\xc0\x0c"
    rr = name + struct.pack("!HHIH", TYPE_A, 1, 300, 4) + socket.inet_aton(ip)
    return build_response(query, RCODE_NOERROR, rr, ancount=1), 1


# ------------------------------------------------------------------ 拦截表


class DomainBlocklist:
    """域名黑/白名单。

    匹配语义（与 Pi-hole 一类工具保持一致，符合用户直觉）：

    * 精确命中 ``ads.example.com`` ⇒ 拦截
    * 命中父域 ``example.com`` ⇒ **其所有子域**也被拦截
    * ``*.example.com`` 形式的条目只拦子域，不拦 ``example.com`` 本身
    * 白名单（allow）优先级最高，用于放行误杀
    """

    def __init__(self) -> None:
        self.exact: set[str] = set()
        self.wildcard: set[str] = set()
        self.allow: set[str] = set()
        self.hits = 0
        self.sources: Dict[str, int] = {}

    # ------------------------------------------------------------ 装载
    @staticmethod
    def normalize(domain: str) -> str:
        d = domain.strip().lower().rstrip(".")
        if d.startswith("http://") or d.startswith("https://"):
            d = d.split("//", 1)[1]
        d = d.split("/", 1)[0].split(":", 1)[0]
        return d

    def add(self, domain: str, wildcard: bool = False) -> bool:
        d = self.normalize(domain)
        if not d or d in ("localhost", "localhost.localdomain", "broadcast", "0.0.0.0"):
            return False
        if d.startswith("*."):
            self.wildcard.add(d[2:])
            return True
        if wildcard:
            self.wildcard.add(d)
            return True
        self.exact.add(d)
        return True

    def allow_domain(self, domain: str) -> bool:
        d = self.normalize(domain)
        if d:
            self.allow.add(d)
            return True
        return False

    def load_file(self, path: str, source: Optional[str] = None) -> int:
        """加载 hosts 格式或纯域名列表。返回新增条数。"""
        p = Path(path).expanduser()
        count = 0
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return 0
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].split("!", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and _looks_like_ip(parts[0]):
                domain = parts[1]
            elif len(parts) == 1:
                domain = parts[0]
            else:
                continue
            if self.add(domain):
                count += 1
        if count:
            self.sources[str(p)] = count
            if source:
                self.sources[source] = count
        return count

    # ------------------------------------------------------------ 匹配
    def match(self, domain: str) -> bool:
        d = self.normalize(domain)
        if not d:
            return False
        if d in self.allow:
            return False
        labels = d.split(".")
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.allow:
                return False
            if i == 0:
                # 精确条目连域名本身一起拦；通配条目（*.x）只拦子域，
                # 因为 i==0 时 candidate 就是域名本身，此时不看 wildcard
                if candidate in self.exact:
                    return True
            else:
                if candidate in self.exact or candidate in self.wildcard:
                    return True
        return False

    def stats(self) -> Dict[str, Any]:
        return {
            "exact": len(self.exact),
            "wildcard": len(self.wildcard),
            "allow": len(self.allow),
            "hits": self.hits,
            "sources": dict(self.sources),
        }


def _looks_like_ip(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# -------------------------------------------------------------------- 缓存


@dataclass
class CacheEntry:
    response: bytes
    expires: float
    stored: float
    hits: int = 0


class DNSCache:
    """带容量上限的字典缓存（不追求 LRU 精细度，够用且简单）。"""

    def __init__(self, capacity: int = 1024, max_ttl: int = DEFAULT_MAX_TTL,
                 min_ttl: int = DEFAULT_MIN_TTL) -> None:
        self.capacity = max(4, int(capacity))
        self.max_ttl = max_ttl
        self.min_ttl = min_ttl
        self._data: Dict[Tuple[str, int], CacheEntry] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    @staticmethod
    def key(question: Question) -> Tuple[str, int]:
        return (question.name, question.qtype)

    def get(self, question: Question, now: Optional[float] = None) -> Optional[bytes]:
        now = now if now is not None else time.time()
        key = self.key(question)
        with self._lock:
            entry = self._data.get(key)
            if not entry or entry.expires <= now:
                if entry:
                    del self._data[key]
                self.misses += 1
                return None
            entry.hits += 1
            self.hits += 1
            remaining = max(self.min_ttl, int(entry.expires - now))
            stored = entry.stored
            response = entry.response
        # 事务 ID 必须是本次查询的；TTL 按已过时间递减
        return rewrite_ttls(set_transaction_id(response, 0), remaining)

    def put(self, question: Question, response: bytes, now: Optional[float] = None) -> bool:
        """写入缓存。``rcode`` 非 0 的响应不缓存（避免把临时故障固化）。"""
        now = now if now is not None else time.time()
        if len(response) < 12:
            return False
        rcode = response[3] & 0x0F
        if rcode != RCODE_NOERROR:
            return False
        ttl = min_ttl(response)
        if ttl <= 0:
            return False
        ttl = max(self.min_ttl, min(self.max_ttl, ttl))
        key = self.key(question)
        with self._lock:
            if len(self._data) >= self.capacity:
                # 淘汰最早过期的四分之一，O(n log n) 但只在满的时候发生
                victims = sorted(self._data.items(), key=lambda kv: kv[1].expires)[: max(1, self.capacity // 4)]
                for k, _ in victims:
                    del self._data[k]
                    self.evictions += 1
            self._data[key] = CacheEntry(response=response, expires=now + ttl, stored=now)
        return True

    def clear(self) -> int:
        with self._lock:
            n = len(self._data)
            self._data.clear()
        return n

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            size = len(self._data)
        total = self.hits + self.misses
        return {
            "size": size,
            "capacity": self.capacity,
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "hit_rate": round(self.hits / total, 4) if total else 0.0,
        }


# ----------------------------------------------------------------- 转发服务


class DNSProxy:
    """DNS 服务。``start()`` 后跑在独立线程里。

    UDP 是主路径；同时可选监听 TCP（部分客户端与 DNSSEC 大响应需要）。
    """

    def __init__(
        self,
        upstream: Sequence[str],
        bind: str = "0.0.0.0",
        port: int = 53,
        blocklist: Optional[DomainBlocklist] = None,
        cache: Optional[DNSCache] = None,
        block_response: str = "0.0.0.0",
        timeout: float = 3.0,
        log_queries: bool = True,
        log_size: int = 500,
        log: Optional[Callable[[str], None]] = None,
        enable_tcp: bool = True,
    ) -> None:
        self.upstream = [u for u in upstream if u]
        self.bind = bind
        self.port = port
        self.blocklist = blocklist or DomainBlocklist()
        self.cache = cache or DNSCache()
        self.block_response = block_response
        self.timeout = timeout
        self.log_queries = log_queries
        self.query_log = store.RingBuffer(log_size)
        self.log = log or (lambda _m: None)
        self.enable_tcp = enable_tcp

        self.udp_sock: Optional[socket.socket] = None
        self.tcp_sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self.last_error = ""
        self.stats = {"queries": 0, "forwarded": 0, "cached": 0, "blocked": 0,
                      "errors": 0, "tcp_queries": 0}

    # ------------------------------------------------------------ 生命周期
    def open(self) -> bool:
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind((self.bind, self.port))
            udp.settimeout(1.0)
            self.udp_sock = udp
        except OSError as exc:
            self.last_error = f"UDP 绑定 {self.bind}:{self.port} 失败: {exc}（端口 <1024 需要 root）"
            return False

        if self.enable_tcp:
            try:
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp.bind((self.bind, self.port))
                tcp.listen(16)
                tcp.settimeout(1.0)
                self.tcp_sock = tcp
            except OSError as exc:
                self.log(f"TCP/53 不可用，仅提供 UDP: {exc}")
                self.tcp_sock = None
        return True

    def start(self) -> bool:
        if not self.open():
            return False
        for target in (self._udp_loop, self._tcp_loop):
            if target is self._tcp_loop and not self.tcp_sock:
                continue
            th = threading.Thread(target=target, name=f"dns-{target.__name__}", daemon=True)
            th.start()
            self._threads.append(th)
        self.log(f"DNS 已启动：{self.bind}:{self.port} 上游={','.join(self.upstream)}"
                 f" 拦截规则={len(self.blocklist.exact) + len(self.blocklist.wildcard)}")
        return True

    def stop(self) -> None:
        self._stop.set()
        for sock in (self.udp_sock, self.tcp_sock):
            try:
                if sock:
                    sock.close()
            except OSError:
                pass
        self.udp_sock = None
        self.tcp_sock = None

    @property
    def running(self) -> bool:
        return any(t.is_alive() for t in self._threads) and self.udp_sock is not None

    # ---------------------------------------------------------------- 循环
    def _udp_loop(self) -> None:  # pragma: no cover - 需要真实网络
        assert self.udp_sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self.udp_sock.recvfrom(MAX_UDP_SIZE)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            try:
                response = self.handle(data, addr[0])
            except Exception as exc:  # 单个坏包不能弄死整个服务
                self.stats["errors"] += 1
                self.log(f"DNS 处理异常: {exc!r}")
                continue
            if response:
                try:
                    self.udp_sock.sendto(response, addr)
                except OSError as exc:
                    self.log(f"DNS 回包失败: {exc}")

    def _tcp_loop(self) -> None:  # pragma: no cover - 需要真实网络
        assert self.tcp_sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self.tcp_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            threading.Thread(target=self._tcp_conn, args=(conn, addr), daemon=True).start()

    def _tcp_conn(self, conn: socket.socket, addr) -> None:  # pragma: no cover
        with conn:
            conn.settimeout(self.timeout + 2)
            try:
                head = _recv_exact(conn, 2)
                if not head:
                    return
                length = struct.unpack("!H", head)[0]
                data = _recv_exact(conn, length)
                if not data:
                    return
                self.stats["tcp_queries"] += 1
                response = self.handle(data, addr[0])
                if response:
                    conn.sendall(struct.pack("!H", len(response)) + response)
            except OSError:
                return

    # ------------------------------------------------------------ 请求处理
    def handle(self, data: bytes, client: str = "-", now: Optional[float] = None) -> Optional[bytes]:
        """处理一个 DNS 查询，返回要发回的字节；None 表示忽略。"""
        now = now if now is not None else time.time()
        started = now
        try:
            question = parse_question(data)
        except ValueError:
            self.stats["errors"] += 1
            return None

        self.stats["queries"] += 1
        action = "forward"

        if self.blocklist.match(question.name):
            self.stats["blocked"] += 1
            self.blocklist.hits += 1
            action = "blocked"
            response = self._blocked_response(data, question)
        else:
            cached = self.cache.get(question, now=now)
            if cached is not None:
                self.stats["cached"] += 1
                action = "cache"
                response = set_transaction_id(cached, transaction_id(data))
            else:
                response = self._forward(data)
                if response is None:
                    self.stats["errors"] += 1
                    action = "servfail"
                    response = build_response(data, RCODE_SERVFAIL)
                else:
                    self.stats["forwarded"] += 1
                    self.cache.put(question, response, now=now)

        if self.log_queries:
            self.query_log.add({
                "t": now,
                "client": client,
                "name": question.name,
                "type": question.type_name,
                "action": action,
                "ms": round((time.time() - started) * 1000, 2),
            })
        return response

    def _blocked_response(self, data: bytes, question: Question) -> bytes:
        """命中拦截时的回答。

        A 查询返回配置的地址（默认 0.0.0.0）；AAAA/HTTPS/SVCB 返回
        NODATA（无答案的 NOERROR）——这样浏览器拿不到任何可用地址，
        又不会因为 NXDOMAIN 触发某些客户端的重试风暴。
        """
        if question.qtype == TYPE_A and self.block_response not in ("nxdomain", "nodata", ""):
            if _looks_like_ip(self.block_response):
                payload, _ = build_a_answer(data, self.block_response)
                return payload
        if question.qtype in (TYPE_AAAA, TYPE_HTTPS, TYPE_SVCB):
            return build_response(data, RCODE_NOERROR)
        if self.block_response == "nxdomain":
            return build_response(data, RCODE_NXDOMAIN)
        return build_response(data, RCODE_NOERROR)

    # ---------------------------------------------------------------- 上游
    def _forward(self, data: bytes) -> Optional[bytes]:
        for upstream in self.upstream:
            response = self._forward_udp(data, upstream)
            if response is None:
                continue
            if len(response) > 12 and (response[2] & 0x02):  # TC 位：响应被截断
                tcp_response = self._forward_tcp(data, upstream)
                if tcp_response:
                    return tcp_response
            if transaction_id(response) != transaction_id(data):
                continue  # ID 不匹配，丢弃（防投毒）
            return response
        return None

    def _forward_udp(self, data: bytes, upstream: str) -> Optional[bytes]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            sock.sendto(data, (upstream, 53))
            response, _ = sock.recvfrom(MAX_UDP_SIZE)
            return response
        except OSError:
            return None
        finally:
            sock.close()

    def _forward_tcp(self, data: bytes, upstream: str) -> Optional[bytes]:
        try:
            conn = socket.create_connection((upstream, 53), timeout=self.timeout)
        except OSError:
            return None
        with conn:
            try:
                conn.sendall(struct.pack("!H", len(data)) + data)
                head = _recv_exact(conn, 2)
                if not head:
                    return None
                length = struct.unpack("!H", head)[0]
                return _recv_exact(conn, length)
            except OSError:
                return None

    # ---------------------------------------------------------------- 状态
    def snapshot(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "bind": f"{self.bind}:{self.port}",
            "upstream": list(self.upstream),
            "tcp": self.tcp_sock is not None,
            "stats": dict(self.stats),
            "cache": self.cache.stats(),
            "blocklist": self.blocklist.stats(),
            "last_error": self.last_error,
        }


def _recv_exact(conn: socket.socket, count: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def build_proxy(cfg, log: Optional[Callable[[str], None]] = None) -> DNSProxy:
    """按配置构造 DNS 服务（含拦截表装载）。"""
    blocklist = DomainBlocklist()
    for path in cfg.get("dns.blocklists") or []:
        n = blocklist.load_file(str(path))
        if log and n:
            log(f"拦截表 {path}: 载入 {n} 条")
    proxy = DNSProxy(
        upstream=[str(u) for u in (cfg.get("dns.upstream") or [])],
        bind="0.0.0.0",
        port=int(cfg.get("dns.port", 53)),
        blocklist=blocklist,
        cache=DNSCache(capacity=int(cfg.get("dns.cache_size", 1024))),
        block_response=str(cfg.get("dns.block_response", "0.0.0.0")),
        timeout=float(cfg.get("dns.query_timeout", 3.0)),
        log_queries=bool(cfg.get("dns.log_queries", True)),
        log_size=int(cfg.get("dns.log_size", 500)),
        log=log,
    )
    return proxy
