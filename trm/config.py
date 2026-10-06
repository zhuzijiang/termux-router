"""配置加载 / 保存 / 校验。

配置格式是 JSON（标准库自带，不引入 YAML 依赖）。所有默认值集中在
``DEFAULTS``，用户配置只需写要覆盖的部分，加载时做深合并。
"""

from __future__ import annotations

import copy
import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import iputil, paths

DEFAULTS: Dict[str, Any] = {
    "version": 1,
    # 内网（热点侧）参数
    "lan": {
        "iface": "auto",          # auto = 自动探测，通常是 ap0 / wlan1 / softap0
        "subnet": "192.168.43.0/24",
        "gateway": "192.168.43.1",
        "pool_start": "192.168.43.50",
        "pool_end": "192.168.43.200",
        "lease_time": 3600,
    },
    # 外网（数据侧）参数
    "wan": {"iface": "auto"},
    # 自建 DHCP 服务器
    "dhcp": {
        "enabled": True,
        "domain": "lan",
        "dns": [],                # 空 = 用本机网关地址做 DNS
        "mtu": 1500,
    },
    # 自建 DNS 转发 + 缓存 + 拦截
    "dns": {
        "enabled": True,
        "port": 53,
        "upstream": ["1.1.1.1", "8.8.8.8"],
        "cache_size": 1024,
        "block_response": "0.0.0.0",   # 命中拦截时返回的地址，可用 "nxdomain"
        "blocklists": [],              # hosts 格式或纯域名列表的本地文件路径
        "blocked": [],                 # 面板/CLI 手动加入的拦截域名（持久化）
        "allowed": [],                 # 白名单，优先级最高
        "log_queries": True,
        "log_size": 500,
        "query_timeout": 3.0,
    },
    # 管理面板
    "web": {
        "host": "127.0.0.1",
        "port": 8080,
        "token": "",               # 空 = 首次启动自动生成
        "refresh_ms": 2000,
    },
    # 限速（tc HTB）
    "shaper": {
        "enabled": False,
        "iface": "auto",
        "default_down_kbps": 0,    # 0 = 不限
        "default_up_kbps": 0,
    },
    # iptables 数据面开关
    "netfilter": {
        "masquerade": True,
        "mss_clamp": True,         # 修复 PMTU 黑洞，手机热点的经典坑
        "hijack_dns": False,       # 强制把 53 端口劫持到本机 DNS
        "icmp_redirect_off": True,
    },
    # 系统热点控制（命令模板，按机型可改）
    "hotspot": {
        "ssid": "",
        "passphrase": "",
        "band": "2.4",
        "start_cmd": "",           # 例：cmd wifi start-softap {ssid} wpa2 {passphrase}
        "stop_cmd": "",
        "status_cmd": "",
    },
    # 固定租约：{"aa:bb:cc:dd:ee:ff": "192.168.43.10"}
    "static_leases": {},
    # 客户端备注：{"192.168.43.55": "客厅电视"}
    "client_names": {},
    # 每客户端限速：{"192.168.43.55": {"down_kbps": 2048, "up_kbps": 512}}
    "limits": {},
    "log_level": "info",
}


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """递归合并，``override`` 优先，返回新字典（不修改入参）。"""
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def new_token() -> str:
    return secrets.token_urlsafe(24)


def coerce_scalar(text: str) -> Any:
    """把 CLI 传入的字符串转成合适的类型。

    支持 ``true/false``、整数、浮点、以及以 ``[``/``{`` 开头的 JSON。
    """
    raw = text.strip()
    low = raw.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none"):
        return None
    if raw[:1] in "[{":
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


class Config:
    """配置对象：支持点号路径读写，改动后调用 :meth:`save`。"""

    def __init__(self, data: Optional[Dict[str, Any]] = None, path: Optional[Path] = None) -> None:
        self.data: Dict[str, Any] = deep_merge(DEFAULTS, data or {})
        self.path: Path = Path(path) if path else paths.config_file()

    # ---------------------------------------------------------------- 读写
    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        target = Path(path) if path else paths.config_file()
        raw: Dict[str, Any] = {}
        if target.exists():
            try:
                raw = json.loads(target.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                raise ValueError(f"配置文件损坏 {target}: {exc}") from exc
            if not isinstance(raw, dict):
                raise ValueError(f"配置文件根节点必须是对象: {target}")
        cfg = cls(raw, target)
        cfg.ensure_token()
        return cfg

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    def ensure_token(self) -> str:
        """确保存在面板访问令牌（空则生成）。"""
        token = self.data.setdefault("web", {}).get("token") or ""
        if not token:
            token = new_token()
            self.data["web"]["token"] = token
        return token

    # ------------------------------------------------------------ 点号访问
    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        node = self.data
        for part in parts[:-1]:
            nxt = node.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                node[part] = nxt
            node = nxt
        node[parts[-1]] = value

    def unset(self, dotted: str) -> bool:
        parts = dotted.split(".")
        node = self.data
        for part in parts[:-1]:
            node = node.get(part)  # type: ignore[assignment]
            if not isinstance(node, dict):
                return False
        return node.pop(parts[-1], None) is not None

    # ------------------------------------------------------------- 便捷属性
    @property
    def lan(self) -> Dict[str, Any]:
        return self.data["lan"]

    @property
    def wan(self) -> Dict[str, Any]:
        return self.data["wan"]

    @property
    def web(self) -> Dict[str, Any]:
        return self.data["web"]

    def gateway_ip(self) -> str:
        return str(self.get("lan.gateway", "192.168.43.1"))

    def dns_servers(self) -> List[str]:
        """DHCP 要下发给客户端的 DNS 列表。"""
        configured = self.get("dhcp.dns") or []
        if configured:
            return [str(x) for x in configured]
        return [self.gateway_ip()]

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self.data)


def validate(cfg: Config) -> List[str]:
    """返回问题列表（空列表代表没问题）。只做能确定的检查，不猜。"""
    problems: List[str] = []
    lan = cfg.data["lan"]
    subnet = str(lan.get("subnet", ""))
    gateway = str(lan.get("gateway", ""))
    pool_start = str(lan.get("pool_start", ""))
    pool_end = str(lan.get("pool_end", ""))

    try:
        net, prefix = iputil.parse_cidr(subnet)
    except (ValueError, TypeError) as exc:
        problems.append(f"lan.subnet 非法: {exc}")
        net = prefix = None  # type: ignore[assignment]

    if not iputil.is_valid_ip(gateway):
        problems.append(f"lan.gateway 非法: {gateway!r}")
    elif net is not None and not iputil.in_cidr(gateway, subnet):
        problems.append(f"lan.gateway ({gateway}) 不在 lan.subnet ({subnet}) 内")

    for label, value in (("lan.pool_start", pool_start), ("lan.pool_end", pool_end)):
        if not iputil.is_valid_ip(value):
            problems.append(f"{label} 非法: {value!r}")
        elif net is not None and not iputil.in_cidr(value, subnet):
            problems.append(f"{label} ({value}) 不在 lan.subnet ({subnet}) 内")

    if iputil.is_valid_ip(pool_start) and iputil.is_valid_ip(pool_end):
        if iputil.ip_to_int(pool_start) > iputil.ip_to_int(pool_end):
            problems.append("lan.pool_start 大于 lan.pool_end")

    if prefix is not None and prefix > 30:
        problems.append(f"lan.subnet 前缀 /{prefix} 太小，装不下一台路由器加客户端（建议 /24）")

    for mac, ip in (cfg.get("static_leases") or {}).items():
        if not iputil.is_valid_mac(mac):
            problems.append(f"static_leases 里的 MAC 非法: {mac!r}")
        if not iputil.is_valid_ip(str(ip)):
            problems.append(f"static_leases[{mac}] 的 IP 非法: {ip!r}")

    port = cfg.get("web.port")
    if not iputil.is_valid_port(int(port) if isinstance(port, int) else 0):
        problems.append(f"web.port 非法: {port!r}")

    host = str(cfg.get("web.host", ""))
    if host not in ("127.0.0.1", "localhost", "::1") and not cfg.get("web.token"):
        problems.append("web.host 不是回环地址却没有设置 web.token，面板会毫无保护地暴露")

    dns_port = cfg.get("dns.port")
    if not iputil.is_valid_port(int(dns_port) if isinstance(dns_port, int) else 0):
        problems.append(f"dns.port 非法: {dns_port!r}")

    for up in cfg.get("dns.upstream") or []:
        if not iputil.is_valid_ip(str(up)):
            problems.append(f"dns.upstream 非法: {up!r}")

    for path in cfg.get("dns.blocklists") or []:
        if not Path(str(path)).expanduser().exists():
            problems.append(f"dns.blocklists 里的文件不存在: {path}")

    return problems
