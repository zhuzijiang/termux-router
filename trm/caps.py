"""能力探测——本项目最重要的一个模块。

为什么它最重要：Android 上"把手机变成路由器"的唯一真解是**内核转发**
（iptables/nftables NAT + tc 限速），而这一切都需要 **真正的 root**。
但存在一个致命陷阱：

    PRoot / proot-distro 容器里 ``id -u`` 会返回 0，``geteuid()`` 也返回 0，
    看起来像 root，**实际上进程真实身份仍是 Termux 应用 uid（如 u0_a408）**，
    既没有 CAP_NET_ADMIN，也碰不到 netfilter。

所以这里绝不使用 ``os.getuid()`` 判断 root，而是读 ``/proc/self/status``
的 ``Uid:`` 字段——在 proot 下它会暴露真实 uid。顺便，这个差异本身
就是最可靠的 proot 检测手段：``os.getuid() != /proc 里的真实 uid`` 即 proot。

探测结果分三档：
* ``router``  —— 真 root + netfilter 可用：完整软路由
* ``partial`` —— 有 root 但缺工具/被内核挡住：部分功能
* ``monitor`` —— 无 root：只读监控面板，且会明确告诉你缺什么
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .exec import Runner

ROOT_ONLY_PROBES = ("/data/misc/wifi", "/data/adb", "/proc/net/ip_tables_names")
AP_IFACE_HINTS = ("ap", "softap", "swlan", "wlan1", "wlan2", "rndis", "usb", "eth")
WAN_IFACE_HINTS = ("rmnet", "ccmni", "wwan", "pdp", "wlan0", "eth0")


def real_uid() -> int:
    """读 ``/proc/self/status`` 拿真实 uid（proot 下不会撒谎）。"""
    try:
        with open("/proc/self/status", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return os.getuid()


def _env_flag() -> bool:
    if os.environ.get("container", "").lower().startswith("proot"):
        return True
    return any(k.startswith("PROOT_") for k in os.environ)


def is_proot() -> bool:
    """proot 判定：环境变量标记，或"假 uid 与真 uid 不一致"。"""
    if _env_flag():
        return True
    try:
        return os.getuid() != real_uid()
    except OSError:
        return False


def _read_ifaces() -> List[str]:
    names: List[str] = []
    netdir = Path("/sys/class/net")
    if netdir.is_dir():
        try:
            names = sorted(p.name for p in netdir.iterdir())
        except OSError:
            names = []
    return names


def _default_iface_from_proc() -> Optional[str]:
    """解析 ``/proc/net/route``，找真正的默认路由。

    注意：Android 上这个文件对普通应用是 **Permission denied**，
    只有 root 能读。这也是为什么外网接口往往是"推测"出来的。

    多个默认路由同时存在时（Android 多网络并存很常见），按 metric 取最小、
    且带 RTF_UP 的那条 —— 直接取第一条会挑错网卡。
    """
    rows: list = []
    try:
        with open("/proc/net/route", "r", encoding="utf-8", errors="replace") as fh:
            next(fh, None)  # 表头
            for line in fh:
                cols = line.split()
                # Iface Destination Gateway Flags RefCnt Use Metric Mask ...
                if len(cols) < 8 or cols[1] != "00000000":
                    continue
                try:
                    flags = int(cols[3], 16)
                    metric = int(cols[6])
                except ValueError:
                    continue
                if not flags & 0x1:  # RTF_UP
                    continue
                rows.append((metric, cols[0]))
    except (OSError, StopIteration):
        return None
    if not rows:
        return None
    rows.sort()
    return rows[0][1]


def _can_bind(port: int, udp: bool = True) -> bool:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _can_open_raw_packet() -> bool:
    """能不能开 AF_PACKET 原始套接字（DHCP 直发帧需要它）。"""
    if not hasattr(socket, "AF_PACKET"):
        return False
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    except OSError:
        return False
    else:
        sock.close()
        return True


@dataclass
class Caps:
    os_name: str = "unknown"
    kernel: str = ""
    arch: str = ""
    fake_uid: int = -1
    real_uid: int = -1
    is_termux: bool = False
    is_proot: bool = False
    real_root: bool = False
    su: Optional[str] = None
    iptables: Optional[str] = None
    nft: Optional[str] = None
    tc: Optional[str] = None
    ip: Optional[str] = None
    af_packet: bool = False
    can_bind_low_ports: bool = False
    netfilter_ok: bool = False
    interfaces: List[str] = field(default_factory=list)
    default_iface: Optional[str] = None
    termux_api: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def mode(self) -> str:
        """router / partial / monitor。"""
        if not self.real_root:
            return "monitor"
        if self.netfilter_ok and (self.iptables or self.nft):
            return "router"
        return "partial"

    @property
    def mode_label(self) -> str:
        return {
            "router": "软路由模式（内核转发已可用）",
            "partial": "受限模式（有 root，但 netfilter 或工具缺失）",
            "monitor": "监控模式（无 root，只能看不能改）",
        }[self.mode]

    @property
    def can_route(self) -> bool:
        return self.mode == "router"

    def lan_iface(self, configured: str = "auto") -> Optional[str]:
        """推测内网（热点）接口名。"""
        if configured and configured != "auto":
            return configured
        for name in self.interfaces:
            if any(name.startswith(h) for h in AP_IFACE_HINTS):
                return name
        return None

    def wan_iface(self, configured: str = "auto") -> Optional[str]:
        """推测外网（数据）接口名。"""
        if configured and configured != "auto":
            return configured
        if self.default_iface:
            return self.default_iface
        for name in self.interfaces:
            if any(name.startswith(h) for h in WAN_IFACE_HINTS):
                return name
        return None

    def missing_for_router(self) -> List[str]:
        """还差什么才能变成真正的软路由。"""
        gaps: List[str] = []
        if self.is_proot:
            gaps.append(
                "当前运行在 PRoot 容器里（container=proot-distro）。PRoot 只是用户态系统调用翻译，"
                "无法操作 Android 内核的 netfilter，装了 iptables 也没用。请直接在 Termux 里运行本项目。"
            )
        if not self.real_root:
            gaps.append(
                f"没有真正的 root（真实 uid={self.real_uid}，run-as 身份是 Termux 应用）。"
                "需要 KernelSU / Magisk 提供 su，并用 tsu 或 sudo 提权运行。"
            )
        if self.real_root and not self.iptables and not self.nft:
            gaps.append("找不到 iptables 或 nft。Termux 里执行：pkg install root-repo && pkg install iptables")
        if self.real_root and not self.netfilter_ok:
            gaps.append("netfilter 不可见（/proc/net/ip_tables_names 读不到）。可能是内核模块未加载或 SELinux 限制。")
        if self.real_root and not self.tc:
            gaps.append("找不到 tc（限速功能需要）。Termux 里执行：pkg install root-repo && pkg install iproute2")
        if not self.af_packet:
            gaps.append("无法打开 AF_PACKET 原始套接字，DHCP 将退回 UDP 广播方式（多数情况仍可用）。")
        return gaps

    def suggestions(self) -> List[str]:
        """给用户的下一步命令建议。"""
        out: List[str] = []
        if self.is_termux:
            missing = []
            if not self.real_root:
                out.append("先刷 KernelSU / Magisk 拿到 root，然后在 Termux 里安装 tsu：pkg install tsu")
                out.append("拿到 root 后用 sudo trm up（或 tsu -c 'trm up'）启动")
            if not self.iptables and not self.nft:
                missing.append("iptables")
            if not self.tc:
                missing.append("iproute2")
            if missing:
                out.append("pkg install root-repo && pkg install " + " ".join(missing))
            if not self.termux_api:
                out.append("可选：pkg install termux-api，并安装 Termux:API 应用，可获得 WiFi/电池状态")
        return out

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "os": self.os_name,
            "kernel": self.kernel,
            "arch": self.arch,
            "mode": self.mode,
            "mode_label": self.mode_label,
            "real_uid": self.real_uid,
            "fake_uid": self.fake_uid,
            "is_termux": self.is_termux,
            "is_proot": self.is_proot,
            "real_root": self.real_root,
            "tools": {
                "su": self.su,
                "iptables": self.iptables,
                "nft": self.nft,
                "tc": self.tc,
                "ip": self.ip,
            },
            "netfilter_ok": self.netfilter_ok,
            "af_packet": self.af_packet,
            "can_bind_low_ports": self.can_bind_low_ports,
            "interfaces": self.interfaces,
            "default_iface": self.default_iface,
            "termux_api": self.termux_api,
            "notes": self.notes,
            "missing": self.missing_for_router(),
            "suggestions": self.suggestions(),
        }
        return data


def detect(runner: Optional[Runner] = None, deep: bool = True) -> Caps:
    """探测本机能力。``deep=True`` 时会真的去调用一次 iptables 验证。"""
    run = runner or Runner(dry_run=False, timeout=8.0)
    caps = Caps()

    caps.kernel = os.uname().release if hasattr(os, "uname") else ""
    caps.arch = os.uname().machine if hasattr(os, "uname") else ""
    caps.fake_uid = os.getuid() if hasattr(os, "getuid") else -1
    caps.real_uid = real_uid()
    caps.is_proot = is_proot()

    # 发行版名字
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                caps.os_name = line.split("=", 1)[1].strip().strip('"')
                break
    except OSError:
        pass

    caps.is_termux = bool(os.environ.get("TERMUX_VERSION")) or Path(
        "/data/data/com.termux/files/usr"
    ).exists()

    # 真 root：真实 uid 为 0 且能读只有 root 能读的路径
    if caps.real_uid == 0:
        readable = any(os.access(p, os.R_OK) for p in ROOT_ONLY_PROBES)
        caps.real_root = readable
        if not readable and caps.is_proot:
            caps.notes.append("uid 为 0 但读不到 root 专属路径 —— 典型的 proot 假 root")
        elif not readable:
            caps.notes.append("uid 为 0 但读不到 root 专属路径，可能是 SELinux 或命名空间限制")
    else:
        caps.real_root = False

    # 工具路径。proot 里的 su 是假的，明确排除，免得误导用户
    caps.su = run.which("su")
    if caps.is_proot and caps.su:
        caps.notes.append(f"检测到 {caps.su}，但在 proot 里它只是假 root，不能用于数据面")
        caps.su = None
    caps.iptables = run.first_available(["iptables", "iptables-nft", "iptables-legacy"])
    caps.nft = run.first_available(["nft"])
    caps.tc = run.first_available(["tc"])
    caps.ip = run.first_available(["ip"])

    caps.interfaces = _read_ifaces()
    if not caps.interfaces and caps.ip:
        res = run.run([caps.ip, "-o", "link", "show"], timeout=6)
        for line in res.lines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                caps.interfaces.append(parts[1].strip().split("@")[0])

    caps.default_iface = _default_iface_from_proc()
    if not caps.default_iface and caps.ip:
        # 回退：ip route show default（同样可能因权限失败）
        res = run.run([caps.ip, "route", "show", "default"], timeout=6)
        candidates: list = []
        for line in res.lines():
            cols = line.split()
            if "dev" not in cols:
                continue
            iface = cols[cols.index("dev") + 1]
            metric = 0
            if "metric" in cols:
                try:
                    metric = int(cols[cols.index("metric") + 1])
                except (ValueError, IndexError):
                    metric = 0
            candidates.append((metric, iface))
        if candidates:
            candidates.sort()
            caps.default_iface = candidates[0][1]

    caps.termux_api = [c for c in ("termux-wifi-connectioninfo", "termux-battery-status", "termux-notification") if run.which(c)]

    if deep:
        caps.netfilter_ok = _probe_netfilter(run, caps)
        caps.af_packet = _can_open_raw_packet()
        caps.can_bind_low_ports = caps.real_uid == 0 or _can_bind(67) or _can_bind(53)

    return caps


def _probe_netfilter(run: Runner, caps: Caps) -> bool:
    """确认 netfilter 真的能用，而不只是"文件存在"。"""
    if os.access("/proc/net/ip_tables_names", os.R_OK):
        return True
    if caps.nft:
        res = run.run([caps.nft, "list", "ruleset"], timeout=8)
        if res.ok:
            return True
    if caps.iptables:
        # nat 表只有 root 能看；失败就说明没有 netfilter 权限
        res = run.run([caps.iptables, "-t", "nat", "-L", "-n"], timeout=8)
        if res.ok:
            return True
        if "Permission denied" in res.text or res.code in (1, 4):
            caps.notes.append(f"{Path(caps.iptables).name} 执行失败: {res.text.splitlines()[0] if res.lines() else res.code}")
    return False


def doctor_report(caps: Caps) -> List[Tuple[str, str, str]]:
    """给 ``trm doctor`` 用的表格数据：``(项目, 值, 状态)``。"""
    ok, bad, warn = "ok", "bad", "warn"
    rows: List[Tuple[str, str, str]] = [
        ("系统", caps.os_name, ok),
        ("内核 / 架构", f"{caps.kernel} / {caps.arch}", ok),
        ("运行环境", "Termux + PRoot 容器" if caps.is_proot else ("Termux" if caps.is_termux else "普通 Linux"), warn if caps.is_proot else ok),
        ("真实 uid（/proc）", str(caps.real_uid), ok if caps.real_uid != 0 else warn),
        ("getuid() 报告", str(caps.fake_uid), warn if caps.fake_uid != caps.real_uid else ok),
        ("真 root", "是" if caps.real_root else "否", ok if caps.real_root else bad),
        ("netfilter 可用", "是" if caps.netfilter_ok else "否", ok if caps.netfilter_ok else bad),
        ("iptables", caps.iptables or "未找到", ok if caps.iptables else bad),
        ("nft", caps.nft or "未找到", ok if caps.nft else warn),
        ("tc（限速）", caps.tc or "未找到", ok if caps.tc else warn),
        ("ip 命令", caps.ip or "未找到", ok if caps.ip else warn),
        ("AF_PACKET 原始套接字", "可用" if caps.af_packet else "不可用", ok if caps.af_packet else warn),
        ("可绑定 53/67 特权端口", "是" if caps.can_bind_low_ports else "否", ok if caps.can_bind_low_ports else bad),
        ("网络接口", ", ".join(caps.interfaces) or "（不可见）", ok if caps.interfaces else warn),
        ("默认出口接口", caps.default_iface or "（未知）", ok if caps.default_iface else warn),
        ("Termux:API", ", ".join(caps.termux_api) or "未安装", ok if caps.termux_api else warn),
    ]
    rows.append(("工作模式", caps.mode_label, {"router": ok, "partial": warn, "monitor": bad}[caps.mode]))
    return rows
