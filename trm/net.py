"""数据面：内核转发 + NAT + MSS 钳制。

这里是"高性能"的真正所在。Python 不参与任何数据包转发——它只负责把
iptables/nftables 规则下发到内核，之后**每个数据包都在内核里转发**，
所以吞吐取决于内核 netfilter 而不是本项目的语言。

支持两个后端：

* ``iptables`` —— 兼容性最好，绝大多数 Android 内核都带 ip_tables/xtables
* ``nftables``  —— 新内核（Android 14+ 只保留 nft 的机型）需要它

两者都通过**纯函数**生成命令/脚本，因此可以在没有 root 的机器上
完整单元测试规则内容（见 ``tests/test_rules.py``）。

关键工程细节：

* 所有规则都放进自建链 ``TRM_NAT`` / ``TRM_FWD`` / ``TRM_MSS``，
  退出时能干净删除，不会留垃圾规则污染用户的防火墙。
* 幂等：先 ``-D`` 删可能存在的跳转规则再 ``-A`` 添加，不依赖条件判断，
  于是整份计划可以是一串纯粹的命令。
* ``mss_clamp`` 是手机热点的经典救命项：运营商 MTU 小于 1500 时，
  不钳制 MSS 会出现"能连上、能 ping、但打不开网页"的 PMTU 黑洞。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .exec import Runner

CHAIN_NAT = "TRM_NAT"
CHAIN_FWD = "TRM_FWD"
CHAIN_MSS = "TRM_MSS"
NFT_TABLE = "trm"

SYSCTL_FORWARD = "net.ipv4.ip_forward"
SYSCTL_SEND_REDIRECTS = "net.ipv4.conf.all.send_redirects"


@dataclass
class Step:
    """一条要下发的动作：要么是 argv，要么是把 stdin 脚本喂给某命令。"""

    argv: Optional[List[str]] = None
    stdin_text: Optional[str] = None
    note: str = ""
    ignore_error: bool = True

    def display(self) -> str:
        if self.argv:
            return " ".join(self.argv)
        return f"<script -> {self.note or 'stdin'}>"


@dataclass
class PlaneContext:
    """下发规则所需的全部上下文。"""

    lan_iface: str
    wan_iface: str
    lan_subnet: str = "192.168.43.0/24"
    backend: str = "iptables"
    masquerade: bool = True
    mss_clamp: bool = True
    icmp_redirect_off: bool = True
    hijack_dns: bool = False
    dns_port: int = 53

    @classmethod
    def from_config(cls, cfg, caps, backend: Optional[str] = None) -> "PlaneContext":
        lan = caps.lan_iface(str(cfg.get("lan.iface", "auto"))) or "ap0"
        wan = caps.wan_iface(str(cfg.get("wan.iface", "auto"))) or "rmnet_data0"
        return cls(
            lan_iface=lan,
            wan_iface=wan,
            lan_subnet=str(cfg.get("lan.subnet", "192.168.43.0/24")),
            backend=backend or select_backend(caps) or "iptables",
            masquerade=bool(cfg.get("netfilter.masquerade", True)),
            mss_clamp=bool(cfg.get("netfilter.mss_clamp", True)),
            icmp_redirect_off=bool(cfg.get("netfilter.icmp_redirect_off", True)),
            hijack_dns=bool(cfg.get("netfilter.hijack_dns", False)),
            dns_port=int(cfg.get("dns.port", 53)),
        )


def select_backend(caps) -> Optional[str]:
    """按"哪个真能用"选后端，而不是按"哪个文件存在"。"""
    ipt_ok = bool(caps.iptables) and (caps.netfilter_ok or caps.real_root)
    nft_ok = bool(caps.nft) and (caps.netfilter_ok or caps.real_root)
    if ipt_ok:
        return "iptables"
    if nft_ok:
        return "nft"
    return None


# --------------------------------------------------------------------- sysctl


def sysctl_path(key: str, root: str = "/proc/sys") -> Path:
    return Path(root) / key.replace(".", "/")


def apply_sysctl(pairs: List[Tuple[str, str]], root: str = "/proc/sys") -> List[str]:
    """直接写 ``/proc/sys``，不需要 sysctl 二进制（Android 上常常没有）。

    返回失败信息列表。``root`` 可注入，方便单元测试。
    """
    failures: List[str] = []
    for key, value in pairs:
        path = sysctl_path(key, root)
        try:
            path.write_text(str(value), encoding="utf-8")
        except OSError as exc:
            failures.append(f"{key}={value} 写入失败: {exc}")
    return failures


def plan_sysctl(ctx: PlaneContext) -> List[Tuple[str, str]]:
    pairs = [(SYSCTL_FORWARD, "1")]
    if ctx.icmp_redirect_off:
        pairs.append((SYSCTL_SEND_REDIRECTS, "0"))
        if ctx.lan_iface:
            pairs.append((f"net.ipv4.conf.{ctx.lan_iface}.send_redirects", "0"))
    return pairs


def plan_sysctl_off(ctx: PlaneContext) -> List[Tuple[str, str]]:
    """关闭时把转发关掉。注意：这会一并影响用户自己其它依赖转发的功能。"""
    pairs: List[Tuple[str, str]] = [(SYSCTL_FORWARD, "0")]
    if ctx.icmp_redirect_off:
        pairs.append((SYSCTL_SEND_REDIRECTS, "1"))
    return pairs


# ------------------------------------------------------------------ iptables


def iptables_enable_plan(ctx: PlaneContext, ipt: str = "iptables") -> List[Step]:
    steps: List[Step] = []

    # --- NAT / MASQUERADE ---
    steps.append(Step(argv=[ipt, "-t", "nat", "-N", CHAIN_NAT], ignore_error=True, note="建 NAT 链"))
    steps.append(Step(argv=[ipt, "-t", "nat", "-F", CHAIN_NAT]))
    steps.append(Step(argv=[ipt, "-t", "nat", "-D", "POSTROUTING", "-o", ctx.wan_iface, "-j", CHAIN_NAT]))
    steps.append(Step(argv=[ipt, "-t", "nat", "-A", "POSTROUTING", "-o", ctx.wan_iface, "-j", CHAIN_NAT]))
    if ctx.masquerade:
        steps.append(Step(argv=[ipt, "-t", "nat", "-A", CHAIN_NAT, "-j", "MASQUERADE"], note="源地址伪装"))

    # --- 转发放行 ---
    steps.append(Step(argv=[ipt, "-N", CHAIN_FWD], ignore_error=True, note="建转发链"))
    steps.append(Step(argv=[ipt, "-F", CHAIN_FWD]))
    steps.append(Step(argv=[ipt, "-D", "FORWARD", "-j", CHAIN_FWD]))
    steps.append(Step(argv=[ipt, "-A", "FORWARD", "-j", CHAIN_FWD]))
    steps.append(Step(argv=[ipt, "-A", CHAIN_FWD, "-i", ctx.lan_iface, "-o", ctx.wan_iface, "-j", "ACCEPT"], note="内网→外网"))
    steps.append(
        Step(
            argv=[
                ipt, "-A", CHAIN_FWD,
                "-i", ctx.wan_iface, "-o", ctx.lan_iface,
                "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
                "-j", "ACCEPT",
            ],
            note="外网→内网（仅已建立连接）",
        )
    )
    steps.append(Step(argv=[ipt, "-A", CHAIN_FWD, "-i", ctx.lan_iface, "-o", ctx.lan_iface, "-j", "ACCEPT"], note="内网互通"))

    # --- MSS 钳制 ---
    if ctx.mss_clamp:
        steps.append(Step(argv=[ipt, "-t", "mangle", "-N", CHAIN_MSS], ignore_error=True, note="建 MSS 链"))
        steps.append(Step(argv=[ipt, "-t", "mangle", "-F", CHAIN_MSS]))
        steps.append(Step(argv=[ipt, "-t", "mangle", "-D", "FORWARD", "-j", CHAIN_MSS]))
        steps.append(Step(argv=[ipt, "-t", "mangle", "-A", "FORWARD", "-j", CHAIN_MSS]))
        steps.append(
            Step(
                argv=[
                    ipt, "-t", "mangle", "-A", CHAIN_MSS,
                    "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                    "-j", "TCPMSS", "--clamp-mss-to-pmtu",
                ],
                note="修复 PMTU 黑洞",
            )
        )

    # --- DNS 劫持到本机 ---
    if ctx.hijack_dns:
        for proto in ("udp", "tcp"):
            steps.append(
                Step(
                    argv=[ipt, "-t", "nat", "-D", "PREROUTING", "-i", ctx.lan_iface, "-p", proto, "--dport", "53",
                          "-j", "REDIRECT", "--to-ports", str(ctx.dns_port)],
                )
            )
            steps.append(
                Step(
                    argv=[ipt, "-t", "nat", "-A", "PREROUTING", "-i", ctx.lan_iface, "-p", proto, "--dport", "53",
                          "-j", "REDIRECT", "--to-ports", str(ctx.dns_port)],
                    note=f"劫持 {proto}/53 到本机 DNS",
                )
            )

    return steps


def iptables_disable_plan(ctx: PlaneContext, ipt: str = "iptables") -> List[Step]:
    steps: List[Step] = [
        Step(argv=[ipt, "-t", "nat", "-D", "POSTROUTING", "-o", ctx.wan_iface, "-j", CHAIN_NAT]),
        Step(argv=[ipt, "-t", "nat", "-F", CHAIN_NAT]),
        Step(argv=[ipt, "-t", "nat", "-X", CHAIN_NAT]),
        Step(argv=[ipt, "-D", "FORWARD", "-j", CHAIN_FWD]),
        Step(argv=[ipt, "-F", CHAIN_FWD]),
        Step(argv=[ipt, "-X", CHAIN_FWD]),
        Step(argv=[ipt, "-t", "mangle", "-D", "FORWARD", "-j", CHAIN_MSS]),
        Step(argv=[ipt, "-t", "mangle", "-F", CHAIN_MSS]),
        Step(argv=[ipt, "-t", "mangle", "-X", CHAIN_MSS]),
    ]
    for proto in ("udp", "tcp"):
        steps.append(
            Step(argv=[ipt, "-t", "nat", "-D", "PREROUTING", "-i", ctx.lan_iface, "-p", proto, "--dport", "53",
                      "-j", "REDIRECT", "--to-ports", str(ctx.dns_port)])
        )
    return steps


def iptables_status_plan(ctx: PlaneContext, ipt: str = "iptables") -> List[Step]:
    return [
        Step(argv=[ipt, "-t", "nat", "-S", CHAIN_NAT]),
        Step(argv=[ipt, "-S", CHAIN_FWD]),
        Step(argv=[ipt, "-t", "mangle", "-S", CHAIN_MSS]),
        Step(argv=[ipt, "-t", "nat", "-L", CHAIN_NAT, "-v", "-n", "-x"]),
    ]


# -------------------------------------------------------------------- nftables


def nft_script(ctx: PlaneContext) -> str:
    """生成一份完整的 nft 脚本（``nft -f -`` 读 stdin）。

    用"整表重建"而不是增量 add，是刻意的：
    nft 的增量规则很容易重复堆积，整表重建保证幂等且原子。
    """
    lines: List[str] = [
        f"table ip {NFT_TABLE} {{",
        "  chain postrouting {",
        "    type nat hook postrouting priority srcnat; policy accept;",
    ]
    if ctx.masquerade:
        lines.append(f'    oifname "{ctx.wan_iface}" masquerade')
    lines += [
        "  }",
        "  chain prerouting {",
        "    type nat hook prerouting priority dstnat; policy accept;",
    ]
    if ctx.hijack_dns:
        lines.append(f'    iifname "{ctx.lan_iface}" udp dport 53 redirect to :{ctx.dns_port}')
        lines.append(f'    iifname "{ctx.lan_iface}" tcp dport 53 redirect to :{ctx.dns_port}')
    lines += [
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter; policy accept;",
        f'    iifname "{ctx.lan_iface}" oifname "{ctx.wan_iface}" accept',
        f'    iifname "{ctx.wan_iface}" oifname "{ctx.lan_iface}" ct state established,related accept',
        f'    iifname "{ctx.lan_iface}" oifname "{ctx.lan_iface}" accept',
        "  }",
    ]
    if ctx.mss_clamp:
        lines += [
            "  chain mss {",
            "    type filter hook forward priority mangle; policy accept;",
            "    tcp flags syn,rst syn tcp option maxseg size set rt mtu",
            "  }",
        ]
    lines.append("}")
    return "\n".join(lines) + "\n"


def nft_enable_plan(ctx: PlaneContext, nft: str = "nft") -> List[Step]:
    return [
        Step(argv=[nft, "delete", "table", "ip", NFT_TABLE], note="先删旧表保证幂等"),
        Step(argv=[nft, "-f", "-"], stdin_text=nft_script(ctx), note="重建 trm 表"),
    ]


def nft_disable_plan(ctx: PlaneContext, nft: str = "nft") -> List[Step]:
    return [Step(argv=[nft, "delete", "table", "ip", NFT_TABLE])]


def nft_status_plan(ctx: PlaneContext, nft: str = "nft") -> List[Step]:
    return [Step(argv=[nft, "list", "table", "ip", NFT_TABLE])]


# ----------------------------------------------------------------- 统一入口


def plan_enable(ctx: PlaneContext) -> Tuple[List[Tuple[str, str]], List[Step]]:
    """返回 ``(sysctl 项, 规则步骤)``。"""
    if ctx.backend == "nft":
        return plan_sysctl(ctx), nft_enable_plan(ctx)
    return plan_sysctl(ctx), iptables_enable_plan(ctx)


def plan_disable(ctx: PlaneContext) -> Tuple[List[Tuple[str, str]], List[Step]]:
    if ctx.backend == "nft":
        return plan_sysctl_off(ctx), nft_disable_plan(ctx)
    return plan_sysctl_off(ctx), iptables_disable_plan(ctx)


def plan_status(ctx: PlaneContext) -> List[Step]:
    if ctx.backend == "nft":
        return nft_status_plan(ctx)
    return iptables_status_plan(ctx)


def apply(runner: Runner, steps: List[Step]) -> List[str]:
    """执行步骤，返回失败描述列表（``ignore_error`` 的失败也会被记录）。"""
    problems: List[str] = []
    for step in steps:
        if not step.argv:
            continue
        res = runner.run(step.argv, input_text=step.stdin_text)
        if not res.ok:
            problems.append(f"{' '.join(step.argv)} -> {res.code}: {res.text.splitlines()[0] if res.lines() else ''}")
    return problems


# ------------------------------------------------------------------- 计数器


def interface_counters(iface: str, root: str = "/sys/class/net") -> Tuple[int, int]:
    """返回 ``(rx_bytes, tx_bytes)``，读不到就返回 ``(0, 0)``。"""
    base = Path(root) / iface / "statistics"

    def _read(name: str) -> int:
        try:
            return int((base / name).read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return 0

    return _read("rx_bytes"), _read("tx_bytes")


def counters_readable(iface: str, root: str = "/sys/class/net") -> bool:
    """接口计数器是否可读。

    区分"流量真的是 0"和"根本读不到"很重要——把后者显示成 0 是在骗用户。
    在 PRoot 容器里 /sys/class/net 通常被屏蔽，会返回 False。
    """
    if not iface:
        return False
    return os.access(Path(root) / iface / "statistics" / "rx_bytes", os.R_OK)


def parse_conntrack_line(line: str) -> Optional[Dict[str, Any]]:
    """解析 ``/proc/net/nf_conntrack`` 的一行。

    原始方向与回复方向各有一组 ``src= dst= sport= dport= bytes=``，
    这里分别记为 ``*`` 与 ``reply_*``。
    """
    cols = line.split()
    if len(cols) < 6:
        return None
    entry: Dict[str, Any] = {"proto": cols[2] if len(cols) > 2 else "", "raw": line.strip()}
    pairs = [c for c in cols if "=" in c]
    seen_src = 0
    for pair in pairs:
        key, _, value = pair.partition("=")
        if key in ("src", "dst", "sport", "dport", "bytes", "packets"):
            prefix = "" if seen_src == 0 or key not in ("src", "dst", "sport", "dport", "bytes", "packets") else "reply_"
            if key == "src" and "src" in entry:
                seen_src = 1
                prefix = "reply_"
            if key in entry and prefix == "":
                prefix = "reply_"
            name = prefix + key
            if key in ("bytes", "packets", "sport", "dport"):
                try:
                    entry[name] = int(value)
                except ValueError:
                    entry[name] = 0
            else:
                entry[name] = value
        elif key == "ESTABLISHED" or (key.isupper() and key not in entry):
            entry.setdefault("state", key)
    # 状态字段其实是无 key 的单字（如 ESTABLISHED）
    for tok in cols[4:8]:
        if tok.isupper() and tok.isalpha():
            entry["state"] = tok
            break
    return entry if "src" in entry else None


def read_conntrack(limit: int = 4000, path: str = "/proc/net/nf_conntrack") -> List[Dict[str, Any]]:
    """读取连接跟踪表。读不到（无 root / 未加载模块）返回空列表。"""
    entries: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= limit:
                    break
                parsed = parse_conntrack_line(line)
                if parsed:
                    entries.append(parsed)
    except OSError:
        return []
    return entries


def aggregate_lan_traffic(entries: List[Dict[str, Any]], lan_iface: str = "") -> Dict[str, Dict[str, int]]:
    """按内网 IP 汇总上/下行字节数。

    方向判定（最容易搞反的地方）：

    * **上行**：原始方向的 ``src`` 是内网客户端，字节数 = ``bytes``
    * **下行**：回复方向的 **``dst``** 才是内网客户端（回复的源是远端服务器），
      字节数 = ``reply_bytes``

    早期版本这里误用了 ``reply_src``，结果下行永远是 0 —— 单元测试抓到了。
    """
    stats: Dict[str, Dict[str, int]] = {}
    for e in entries:
        candidates = (
            (str(e.get("src", "")), int(e.get("bytes", 0) or 0), "up"),
            (str(e.get("reply_dst", "")), int(e.get("reply_bytes", 0) or 0), "down"),
        )
        for ip, delta, direction in candidates:
            if not ip or not _is_private(ip):
                continue
            node = stats.setdefault(ip, {"up": 0, "down": 0, "conns": 0})
            node[direction] += delta
            if direction == "up":
                node["conns"] += 1
    return stats


def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 100 and 64 <= b <= 127:  # CGNAT，运营商热点常用
        return True
    return False
