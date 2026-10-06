"""限速：tc HTB（下行）+ ingress police（上行）。

关于"上行"的一个诚实说明
------------------------
标准 Linux 路由器的上行限速需要 ``ifb`` 中间设备（把内网入口流量重定向到
一个虚拟网卡上整形）。``ifb`` 需要 ``modprobe ifb``，而 Android 的 GKI 内核
通常**不带** ifb 模块，加载会失败。

所以这里采用不需要任何内核模块的方案：

* **下行**：在 LAN 接口的 egress 上建 HTB 树，按目的 IP 分类。
  整形（缓存+排队），效果精确 —— 这是唯一真正重要的方向（下载占带宽）。
* **上行**：在 LAN 接口的 ingress 上挂 ``police`` 过滤器，按源 IP 限速。
  police 的行为是**超限丢包**而不是排队整形，所以上行的时延表现会比理想
  整形差一些，但对"限制某个设备偷偷上传"这个真实需求完全够用，
  而且不需要 ifb。两者都失败时本项目不会假装成功。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .net import Step

ROOT_HANDLE = "1:"
INGRESS_HANDLE = "ffff:"
DEFAULT_CLASS_MINOR = 30
DEFAULT_CLASS_ID = f"{ROOT_HANDLE}{DEFAULT_CLASS_MINOR}"
UNLIMITED_BIT = "1000mbit"
MINOR_BASE = 0x100
PRIO_BASE = 10


@dataclass
class ShaperMap:
    """IP -> (classid minor, filter prio) 的稳定映射。

    必须在多次运行之间保持一致，否则无法删除上一次下的规则。
    """

    data: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def alloc(self, ip: str) -> Dict[str, int]:
        if ip in self.data:
            return self.data[ip]
        used_minor = {int(v.get("minor", 0)) for v in self.data.values()}
        used_prio = {int(v.get("prio", 0)) for v in self.data.values()}
        minor = MINOR_BASE
        while minor in used_minor or minor == DEFAULT_CLASS_MINOR:
            minor += 1
        prio = PRIO_BASE
        while prio in used_prio:
            prio += 1
        self.data[ip] = {"minor": minor, "prio": prio}
        return self.data[ip]

    def get(self, ip: str) -> Optional[Dict[str, int]]:
        return self.data.get(ip)

    def remove(self, ip: str) -> Optional[Dict[str, int]]:
        return self.data.pop(ip, None)

    def to_dict(self) -> Dict[str, Dict[str, int]]:
        return dict(self.data)

    @classmethod
    def from_dict(cls, raw: Optional[Dict[str, Any]]) -> "ShaperMap":
        clean: Dict[str, Dict[str, int]] = {}
        for ip, val in (raw or {}).items():
            if isinstance(val, dict) and "minor" in val and "prio" in val:
                clean[str(ip)] = {"minor": int(val["minor"]), "prio": int(val["prio"])}
        return cls(clean)


def _kbps(value: int) -> str:
    return f"{max(1, int(value))}kbit"


def plan_setup(iface: str, tc: str = "tc", default_down_kbps: int = 0) -> List[Step]:
    """建立 HTB 根 + 默认类 + ingress qdisc。"""
    default_rate = _kbps(default_down_kbps) if default_down_kbps > 0 else UNLIMITED_BIT
    return [
        Step(
            argv=[tc, "qdisc", "replace", "dev", iface, "root", "handle", ROOT_HANDLE, "htb",
                  "default", str(DEFAULT_CLASS_MINOR)],
            note="建 HTB 根队列",
        ),
        Step(
            argv=[tc, "class", "replace", "dev", iface, "parent", ROOT_HANDLE, "classid",
                  DEFAULT_CLASS_ID, "htb", "rate", default_rate, "ceil", default_rate],
            note="默认类（未单独限速的设备）",
        ),
        Step(
            argv=[tc, "qdisc", "replace", "dev", iface, "handle", INGRESS_HANDLE, "ingress"],
            note="建 ingress 队列（上行限速用）",
        ),
    ]


def plan_limit(ip: str, down_kbps: int, up_kbps: int, iface: str, entry: Dict[str, int],
               tc: str = "tc") -> List[Step]:
    """对单个客户端下发限速。``0`` 表示该方向不限。"""
    minor = int(entry["minor"])
    prio = int(entry["prio"])
    classid = f"{ROOT_HANDLE}{minor}"
    steps: List[Step] = []

    # 下行：LAN 出口整形
    rate = _kbps(down_kbps) if down_kbps > 0 else UNLIMITED_BIT
    steps.append(
        Step(
            argv=[tc, "class", "replace", "dev", iface, "parent", ROOT_HANDLE, "classid", classid,
                  "htb", "rate", rate, "ceil", rate, "burst", "32k"],
            note=f"下行 {down_kbps or '不限'} kbps",
        )
    )
    steps.append(
        Step(
            argv=[tc, "filter", "replace", "dev", iface, "protocol", "ip", "parent", ROOT_HANDLE,
                  "prio", str(prio), "u32", "match", "ip", "dst", f"{ip}/32", "flowid", classid],
            note=f"目的 {ip} 归入 {classid}",
        )
    )

    # 上行：ingress police
    if up_kbps > 0:
        steps.append(
            Step(
                argv=[tc, "filter", "replace", "dev", iface, "protocol", "ip", "parent", INGRESS_HANDLE,
                      "prio", str(prio), "u32", "match", "ip", "src", f"{ip}/32",
                      "police", "rate", _kbps(up_kbps), "burst", "64k", "drop", "flowid", ":1"],
                note=f"上行 {up_kbps} kbps（超限丢弃）",
            )
        )
    else:
        steps.append(
            Step(
                argv=[tc, "filter", "del", "dev", iface, "protocol", "ip", "parent", INGRESS_HANDLE,
                      "prio", str(prio)],
                note="清除该设备的上行限制",
            )
        )
    return steps


def plan_unlimit(ip: str, iface: str, entry: Dict[str, int], tc: str = "tc") -> List[Step]:
    """完全解除某客户端的限速（连类一起删）。"""
    minor = int(entry["minor"])
    prio = int(entry["prio"])
    return [
        Step(argv=[tc, "filter", "del", "dev", iface, "protocol", "ip", "parent", ROOT_HANDLE, "prio", str(prio)]),
        Step(argv=[tc, "filter", "del", "dev", iface, "protocol", "ip", "parent", INGRESS_HANDLE, "prio", str(prio)]),
        Step(argv=[tc, "class", "del", "dev", iface, "classid", f"{ROOT_HANDLE}{minor}"]),
    ]


def plan_teardown(iface: str, tc: str = "tc") -> List[Step]:
    return [
        Step(argv=[tc, "qdisc", "del", "dev", iface, "root"]),
        Step(argv=[tc, "qdisc", "del", "dev", iface, "handle", INGRESS_HANDLE, "ingress"]),
    ]


def plan_status(iface: str, tc: str = "tc") -> List[Step]:
    return [
        Step(argv=[tc, "qdisc", "show", "dev", iface]),
        Step(argv=[tc, "class", "show", "dev", iface]),
        Step(argv=[tc, "filter", "show", "dev", iface]),
    ]


def parse_class_stats(text: str) -> Dict[str, Dict[str, int]]:
    """解析 ``tc -s class show`` 输出，取每个 classid 的字节数。

    真实输出形如::

        class htb 1:256 parent 1: prio 0 rate 2048Kbit ceil 2048Kbit burst 32Kb
         Sent 55555 bytes 78 pkt (dropped 3, overlimits 0 requeues 0) backlog 0b 0p

    注意每一行 "class ..." 都必须**重置** current，否则多个 class 的统计会
    全部记到第一个 class 上（这个 bug 也是单元测试抓出来的）。
    """
    stats: Dict[str, Dict[str, int]] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("class "):
            parts = line.split()
            current = None
            for i, tok in enumerate(parts):
                if tok == "classid" and i + 1 < len(parts):
                    current = parts[i + 1]
                    break
            if current is None and len(parts) >= 3:
                current = parts[2]
            stats.setdefault(current or "", {"bytes": 0, "packets": 0, "dropped": 0})
        elif current and line.startswith("Sent"):
            match = re.search(
                r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt(?:\s*\(dropped\s+(\d+))?", line)
            if match:
                stats[current]["bytes"] = int(match.group(1))
                stats[current]["packets"] = int(match.group(2))
                stats[current]["dropped"] = int(match.group(3) or 0)
    return stats
