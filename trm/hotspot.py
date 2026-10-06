"""系统热点（SoftAP）控制。

为什么把 AP 层交给 Android 系统的热点，而不是自己跑 hostapd：

* 手机 WiFi 芯片的 AP 模式由厂商驱动 + Android framework 共同管理，
  hostapd 在绝大多数手机上**根本无法启动**（nl80211 接口被 framework 占用、
  驱动不支持），教程里能跑通的多是极老机型。
* 系统热点已经实现了 AP + DHCP + NAPT 全套，稳定且省电。
* 我们的价值在**它做不到的部分**：按设备限速、DNS 拦截、细粒度统计、
  统一管理面板。

所以本模块的职责是"可控地调用系统热点"，并且**老实承认命令因 ROM 而异**：
Android 各版本/各家 ROM 的 ``cmd wifi start-softap`` 参数不同，
所以这里用**命令模板**（可在配置里改），而不是硬编码一条命令假装通用。
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

# 按成功率排序的默认启动模板。{ssid} {passphrase} 会被替换。
DEFAULT_START_TEMPLATES: List[str] = [
    "cmd wifi start-softap {ssid} wpa2 {passphrase}",
    "cmd wifi start-softap {ssid} {passphrase}",
    "cmd wifi start-softap {ssid} open",
]
DEFAULT_STOP_TEMPLATES: List[str] = [
    "cmd wifi stop-softap",
]
DEFAULT_STATUS_TEMPLATES: List[str] = [
    "cmd wifi status",
    "dumpsys wifi",
]


@dataclass
class HotspotResult:
    ok: bool
    action: str
    command: str = ""
    output: str = ""
    reason: str = ""
    tried: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok, "action": self.action, "command": self.command,
            "output": self.output, "reason": self.reason, "tried": self.tried or [],
        }


class HotspotController:
    """热点控制。所有命令都经 :class:`~trm.exec.Runner`，因此支持 dry-run。"""

    def __init__(self, cfg, caps, runner, log: Optional[Callable[[str], None]] = None) -> None:
        self.cfg = cfg
        self.caps = caps
        self.runner = runner
        self.log = log or (lambda _m: None)

    # ---------------------------------------------------------------- 工具
    def _tmp(self, template: str) -> str:
        ssid = str(self.cfg.get("hotspot.ssid") or "")
        passphrase = str(self.cfg.get("hotspot.passphrase") or "")
        return template.format(ssid=ssid, passphrase=passphrase,
                               band=self.cfg.get("hotspot.band", "2.4"))

    def _configured(self, key: str, defaults: List[str]) -> List[str]:
        custom = str(self.cfg.get(f"hotspot.{key}") or "").strip()
        if custom:
            return [custom]
        return defaults

    def _run_first_ok(self, templates: List[str], action: str) -> HotspotResult:
        tried: List[str] = []
        for template in templates:
            command = self._tmp(template)
            tried.append(command)
            parts = shlex.split(command)
            if not parts:
                continue
            res = self.runner.run(parts, timeout=15)
            if res.ok:
                self.log(f"热点 {action} 成功: {command}")
                return HotspotResult(ok=True, action=action, command=command,
                                     output=res.text, tried=tried)
            output = res.text
            self.log(f"热点 {action} 失败({res.code}): {command} :: {output[:160]}")
        return HotspotResult(
            ok=False, action=action, tried=tried,
            reason=self._why_failed(action),
        )

    def _why_failed(self, action: str) -> str:
        if self.caps.is_proot:
            return ("当前在 PRoot 容器里，无法访问 Android 的 cmd/dumpsys。"
                    "请在 Termux 原生环境（不是 proot-distro）里运行。")
        if not self.caps.real_root:
            return ("启动/停止系统热点需要 root：Android 只把 TETHER_PRIVILEGED 权限"
                    "授予系统应用，普通应用（含 Termux）无法调用。"
                    "可选做法：① 用 root 运行本项目；② 手动在系统设置里开关热点，"
                    "本项目仍然可以管理限速、DNS 与统计。")
        return (f"{action} 命令全部失败。不同 ROM 的热点命令不同，"
                "请在配置里设置 hotspot.start_cmd / hotspot.stop_cmd，"
                "例如：cmd wifi start-softap MySSID wpa2 MyPassword")

    # ---------------------------------------------------------------- 动作
    def start(self) -> HotspotResult:
        ssid = str(self.cfg.get("hotspot.ssid") or "")
        if not ssid:
            return HotspotResult(ok=False, action="start",
                                 reason="还没配置热点名称（hotspot.ssid）")
        return self._run_first_ok(self._configured("start_cmd", DEFAULT_START_TEMPLATES), "start")

    def stop(self) -> HotspotResult:
        return self._run_first_ok(self._configured("stop_cmd", DEFAULT_STOP_TEMPLATES), "stop")

    def status(self) -> Dict[str, Any]:
        """探测热点状态。探测不到就返回 ``unknown``，绝不猜。"""
        templates = self._configured("status_cmd", DEFAULT_STATUS_TEMPLATES)
        for template in templates:
            command = self._tmp(template)
            parts = shlex.split(command)
            if not parts:
                continue
            if not self.runner.which(parts[0]):
                continue
            res = self.runner.run(parts, timeout=12)
            if not res.ok:
                continue
            text = res.text
            state = _interpret_hotspot(text)
            return {
                "state": state,
                "command": command,
                "ap_iface": self.ap_iface(),
                "detail": _extract_ssid(text),
            }
        return {
            "state": "unknown",
            "command": "",
            "ap_iface": self.ap_iface(),
            "detail": "无法探测（需要 root 才能执行 cmd/dumpsys）" if not self.caps.real_root else "命令无输出",
        }

    def ap_iface(self) -> Optional[str]:
        """猜测当前热点接口名。"""
        return self.caps.lan_iface(str(self.cfg.get("lan.iface", "auto")))

    def guidance(self) -> List[str]:
        """无 root 时给用户的操作指引。"""
        steps = [
            "系统设置 → 个人热点 / 便携式热点 → 打开。建议把热点网段设为与本项目配置一致。",
            "Redmi/MIUI 里路径通常是：设置 → 连接与共享 → 便携式热点。",
        ]
        if self.cfg.get("hotspot.ssid"):
            steps.insert(0, f"热点名称设为 {self.cfg.get('hotspot.ssid')}（与配置一致）")
        if not self.caps.real_root:
            steps.append("想要一键开关热点：root 后用 sudo trm hotspot start。")
        return steps


def _interpret_hotspot(text: str) -> str:
    low = text.lower()
    if "softap" not in low and "ap interface" not in low and "tethering" not in low:
        return "unknown"
    off_markers = ("softap is stopped", "softap: stopped", "not started", "state: disabled",
                   "ap disabled", "softap disabled")
    on_markers = ("softap is started", "softap: started", "ap enabled", "state: enabled",
                  "softap enabled", "tethering on")
    for marker in on_markers:
        if marker in low:
            return "on"
    for marker in off_markers:
        if marker in low:
            return "off"
    return "unknown"


def _extract_ssid(text: str) -> str:
    for line in text.splitlines():
        if "ssid" in line.lower():
            return line.strip()[:120]
    return ""


def wifi_info(runner) -> Dict[str, Any]:
    """通过 Termux:API 读取当前 WiFi 连接（上行）信息。

    这是**无 root 也能用**的少数真实能力之一，所以监控模式下它是主角：
    至少能告诉你手机自己连的是哪个 WiFi、信号多强、速率多少。
    """
    if not runner.which("termux-wifi-connectioninfo"):
        return {"available": False,
                "hint": "pkg install termux-api 并安装 Termux:API 应用后可用"}
    res = runner.run(["termux-wifi-connectioninfo"], timeout=10)
    if not res.ok:
        return {"available": False, "error": res.text or f"退出码 {res.code}"}
    try:
        raw = json.loads(res.text)
    except json.JSONDecodeError:
        return {"available": False, "error": "返回值不是 JSON"}
    return {
        "available": True,
        "ssid": raw.get("ssid"),
        "bssid": raw.get("bssid"),
        "ip": raw.get("ip"),
        "link_speed_mbps": raw.get("link_speed_mbps"),
        "rssi": raw.get("rssi"),
        "frequency_mhz": raw.get("frequency_mhz"),
    }


def battery_info(runner) -> Dict[str, Any]:
    """读取电池状态，用来提示"当路由器很耗电"。"""
    if not runner.which("termux-battery-status"):
        return {"available": False}
    res = runner.run(["termux-battery-status"], timeout=10)
    if not res.ok:
        return {"available": False, "error": res.text}
    try:
        raw = json.loads(res.text)
    except json.JSONDecodeError:
        return {"available": False, "error": "返回值不是 JSON"}
    return {
        "available": True,
        "percentage": raw.get("percentage"),
        "plugged": raw.get("plugged"),
        "temperature": raw.get("temperature"),
        "health": raw.get("health"),
    }
