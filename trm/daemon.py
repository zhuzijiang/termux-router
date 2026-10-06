"""守护进程：把数据面、DHCP、DNS、热点、管理面板串成一个整体。

设计上明确区分两种工作模式，并且**在监控模式下也照常提供面板**：

* ``router``：root + netfilter 可用 → 下发 NAT、起 DHCP/DNS、可按设备限速
* ``monitor``：无 root → 不起任何需要特权的东西，只提供只读面板：
  能力清单、接口流量、热点状态、WiFi/电池（走 Termux:API）

这不是"降级凑数"：在一个没 root 的手机上，一个能告诉你"还差什么、
为什么不能开 NAT"的面板，比一个假装在工作的面板有用得多。

所有子进程调用都经过 :class:`~trm.exec.Runner`，所以 ``dry_run=True``
可以把整套动作变成"只打印命令"，用于在没有 root 的机器上端到端验证。
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import __version__, caps as caps_mod, clients as clients_mod, config as config_mod
from . import dhcpd, dnsd, hotspot, net, paths, shaper, store, web
from .exec import Runner

LOG_RING_SIZE = 400
COUNTER_CACHE_TTL = 1.5
SLOW_INFO_CACHE_TTL = 12.0

# 这些配置改动必须重启进程才生效
RESTART_REQUIRED = {
    "web.host", "web.port", "dns.port", "web.token",
    "lan.subnet", "lan.gateway", "lan.pool_start", "lan.pool_end",
}


class RouterDaemon:
    def __init__(self, cfg: config_mod.Config, dry_run: bool = False,
                 log_to_file: bool = True, web_only: bool = False) -> None:
        self.cfg = cfg
        self.dry_run = dry_run
        self.log_to_file = log_to_file
        self.web_only = web_only
        self.logs = store.RingBuffer(LOG_RING_SIZE)
        self.started_at = 0.0
        self.runner = Runner(dry_run=dry_run, timeout=15.0, log=self._trace)
        self.caps: Optional[caps_mod.Caps] = None
        self.plane_ctx: Optional[net.PlaneContext] = None
        self.responder: Optional[dhcpd.DHCPResponder] = None
        self.dhcp_server: Optional[dhcpd.DHCPServer] = None
        self.dns_proxy: Optional[dnsd.DNSProxy] = None
        self.hotspot_ctl: Optional[hotspot.HotspotController] = None
        self.web_server: Optional[web.WebServer] = None
        self.shaper_map = shaper.ShaperMap.from_dict(
            store.read_json(paths.state_dir() / "shaper.json", default={}) or {}
        )
        self.plane_applied = False
        self.plane_problems: List[str] = []
        self.sysctl_failures: List[str] = []
        self.boot_problems: List[str] = []
        self._stop = threading.Event()
        self._maintenance: Optional[threading.Thread] = None
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()
        # dry-run 下"假装在跑"的服务，用于让前端如实显示"这是模拟"
        self._simulated: set = set()

    # ------------------------------------------------------------------ 日志
    def _log(self, message: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {message}"
        self.logs.add(line)
        if self.log_to_file:
            try:
                store.append_line(paths.log_file(), f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}")
            except OSError:
                pass
        if not self.log_to_file:
            print(line, flush=True)

    def _trace(self, message: str) -> None:
        """命令级日志（sh -x 风格），只在 debug 时进面板。"""
        if str(self.cfg.get("log_level", "info")) == "debug":
            self._log(message)

    def _cached(self, key: str, ttl: float, producer: Callable[[], Any]) -> Any:
        now = time.time()
        hit = self._cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
        value = producer()
        self._cache[key] = (now + ttl, value)
        return value

    # ---------------------------------------------------------------- 生命周期
    def start(self) -> bool:
        paths.ensure_dirs()
        self.started_at = time.time()
        self._log(f"termux-router {__version__} 启动中{'（dry-run 模拟）' if self.dry_run else ''}")

        problems = config_mod.validate(self.cfg)
        for problem in problems:
            self._log(f"配置问题: {problem}")
        self.boot_problems = list(problems)

        self.caps = caps_mod.detect(self.runner, deep=not self.dry_run)
        if self.dry_run:
            # dry-run 是"假设具备 root"的模拟执行，必须显式说明，避免误判
            self.caps.real_root = True
            self.caps.netfilter_ok = True
            self.caps.af_packet = True
            self.caps.can_bind_low_ports = True
            self.caps.notes.append("dry-run：能力按『具备 root』假设，只打印命令不执行")

        self.hotspot_ctl = hotspot.HotspotController(self.cfg, self.caps, self.runner, self._log)
        self.plane_ctx = net.PlaneContext.from_config(self.cfg, self.caps)
        self._log(f"工作模式: {self.caps.mode_label}")

        if self.web_only:
            self._log("仅面板模式：不下发任何规则，不启动 DHCP/DNS")
        elif self.caps.can_route or self.dry_run:
            self._bring_up_plane()
        else:
            for gap in self.caps.missing_for_router():
                self._log(f"跳过数据面: {gap}")
            self._log("已进入监控模式：面板与只读监控可用，转发/NAT/DHCP/DNS 未启动")

        self._start_web()
        self._write_pidfile()
        self._maintenance = threading.Thread(target=self._maintenance_loop, name="maint", daemon=True)
        self._maintenance.start()
        self._install_signal_handlers()
        self._log("启动完成")
        return True

    def _bring_up_plane(self) -> None:
        assert self.plane_ctx is not None
        ctx = self.plane_ctx
        if not ctx.lan_iface or not ctx.wan_iface:
            self._log(f"接口未识别（内网={ctx.lan_iface} 外网={ctx.wan_iface}），"
                      "请在配置里显式指定 lan.iface / wan.iface")
        else:
            # 猜出来的接口名如果根本不存在，规则会下发失败。宁可在启动时就喊出来。
            known = self.caps.interfaces if self.caps else []
            for role, iface in (("内网", ctx.lan_iface), ("外网", ctx.wan_iface)):
                if known and iface not in known:
                    self._log(f"警告：{role}接口 {iface} 不在当前接口列表中"
                              f"（实际有：{', '.join(known) or '无'}）。"
                              f"{'热点可能还没开——先开启系统热点，然后 trm down && trm up' if role == '内网' else '请检查 wan.iface 配置'}")
        pairs, steps = net.plan_enable(ctx)
        self.sysctl_failures = net.apply_sysctl(pairs) if not self.dry_run else []
        if self.dry_run:
            for step in steps:
                self._log(f"[dry-run] {step.display()}")
        problems = net.apply(self.runner, steps) if not self.dry_run else []
        self.plane_problems = problems + self.sysctl_failures
        self.plane_applied = True
        self._log(f"数据面已下发（后端={ctx.backend}，接口 {ctx.lan_iface} → {ctx.wan_iface}）")
        for problem in self.plane_problems:
            self._log(f"规则下发有失败项: {problem}")

        if self.cfg.get("shaper.enabled"):
            self._setup_shaper()

        events = store.RingBuffer(200)
        self.responder = dhcpd.build_responder(self.cfg, events=events)
        if self.cfg.get("dhcp.enabled"):
            server = dhcpd.DHCPServer(self.responder, iface=ctx.lan_iface, log=self._log)
            if self.dry_run:
                self._log(f"[dry-run] 启动 DHCP 服务器 0.0.0.0:67 接口={ctx.lan_iface}")
                self.dhcp_server = server
                self._simulated.add("dhcp")
            elif server.open():
                server.start()
                self.dhcp_server = server
            else:
                self._log(f"DHCP 启动失败: {server.last_error}")

        if self.cfg.get("dns.enabled"):
            proxy = dnsd.build_proxy(self.cfg, log=self._log)
            for domain in self.cfg.get("dns.blocked") or []:
                proxy.blocklist.add(str(domain))
            for domain in self.cfg.get("dns.allowed") or []:
                proxy.blocklist.allow_domain(str(domain))
            if self.dry_run:
                self._log(f"[dry-run] 启动 DNS 服务 0.0.0.0:{proxy.port} 上游={','.join(proxy.upstream)}")
                self.dns_proxy = proxy
                self._simulated.add("dns")
            elif proxy.start():
                self.dns_proxy = proxy
            else:
                self._log(f"DNS 启动失败: {proxy.last_error}")

    def _setup_shaper(self) -> None:
        assert self.plane_ctx is not None
        iface = self.plane_ctx.lan_iface
        if not self.caps or not self.caps.tc:
            self._log("限速已启用但找不到 tc 命令，跳过")
            return
        steps = shaper.plan_setup(iface, tc=self.caps.tc,
                                  default_down_kbps=int(self.cfg.get("shaper.default_down_kbps", 0)))
        if self.dry_run:
            for step in steps:
                self._log(f"[dry-run] {step.display()}")
        else:
            for problem in net.apply(self.runner, steps):
                self._log(f"限速初始化失败: {problem}")
        # 重新应用已保存的每设备限速
        for ip, limit in (self.cfg.get("limits") or {}).items():
            if isinstance(limit, dict):
                self.apply_limit(ip, int(limit.get("down_kbps", 0) or 0), int(limit.get("up_kbps", 0) or 0),
                                 persist=False, quiet=True)

    def stop(self) -> None:
        self._log("正在停止…")
        self._stop.set()
        if self.dhcp_server:
            self.dhcp_server.stop()
            if self.responder:
                self.responder.leases.save(force=True)
        if self.dns_proxy:
            self.dns_proxy.stop()
        if self.web_server:
            self.web_server.stop()
        if self.plane_applied and self.plane_ctx and not self.dry_run:
            removed = net.plan_disable(self.plane_ctx)
            pairs, steps = removed
            for problem in net.apply(self.runner, steps):
                self._log(f"清理规则失败: {problem}")
            if self.cfg.get("shaper.enabled") and self.caps and self.caps.tc:
                for problem in net.apply(self.runner, shaper.plan_teardown(self.plane_ctx.lan_iface,
                                                                          tc=self.caps.tc)):
                    self._log(f"清理限速失败: {problem}")
        self._remove_pidfile()
        self._log("已停止")

    def run_forever(self) -> int:
        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
        return 0

    def _install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, lambda *_a: self._stop.set())
            except (ValueError, OSError):
                pass

    # ---------------------------------------------------------------- pid 文件
    def _write_pidfile(self) -> None:
        try:
            store.write_json(paths.pid_file(), {
                "pid": os.getpid(), "started": self.started_at,
                "dry_run": self.dry_run, "mode": self.caps.mode if self.caps else "unknown",
                "version": __version__,
            })
        except OSError as exc:
            self._log(f"写 pid 文件失败: {exc}")

    def _remove_pidfile(self) -> None:
        try:
            paths.pid_file().unlink(missing_ok=True)
        except OSError:
            pass

    def _start_web(self) -> None:
        cfg_web = self.cfg.web
        server = web.WebServer(
            host=str(cfg_web.get("host", "127.0.0.1")),
            port=int(cfg_web.get("port", 8080)),
            token=self.cfg.ensure_token(),
            state_provider=self.snapshot,
            action_handler=self.handle_action,
            log=self._log,
            dry_run=self.dry_run,
        )
        if server.start():
            self.web_server = server
            self.cfg.save()
        else:
            self._log(f"面板启动失败: {server.last_error}")

    # ------------------------------------------------------------ 维护线程
    def _maintenance_loop(self) -> None:
        while not self._stop.wait(10.0):
            try:
                if self.responder:
                    self.responder.leases.sweep()
                    self.responder.leases.save()
            except Exception as exc:  # 维护线程绝不能死
                self._log(f"维护任务异常: {exc!r}")

    # ---------------------------------------------------------------- 状态
    def snapshot(self) -> Dict[str, Any]:
        assert self.caps is not None
        ctx = self.plane_ctx
        lan_iface = ctx.lan_iface if ctx else None
        wan_iface = ctx.wan_iface if ctx else None

        wan_counters = self._cached("cnt_wan", COUNTER_CACHE_TTL,
                                    lambda: net.interface_counters(wan_iface) if wan_iface else (0, 0))
        lan_counters = self._cached("cnt_lan", COUNTER_CACHE_TTL,
                                    lambda: net.interface_counters(lan_iface) if lan_iface else (0, 0))

        client_list = clients_mod.collect_from_system(self.cfg, responder=self.responder,
                                                     runner=self.runner, caps=self.caps)
        summary = clients_mod.summarize(client_list)

        dhcp_snap: Dict[str, Any] = {"running": False, "pool_size": 0, "pool_used": 0}
        if self.responder:
            dhcp_snap.update(self.responder.snapshot())
        if self.dhcp_server:
            dhcp_snap.update(self.dhcp_server.snapshot())
        if "dhcp" in self._simulated:
            dhcp_snap["running"] = True
            dhcp_snap["simulated"] = True

        dns_snap: Dict[str, Any] = {"running": False, "stats": {}, "cache": {}, "blocklist": {}, "queries": []}
        if self.dns_proxy:
            dns_snap.update(self.dns_proxy.snapshot())
            dns_snap["queries"] = self.dns_proxy.query_log.latest(120)
        if "dns" in self._simulated:
            dns_snap["running"] = True
            dns_snap["simulated"] = True

        hotspot_snap = self._cached("hotspot", SLOW_INFO_CACHE_TTL,
                                    lambda: self._hotspot_state())
        phone = self._cached("phone", SLOW_INFO_CACHE_TTL, lambda: {
            "wifi": hotspot.wifi_info(self.runner),
            "battery": hotspot.battery_info(self.runner),
        })

        forwarding = "未知"
        try:
            forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8").strip()
        except OSError:
            pass

        return {
            "app": {
                "name": "termux-router",
                "version": __version__,
                "pid": os.getpid(),
                "uptime": int(time.time() - self.started_at) if self.started_at else 0,
                "dry_run": self.dry_run,
                "mode": self.caps.mode,
            },
            "caps": self.caps.to_dict(),
            "plane": {
                "applied": self.plane_applied,
                "backend": ctx.backend if ctx else None,
                "lan_iface": lan_iface,
                "wan_iface": wan_iface,
                # Android 上 /proc/net/route 对普通应用不可读，外网接口常常只能靠命名推测。
                # 明确告诉用户"这是猜的"，而不是让他以为一定正确。
                "wan_iface_guessed": bool(
                    ctx and str(self.cfg.get("wan.iface", "auto")) == "auto"
                    and not (self.caps and self.caps.default_iface)
                ),
                "lan_iface_guessed": bool(
                    ctx and str(self.cfg.get("lan.iface", "auto")) == "auto"
                    and self.caps and not any(
                        name == lan_iface for name in self.caps.interfaces
                    )
                ),
                "forwarding": forwarding,
                "problems": list(self.plane_problems),
                "sysctl_failures": list(self.sysctl_failures),
            },
            "counters": {
                "wan": {"rx": wan_counters[0], "tx": wan_counters[1],
                        "available": net.counters_readable(wan_iface), "iface": wan_iface},
                "lan": {"rx": lan_counters[0], "tx": lan_counters[1],
                        "available": net.counters_readable(lan_iface), "iface": lan_iface},
            },
            "dhcp": dhcp_snap,
            "dns": dns_snap,
            "clients": [c.to_dict() for c in client_list],
            "client_summary": summary,
            "hotspot": hotspot_snap,
            "shaper": {
                "enabled": bool(self.cfg.get("shaper.enabled")),
                "iface": lan_iface,
                "default_down_kbps": int(self.cfg.get("shaper.default_down_kbps", 0)),
                "default_up_kbps": int(self.cfg.get("shaper.default_up_kbps", 0)),
                "limits": dict(self.cfg.get("limits") or {}),
            },
            "phone": phone,
            "web": self.web_server.snapshot() if self.web_server else {"running": False},
            "config": self.cfg.to_dict(),
            "problems": list(self.boot_problems),
            "logs": self.logs.latest(200),
        }

    def _hotspot_state(self) -> Dict[str, Any]:
        assert self.hotspot_ctl is not None
        state = self.hotspot_ctl.status()
        state["guidance"] = self.hotspot_ctl.guidance()
        return state

    # ---------------------------------------------------------------- 动作
    def handle_action(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        handler = {
            "net.up": self._action_net_up,
            "net.down": self._action_net_down,
            "client.limit": self._action_client_limit,
            "client.unlimit": self._action_client_unlimit,
            "client.name": self._action_client_name,
            "client.forget": self._action_client_forget,
            "dns.block": self._action_dns_block,
            "dns.unblock": self._action_dns_unblock,
            "dns.cache.clear": self._action_dns_clear,
            "hotspot.start": self._action_hotspot_start,
            "hotspot.stop": self._action_hotspot_stop,
            "config.set": self._action_config_set,
            "daemon.stop": self._action_daemon_stop,
        }.get(action)
        if handler is None:
            return {"ok": False, "error": f"未知动作 {action}"}
        try:
            with self._lock:
                return handler(payload)
        except Exception as exc:
            self._log(f"动作 {action} 异常: {exc!r}")
            return {"ok": False, "error": repr(exc)}

    def _action_net_up(self, _payload: Dict[str, Any]) -> Dict[str, Any]:
        if not (self.caps and (self.caps.can_route or self.dry_run)):
            return {"ok": False, "error": "当前没有 root 或 netfilter 不可用，无法下发 NAT 规则"}
        self._bring_up_plane()
        return {"ok": True, "message": "数据面已下发"}

    def _action_net_down(self, _payload: Dict[str, Any]) -> Dict[str, Any]:
        if not (self.plane_ctx and self.plane_applied):
            return {"ok": False, "error": "数据面本来就没有下发"}
        # 即使 dry-run 也要更新模拟状态，否则预览会自相矛盾
        self.plane_applied = False
        if self.dry_run:
            self._log("[dry-run] 清理数据面规则（仅模拟）")
            return {"ok": True, "message": "dry-run：未真正清理", "dry_run": True}
        pairs, steps = net.plan_disable(self.plane_ctx)
        problems = net.apply(self.runner, steps)
        self._log("数据面规则已清除")
        return {"ok": not problems, "message": "规则已清除" if not problems else "部分规则清理失败",
                "problems": problems}

    def _action_client_limit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ip = str(payload.get("ip", ""))
        if not ip:
            return {"ok": False, "error": "缺少 ip"}
        down = int(payload.get("down_kbps", 0) or 0)
        up = int(payload.get("up_kbps", 0) or 0)
        return self.apply_limit(ip, down, up)

    def apply_limit(self, ip: str, down_kbps: int, up_kbps: int,
                    persist: bool = True, quiet: bool = False) -> Dict[str, Any]:
        limits = dict(self.cfg.get("limits") or {})
        limits[ip] = {"down_kbps": max(0, down_kbps), "up_kbps": max(0, up_kbps)}
        self.cfg.set("limits", limits)
        if persist:
            self.cfg.save()
        if not self.cfg.get("shaper.enabled"):
            return {"ok": True, "message": "已记录限速，但 shaper 未启用（需要 root 且配置 shaper.enabled=true 才会真正生效）",
                    "applied": False}
        if not (self.caps and self.caps.tc and self.plane_ctx):
            return {"ok": True, "message": "已记录限速，但缺少 tc 或接口信息，未下发", "applied": False}
        entry = self.shaper_map.alloc(ip)
        steps = shaper.plan_limit(ip, down_kbps, up_kbps, self.plane_ctx.lan_iface, entry, tc=self.caps.tc)
        if self.dry_run:
            for step in steps:
                self._log(f"[dry-run] {step.display()}")
            return {"ok": True, "message": "dry-run：未真正下发", "dry_run": True}
        problems = net.apply(self.runner, steps)
        self._persist_shaper_map()
        if not quiet:
            self._log(f"限速 {ip}: ↓{down_kbps} / ↑{up_kbps} kbps" + ("（有失败项）" if problems else ""))
        return {"ok": not problems, "message": "限速已下发" if not problems else "部分规则下发失败",
                "applied": True, "problems": problems}

    def _action_client_unlimit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ip = str(payload.get("ip", ""))
        limits = dict(self.cfg.get("limits") or {})
        limits.pop(ip, None)
        self.cfg.set("limits", limits)
        self.cfg.save()
        entry = self.shaper_map.get(ip)
        problems: List[str] = []
        if entry and self.caps and self.caps.tc and self.plane_ctx and not self.dry_run:
            problems = net.apply(self.runner, shaper.plan_unlimit(ip, self.plane_ctx.lan_iface,
                                                                 entry, tc=self.caps.tc))
            self.shaper_map.remove(ip)
            self._persist_shaper_map()
        return {"ok": not problems, "message": f"{ip} 的限速已解除",
                "problems": problems}

    def _action_client_name(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ip = str(payload.get("ip", ""))
        name = str(payload.get("name", "")).strip()
        names = dict(self.cfg.get("client_names") or {})
        if name:
            names[ip] = name
        else:
            names.pop(ip, None)
        self.cfg.set("client_names", names)
        self.cfg.save()
        return {"ok": True, "message": f"已保存备注：{name or '（清空）'}"}

    def _action_client_forget(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        ip = str(payload.get("ip", ""))
        removed = False
        if self.responder:
            removed = self.responder.leases.remove_ip(ip)
            self.responder.leases.save(force=True)
        if self.caps and self.caps.real_root and self.plane_ctx and not self.dry_run:
            self.runner.run([self.caps.ip or "ip", "neigh", "del", ip,
                             "dev", self.plane_ctx.lan_iface])
        return {"ok": True, "message": f"已清除 {ip} 的租约" if removed else f"{ip} 没有活跃租约"}

    def _action_dns_block(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        domain = dnsd.DomainBlocklist.normalize(str(payload.get("domain", "")))
        if not domain:
            return {"ok": False, "error": "域名无效"}
        if self.dns_proxy:
            self.dns_proxy.blocklist.add(domain)
        blocked = list(self.cfg.get("dns.blocked") or [])
        if domain not in blocked:
            blocked.append(domain)
        self.cfg.set("dns.blocked", blocked)
        self.cfg.save()
        return {"ok": True, "message": f"已拦截 {domain}"}

    def _action_dns_unblock(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        domain = dnsd.DomainBlocklist.normalize(str(payload.get("domain", "")))
        if self.dns_proxy:
            bl = self.dns_proxy.blocklist
            bl.exact.discard(domain)
            bl.wildcard.discard(domain)
            bl.allow_domain(domain)
        blocked = [d for d in (self.cfg.get("dns.blocked") or []) if str(d) != domain]
        allowed = list(self.cfg.get("dns.allowed") or [])
        if domain and domain not in allowed:
            allowed.append(domain)
        self.cfg.set("dns.blocked", blocked)
        self.cfg.set("dns.allowed", allowed)
        self.cfg.save()
        return {"ok": True, "message": f"已放行 {domain}"}

    def _action_dns_clear(self, _payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.dns_proxy:
            return {"ok": False, "error": "DNS 服务未运行"}
        count = self.dns_proxy.cache.clear()
        return {"ok": True, "message": f"已清空 {count} 条缓存"}

    def _action_hotspot_start(self, _payload: Dict[str, Any]) -> Dict[str, Any]:
        assert self.hotspot_ctl is not None
        result = self.hotspot_ctl.start()
        self._cache.pop("hotspot", None)
        return result.to_dict()

    def _action_hotspot_stop(self, _payload: Dict[str, Any]) -> Dict[str, Any]:
        assert self.hotspot_ctl is not None
        result = self.hotspot_ctl.stop()
        self._cache.pop("hotspot", None)
        return result.to_dict()

    def _action_config_set(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        key = str(payload.get("key", ""))
        if not key:
            return {"ok": False, "error": "缺少 key"}
        if key not in config_mod.flatten_keys():
            return {"ok": False, "error": f"未知配置项 {key}"}
        value = payload.get("value")
        self.cfg.set(key, value)
        problems = config_mod.validate(self.cfg)
        self.cfg.save()
        note = "需要重启服务才能生效" if key in RESTART_REQUIRED else "即时生效"
        return {"ok": True, "message": f"{key} 已保存（{note}）",
                "problems": problems}

    def _action_daemon_stop(self, _payload: Dict[str, Any]) -> Dict[str, Any]:
        # 先回响应再退出，否则前端只会看到连接被重置
        threading.Timer(0.4, self._stop.set).start()
        return {"ok": True, "message": "服务正在停止"}

    def _persist_shaper_map(self) -> None:
        try:
            store.write_json(paths.state_dir() / "shaper.json", self.shaper_map.to_dict())
        except OSError as exc:
            self._log(f"保存限速映射失败: {exc}")


def read_pidfile() -> Optional[Dict[str, Any]]:
    data = store.read_json(paths.pid_file(), default=None)
    return data if isinstance(data, dict) else None


def daemon_running() -> Optional[Dict[str, Any]]:
    """返回正在运行的守护进程信息；没在跑返回 None。"""
    info = read_pidfile()
    if not info:
        return None
    pid = int(info.get("pid", 0) or 0)
    if pid <= 0:
        return None
    if not Path(f"/proc/{pid}").exists():
        return None
    return info


def daemonize() -> None:
    """标准双 fork 后台化。用于 ``trm up --daemon``。"""
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    os.chdir("/")
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        try:
            os.dup2(devnull, fd)
        except OSError:
            pass
