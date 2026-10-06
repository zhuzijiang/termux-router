"""命令行界面：``trm``。

设计原则：同一个能力，命令行和网页面板走的是**同一套实现**
（面板走 HTTP → 守护进程 → 同一批函数），避免"命令行能做、面板做不到"
或者两者行为不一致这种经典毛病。

需要守护进程的命令（``status``/``clients``/``limit`` 等）通过本机
HTTP 接口访问，不直接操作内核——这样权限只集中在守护进程一处。
无需守护进程的命令（``doctor``/``rules``/``config``/``token``）纯本地执行。
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__, caps as caps_mod, config as config_mod, daemon as daemon_mod
from . import dhcpd, net, paths, shaper, store

# 终端宽度自适应，最长不超过 100 列（手机窄屏友好）
WIDTH = min(100, max(60, int(os.environ.get("COLUMNS", "80") or 80)))


# ---------------------------------------------------------------- 输出工具


def _c(text: str, code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    codes = {"dim": "\033[2m", "ok": "\033[32m", "warn": "\033[33m",
             "bad": "\033[31m", "bold": "\033[1m", "info": "\033[36m"}
    return f"{codes.get(code, '')}{text}\033[0m"


def _badge(kind: str, text: str) -> str:
    return {"ok": _c(text, "ok"), "warn": _c(text, "warn"),
            "bad": _c(text, "bad")}.get(kind, text)


def _display_width(text: str) -> int:
    """终端显示宽度：中文/全角字符占 2 列。

    直接用 len() 会让中文表格错位（"系统"是 2 个字符但占 4 列）。
    """
    import unicodedata

    width = 0
    for char in text:
        if unicodedata.east_asian_width(char) in ("W", "F"):
            width += 2
        elif unicodedata.combining(char):
            continue
        else:
            width += 1
    return width


def _kv_table(rows: List[Tuple[str, str]], indent: int = 0) -> str:
    """两列表格：按**显示宽度**对齐（中日韩字符双宽），右列可换行。"""
    if not rows:
        return ""
    pad = " " * indent
    label_width = min(28, max(_display_width(label) for label, _ in rows))
    out = []
    for label, value in rows:
        spaces = " " * max(1, label_width - _display_width(label) + 2)
        out.append(f"{pad}{label}{spaces}{value}")
    return "\n".join(out)


def _human_bytes(n: int) -> str:
    value = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _human_duration(seconds: int) -> str:
    seconds = max(0, int(seconds or 0))
    if seconds < 60:
        return f"{seconds} 秒"
    if seconds < 3600:
        return f"{seconds // 60} 分 {seconds % 60} 秒"
    hours, minutes = divmod(seconds // 60, 60)
    if hours < 24:
        return f"{hours} 时 {minutes} 分"
    return f"{hours // 24} 天 {hours % 24} 时"


def _print(message: str = "") -> None:
    print(message)


# ---------------------------------------------------------------- HTTP 客户端


class ApiError(RuntimeError):
    pass


def _api_call(cfg: config_mod.Config, method: str, path: str,
              body: Optional[Dict[str, Any]] = None, timeout: float = 20.0) -> Dict[str, Any]:
    host = str(cfg.get("web.host", "127.0.0.1"))
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"
    port = int(cfg.get("web.port", 8080))
    url = f"http://{host}:{port}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("X-TRM-Token", cfg.ensure_token())
    if data:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        try:
            payload = json.loads(detail)
            raise ApiError(payload.get("error") or detail) from exc
        except json.JSONDecodeError:
            raise ApiError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ApiError(f"连接不上守护进程（{url}）：{exc.reason}。先执行 trm up") from exc
    if not isinstance(payload, dict):
        raise ApiError("响应格式异常")
    if payload.get("ok") is False:
        raise ApiError(payload.get("error") or "操作失败")
    return payload


def _require_daemon(cfg: config_mod.Config) -> Dict[str, Any]:
    info = daemon_mod.daemon_running()
    if not info:
        raise ApiError("守护进程没有在运行。先执行：trm up --daemon（或 sudo trm up -d）")
    return info


# ---------------------------------------------------------------- 子命令实现


def cmd_doctor(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    from .exec import Runner
    caps = caps_mod.detect(Runner(dry_run=False, timeout=8.0), deep=True)
    created = False
    if not cfg.path.exists():
        paths.ensure_dirs()
        cfg.ensure_token()
        cfg.save()
        created = True

    _print(_c("termux-router 体检报告", "bold"))
    _print(_c("=" * 46, "dim"))
    rows = [(label, f"{_badge(kind, value)}") for label, value, kind in caps_mod.doctor_report(caps)]
    _print(_kv_table(rows))
    _print()

    gaps = caps.missing_for_router()
    if gaps:
        _print(_c("还差什么才能作为真路由器工作：", "warn"))
        for gap in gaps:
            _print(f"  • {gap}")
    else:
        _print(_c("内核转发所需条件全部满足。", "ok"))

    tips = caps.suggestions()
    if tips:
        _print()
        _print(_c("建议的下一步：", "info"))
        for tip in tips:
            _print(f"  $ {tip}")

    problems = config_mod.validate(cfg)
    _print()
    if created:
        _print(_c(f"已生成默认配置文件：{cfg.path}", "info"))
    if problems:
        _print(_c("配置问题：", "warn"))
        for problem in problems:
            _print(f"  • {problem}")
    else:
        _print(_c(f"配置检查通过（{cfg.path}）", "ok"))
    return 0 if caps.can_route and not problems else 1


def cmd_rules(args: argparse.Namespace) -> int:
    """打印将要下发的全部命令（不执行）。这是排查"到底改了什么"的最佳方式。"""
    cfg = config_mod.Config.load()
    from .exec import Runner
    runner = Runner(dry_run=True)
    caps = caps_mod.detect(runner, deep=True)
    if args.assume_root:
        caps.real_root = True
        caps.netfilter_ok = True
        caps.notes.append("--assume-root：按具备 root 生成规则")
    ctx = net.PlaneContext.from_config(cfg, caps, backend=args.backend)
    if ctx.backend not in ("iptables", "nft"):
        if caps.iptables or caps.nft:
            _print(_c(f"找到了 {caps.iptables or caps.nft}，但当前身份无权操作 netfilter。", "bad"))
            _print(f"  真实 uid={caps.real_uid}（getuid()={caps.fake_uid}）")
            if caps.is_proot:
                _print("  你正在 PRoot 容器里 —— proot 无法操作 Android 内核的 netfilter，"
                       "换到 Termux 原生环境并用 root 运行。")
            else:
                _print("  需要 root：用 sudo trm rules 或 tsu -c 'trm rules'")
        else:
            _print(_c("既没有 iptables 也没有 nft。", "bad"))
            _print("  Termux 里安装：pkg install root-repo && pkg install iptables")
        _print(_c("（加 --assume-root 可以查看『假设有 root 时会执行什么』）", "dim"))
        return 1

    _print(_c(f"后端: {ctx.backend}    内网 {ctx.lan_iface} → 外网 {ctx.wan_iface}", "bold"))
    _print(_c("sysctl:", "dim"))
    for key, value in net.plan_sysctl(ctx):
        _print(f"  {key} = {value}")
    _print(_c("规则:", "dim"))
    _pairs, steps = net.plan_enable(ctx)
    for step in steps:
        if step.stdin_text:
            _print(f"  # {step.note}")
            for line in step.stdin_text.rstrip().splitlines():
                _print(f"  | {line}")
        else:
            _print(f"  $ {step.display()}")
    if cfg.get("shaper.enabled"):
        _print(_c("限速:", "dim"))
        for step in shaper.plan_setup(ctx.lan_iface, default_down_kbps=int(cfg.get("shaper.default_down_kbps", 0))):
            _print(f"  $ {step.display()}")
    _print()
    _print(_c("以上命令仅供参考，trm up 会执行同样内容。", "dim"))
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    if daemon_mod.daemon_running():
        _print(_c("守护进程已经在运行。用 trm status 查看，或 trm down 先停掉。", "warn"))
        return 1
    if args.daemon:
        try:
            daemon_mod.daemonize()
        except OSError as exc:
            _print(_c(f"后台化失败（{exc}），改为前台运行", "warn"))
    cfg.save()
    daemon = daemon_mod.RouterDaemon(cfg, dry_run=args.dry_run, web_only=args.web_only,
                                     force=args.force)
    if not daemon.start():
        return 1
    if args.daemon:
        return daemon.run_forever()
    _print(_c("已在后台线程运行，Ctrl+C 停止。", "dim"))
    return daemon.run_forever()


def cmd_down(args: argparse.Namespace) -> int:
    info = daemon_mod.daemon_running()
    if not info:
        _print(_c("守护进程没有在运行。", "warn"))
        return 1
    pid = int(info["pid"])
    try:
        os.kill(pid, signal.SIGTERM)
    except PermissionError:
        # 常见情况：守护进程是 sudo 起的（属主 root），普通身份杀不掉。
        # 先尝试自动借 su 提权，不行再明确告诉用户该敲什么。
        _print(_c("没有权限停止该进程（它由 root 启动），尝试用 su 提权…", "warn"))
        from .exec import Runner

        su = Runner().which("su")
        if su:
            res = Runner(timeout=20).run([su, "-c", f"kill -TERM {pid}"])
            if not res.ok:
                _print(_c(f"自动提权失败：{res.text or res.code}", "bad"))
                _print(_c("请手动执行：sudo trm down", "bad"))
                return 1
        else:
            _print(_c("找不到 su。请手动执行：sudo trm down", "bad"))
            return 1
    except OSError as exc:
        _print(_c(f"发送信号失败: {exc}", "bad"))
        return 1
    for _ in range(60):
        if not daemon_mod.daemon_running():
            _print(_c("已停止。", "ok"))
            return 0
        time.sleep(0.2)
    _print(_c("等待超时。如果守护进程是 root 启动的，请用：sudo trm down", "warn"))
    return 1


def _load_status(cfg: config_mod.Config) -> Dict[str, Any]:
    return _api_call(cfg, "GET", "/api/status").get("data", {})


def cmd_status(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    if args.json:
        try:
            _print(json.dumps(_load_status(cfg), ensure_ascii=False, indent=2))
            return 0
        except ApiError as exc:
            _print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
            return 1
    try:
        data = _load_status(cfg)
    except ApiError as exc:
        _print(_c(str(exc), "warn"))
        from .exec import Runner
        caps = caps_mod.detect(Runner(), deep=True)
        _print()
        _print(_kv_table([("工作模式", _badge(
            {"router": "ok", "partial": "warn", "monitor": "bad"}[caps.mode], caps.mode_label))]))
        for gap in caps.missing_for_router():
            _print(f"  • {gap}")
        return 1

    app = data.get("app", {})
    caps = data.get("caps", {})
    plane = data.get("plane", {})
    mode = app.get("mode", "monitor")
    kind = {"router": "ok", "partial": "warn", "monitor": "bad"}.get(mode, "warn")

    _print(_c("termux-router 状态", "bold"))
    _print(_c("=" * 46, "dim"))
    rows = [
        ("工作模式", _badge(kind, caps.get("mode_label", mode))),
        ("运行时长", _human_duration(app.get("uptime", 0))),
        ("进程 / 版本", f"{app.get('pid')} / {app.get('version')}"),
        ("数据面", f"{plane.get('backend') or '无'}  "
                   f"{_badge('ok' if plane.get('applied') else 'bad', '已下发' if plane.get('applied') else '未下发')}"),
        ("接口", f"{plane.get('lan_iface') or '?'} → {plane.get('wan_iface') or '?'}"),
        ("ip_forward", str(plane.get("forwarding", "未知"))),
    ]
    counters = data.get("counters", {})
    wan = counters.get("wan", {})
    lan = counters.get("lan", {})
    rows.append(("外网流量", f"收 {_human_bytes(wan.get('rx', 0))} / 发 {_human_bytes(wan.get('tx', 0))}"))
    rows.append(("内网流量", f"收 {_human_bytes(lan.get('rx', 0))} / 发 {_human_bytes(lan.get('tx', 0))}"))

    dhcp = data.get("dhcp", {})
    rows.append(("DHCP", f"{_badge('ok' if dhcp.get('running') else 'bad', '运行中' if dhcp.get('running') else '未运行')}"
                         f"  地址池 {dhcp.get('pool_used', 0)}/{dhcp.get('pool_size', 0)}"))
    dns = data.get("dns", {})
    cache = dns.get("cache", {})
    rows.append(("DNS", f"{_badge('ok' if dns.get('running') else 'bad', '运行中' if dns.get('running') else '未运行')}"
                        f"  缓存 {cache.get('size', 0)}/{cache.get('capacity', 0)}"
                        f"  命中率 {round((cache.get('hit_rate') or 0) * 100)}%"))
    summary = data.get("client_summary", {})
    rows.append(("客户端", f"{summary.get('total', 0)} 台（在线 {summary.get('online', 0)}，限速 {summary.get('limited', 0)}）"))
    hotspot = data.get("hotspot", {})
    hotspot_label = {"on": ("ok", "已开启"), "off": ("", "已关闭"), "unknown": ("warn", "无法探测")}
    hk, hv = hotspot_label.get(hotspot.get("state"), ("warn", "未知"))
    rows.append(("热点", _badge(hk, hv) + f"  接口 {hotspot.get('ap_iface') or '未识别'}"))
    web_info = data.get("web", {})
    rows.append(("管理面板", f"{web_info.get('url', '')}"))
    _print(_kv_table(rows))

    problems = data.get("problems") or plane.get("problems") or []
    if problems:
        _print()
        _print(_c("问题：", "warn"))
        for problem in problems[:10]:
            _print(f"  • {problem}")
    if mode != "router":
        _print()
        _print(_c("当前不是软路由模式，原因：", "warn"))
        for gap in (caps.get("missing") or [])[:5]:
            _print(f"  • {gap}")
    return 0


def cmd_clients(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    _require_daemon(cfg)
    payload = _api_call(cfg, "GET", "/api/clients")
    clients = payload.get("data", [])
    if args.json:
        _print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if not clients:
        _print(_c("没有客户端数据。", "warn"))
        _print("设备列表需要 root 才能读取（DHCP 租约 + ARP 表 + conntrack）。")
        return 0
    header = f"{'IP':<16}{'在线':<6}{'下行':>10}{'上行':>10}  {'名称/MAC'}"
    _print(_c(header, "bold"))
    _print(_c("-" * len(header), "dim"))
    for client in clients:
        online = client.get("online")
        mark = _badge("ok", "在线") if online is True else (_badge("bad", "离线") if online is False else _badge("warn", "未知"))
        label = client.get("label") or client.get("mac") or ""
        limit = ""
        if client.get("limited"):
            limit = f"  [↓{client.get('down_kbps')}k/↑{client.get('up_kbps')}k]"
        _print(f"{client.get('ip', ''):<16}{mark:<14}{_human_bytes(client.get('down', 0)):>10}"
               f"{_human_bytes(client.get('up', 0)):>10}  {label}{limit}")
    summary = payload.get("summary", {})
    _print()
    _print(_c(f"共 {summary.get('total', 0)} 台，在线 {summary.get('online', 0)}，"
              f"状态未知 {summary.get('unknown', 0)}，限速中 {summary.get('limited', 0)}", "dim"))
    return 0


def cmd_limit(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    _require_daemon(cfg)
    result = _api_call(cfg, "POST", f"/api/clients/{args.ip}/limit",
                       {"down_kbps": args.down, "up_kbps": args.up})
    _print(result.get("message", "完成"))
    for problem in result.get("problems") or []:
        _print(_c(f"  ! {problem}", "warn"))
    return 0


def cmd_unlimit(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    _require_daemon(cfg)
    result = _api_call(cfg, "POST", f"/api/clients/{args.ip}/unlimit", {})
    _print(result.get("message", "完成"))
    return 0


def cmd_name(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    _require_daemon(cfg)
    result = _api_call(cfg, "POST", f"/api/clients/{args.ip}/name", {"name": args.name})
    _print(result.get("message", "完成"))
    return 0


def cmd_kick(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    _require_daemon(cfg)
    result = _api_call(cfg, "POST", f"/api/clients/{args.ip}/forget", {})
    _print(result.get("message", "完成"))
    return 0


def cmd_dns(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    if args.dns_action == "block":
        _require_daemon(cfg)
        _print(_api_call(cfg, "POST", "/api/dns/block", {"domain": args.domain}).get("message", "完成"))
    elif args.dns_action == "unblock":
        _require_daemon(cfg)
        _print(_api_call(cfg, "POST", "/api/dns/unblock", {"domain": args.domain}).get("message", "完成"))
    elif args.dns_action == "clear":
        _require_daemon(cfg)
        _print(_api_call(cfg, "POST", "/api/dns/cache/clear", {}).get("message", "完成"))
    elif args.dns_action == "queries":
        _require_daemon(cfg)
        payload = _api_call(cfg, "GET", f"/api/dns/queries?limit={args.limit}")
        rows = payload.get("data", [])
        if not rows:
            _print("还没有查询记录。")
            return 0
        for item in rows:
            _print(f"{item.get('action', ''):<9}{item.get('name', ''):<44}"
                   f"{item.get('type', ''):<6}{item.get('client', '')}")
    elif args.dns_action == "list":
        data = _load_status(cfg)
        bl = data.get("dns", {}).get("blocklist", {})
        _print(f"精确 {bl.get('exact', 0)} 条 / 通配 {bl.get('wildcard', 0)} 条 / 放行 {bl.get('allow', 0)} 条")
        blocked = cfg.get("dns.blocked") or []
        if blocked:
            _print(_c("手动拦截：", "dim"))
            for domain in blocked:
                _print(f"  {domain}")
        allowed = cfg.get("dns.allowed") or []
        if allowed:
            _print(_c("白名单：", "dim"))
            for domain in allowed:
                _print(f"  {domain}")
    return 0


def cmd_hotspot(args: argparse.Namespace) -> int:
    """热点开关与状态。

    刻意**不走守护进程**：这是一次性命令，脚本里（比如 bootstrap.sh）需要在
    服务启动之前就能用。面板上的热点开关才会经过守护进程。
    """
    cfg = config_mod.Config.load()
    from .exec import Runner

    runner = Runner()
    caps = caps_mod.detect(runner, deep=False)
    controller = hotspot_controller(cfg, caps, runner)

    if args.hotspot_action in ("start", "stop"):
        result = controller.start() if args.hotspot_action == "start" else controller.stop()
        if result.ok:
            _print(_c(f"{'已开启' if args.hotspot_action == 'start' else '已关闭'}热点"
                      f"（{result.command}）", "ok"))
            _print(_c("提示：面板上的热点状态最多 10 秒后刷新。", "dim"))
            return 0
        _print(_c(f"{'开启' if args.hotspot_action == 'start' else '关闭'}热点失败", "bad"))
        if result.reason:
            _print(f"  原因：{result.reason}")
        for line in controller.guidance():
            _print(f"  • {line}")
        return 1

    state = controller.status()
    _print(_kv_table([
        ("状态", {"on": _badge("ok", "已开启"), "off": "已关闭",
                  "unknown": _badge("warn", "无法探测")}.get(state.get("state"), "未知")),
        ("热点接口", str(state.get("ap_iface") or "未识别")),
        ("探测命令", str(state.get("command") or "—")),
        ("详情", str(state.get("detail") or "")),
    ]))
    for line in controller.guidance():
        _print(f"  • {line}")
    return 0


def hotspot_controller(cfg, caps, runner):
    from .hotspot import HotspotController
    return HotspotController(cfg, caps, runner)


def _known_config_keys() -> set:
    """可配置项的合法键集合（与面板 API 共用同一份规则）。"""
    return config_mod.flatten_keys()


def cmd_config(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    if args.config_action == "show":
        _print(json.dumps(cfg.to_dict(), ensure_ascii=False, indent=2))
        return 0
    if args.config_action == "get":
        value = cfg.get(args.key)
        if isinstance(value, (dict, list)):
            _print(json.dumps(value, ensure_ascii=False, indent=2))
        else:
            _print("" if value is None else str(value))
        return 0
    if args.config_action == "set":
        known = _known_config_keys()
        if args.key not in known:
            _print(_c(f"未知配置项：{args.key}", "bad"))
            _print(_c("用 trm config show 查看全部可配置项（拼错一个字母就会静默失效，所以这里直接拒绝）", "dim"))
            return 1
        value = config_mod.coerce_scalar(args.value)
        cfg.set(args.key, value)
        problems = config_mod.validate(cfg)
        cfg.save()
        _print(_c(f"{args.key} = {value!r} 已保存", "ok"))
        for problem in problems:
            _print(_c(f"  ! {problem}", "warn"))
        if args.key in daemon_mod.RESTART_REQUIRED:
            _print(_c("  该项需要重启守护进程才生效：trm down && trm up -d", "warn"))
        return 0
    if args.config_action == "path":
        _print(str(cfg.path))
        return 0
    return 1


def cmd_token(args: argparse.Namespace) -> int:
    cfg = config_mod.Config.load()
    token = cfg.ensure_token()
    cfg.save()
    host = str(cfg.get("web.host", "127.0.0.1"))
    port = int(cfg.get("web.port", 8080))
    loopback_only = host in ("127.0.0.1", "localhost", "::1")
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host

    _print(_kv_table([
        ("监听地址", f"{host}:{port}" + ("（仅本机）" if loopback_only else "（所有网卡）")),
        ("访问令牌", token),
    ]))
    _print()
    _print(_c("免密直达链接（在浏览器打开即自动登录）：", "dim"))
    _print(f"  手机本机          http://127.0.0.1:{port}/?token={token}")

    if loopback_only:
        _print(_c("  其他设备          访问不了：面板只监听本机", "warn"))
        _print(_c("                   放开：trm config set web.host 0.0.0.0", "dim"))
        _print(_c("                         trm down && trm up -d", "dim"))
    else:
        from .exec import Runner

        runner = Runner()
        cap = caps_mod.detect(runner, deep=False)
        addresses = net.local_ipv4(runner, ip_cmd=cap.ip)
        mobile_prefixes = ("rmnet", "ccmni", "wwan", "pdp", "clat")
        shown = 0
        for iface, addr in addresses:
            if addr.startswith("127."):
                continue
            if iface.startswith(mobile_prefixes):
                # 手机移动数据的 10.x 是运营商内网，别的设备连不上，必须说清楚
                tag = "移动数据，其他设备访问不到"
            elif net.is_private_ip(addr):
                tag = "局域网，其他设备可用"
            else:
                tag = "公网地址，注意风险"
            _print(f"  {iface:<16}  http://{addr}:{port}/?token={token}")
            _print(_c(f"  {'':<16}  ↑ {tag}", "dim"))
            shown += 1
        if not shown:
            _print(_c("  其他设备          读不到本机地址。手动查看：ip -o -4 addr show", "warn"))
            _print(_c("                   手机若没开 WiFi，先打开 WiFi 连到同一局域网", "dim"))

    _print()
    if loopback_only:
        _print(_c("提示：把令牌当路由器管理密码看待。", "dim"))
    else:
        _print(_c("提示：面板已在所有网卡监听，同一网络里拿到令牌的人都能改设置。", "warn"))
        _print(_c("      改回仅本机：trm config set web.host 127.0.0.1 && trm down && trm up -d", "dim"))
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    _print(f"termux-router {__version__}")
    return 0


# ---------------------------------------------------------------- 参数解析


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trm",
        description="termux-router —— 把 Android 手机变成一台可管理的软路由",
        epilog="不带参数运行会显示本帮助。建议先跑 trm doctor 看设备支持情况。",
    )
    parser.add_argument("--version", action="version", version=f"termux-router {__version__}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("doctor", help="体检：本机能不能当路由器，还差什么")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("rules", help="只打印将要下发的 iptables/nft 命令，不执行")
    p.add_argument("--assume-root", action="store_true", help="按『已具备 root』生成规则")
    p.add_argument("--backend", choices=["iptables", "nft"], default=None, help="强制指定后端")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("up", help="启动（数据面 + DHCP + DNS + 面板）")
    p.add_argument("-d", "--daemon", action="store_true", help="后台运行")
    p.add_argument("--dry-run", action="store_true", help="只打印将要执行的命令，不真的执行")
    p.add_argument("--web-only", action="store_true", help="只启动管理面板，不下发规则")
    p.add_argument("--force", action="store_true",
                   help="接口探测不到时也强行下发规则（默认会拒绝并说明原因）")
    p.set_defaults(func=cmd_up)

    p = sub.add_parser("down", help="停止守护进程并清理本项目下发的全部规则")
    p.set_defaults(func=cmd_down)

    p = sub.add_parser("status", help="查看运行状态")
    p.add_argument("--json", action="store_true", help="输出原始 JSON")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("clients", help="列出上网设备")
    p.add_argument("--json", action="store_true", help="输出原始 JSON")
    p.set_defaults(func=cmd_clients)

    p = sub.add_parser("limit", help="给某台设备限速（kbps，0 表示该方向不限）")
    p.add_argument("ip")
    p.add_argument("down", type=int, help="下行限制 kbps")
    p.add_argument("up", type=int, nargs="?", default=0, help="上行限制 kbps")
    p.set_defaults(func=cmd_limit)

    p = sub.add_parser("unlimit", help="解除限速")
    p.add_argument("ip")
    p.set_defaults(func=cmd_unlimit)

    p = sub.add_parser("name", help="给设备起个备注名")
    p.add_argument("ip")
    p.add_argument("name")
    p.set_defaults(func=cmd_name)

    p = sub.add_parser("kick", help="清除某台设备的 DHCP 租约（让它重新申请）")
    p.add_argument("ip")
    p.set_defaults(func=cmd_kick)

    p = sub.add_parser("dns", help="DNS 拦截与查询日志")
    dns_sub = p.add_subparsers(dest="dns_action", required=True)
    d = dns_sub.add_parser("block", help="拦截域名")
    d.add_argument("domain")
    d = dns_sub.add_parser("unblock", help="放行域名")
    d.add_argument("domain")
    dns_sub.add_parser("clear", help="清空 DNS 缓存")
    d = dns_sub.add_parser("queries", help="最近的查询日志")
    d.add_argument("--limit", type=int, default=40)
    dns_sub.add_parser("list", help="查看当前拦截规则")
    p.set_defaults(func=cmd_dns)

    p = sub.add_parser("hotspot", help="系统热点开关与状态")
    hs = p.add_subparsers(dest="hotspot_action", required=True)
    hs.add_parser("start")
    hs.add_parser("stop")
    hs.add_parser("status")
    p.set_defaults(func=cmd_hotspot)

    p = sub.add_parser("config", help="读写配置")
    cfg_sub = p.add_subparsers(dest="config_action", required=True)
    cfg_sub.add_parser("show", help="打印全部配置")
    cfg_sub.add_parser("path", help="打印配置文件路径")
    g = cfg_sub.add_parser("get", help="读取某一项，如 lan.subnet")
    g.add_argument("key")
    s = cfg_sub.add_parser("set", help="写入某一项")
    s.add_argument("key")
    s.add_argument("value")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("token", help="显示面板地址与访问令牌")
    p.set_defaults(func=cmd_token)

    p = sub.add_parser("version", help="显示版本")
    p.set_defaults(func=cmd_version)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except ApiError as exc:
        _print(_c(f"错误: {exc}", "bad"))
        return 1
    except KeyboardInterrupt:
        _print(_c("已中断", "dim"))
        return 130
    except ValueError as exc:
        _print(_c(f"配置错误: {exc}", "bad"))
        return 1


if __name__ == "__main__":
    sys.exit(main())
