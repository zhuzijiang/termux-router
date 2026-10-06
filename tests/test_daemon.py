"""守护进程的集成测试（dry-run + 临时 TRM_HOME，不碰真实系统）。

这里验证的是"整套东西接起来能不能跑"：

* dry-run 下能完整启动（数据面计划、DHCP、DNS、面板全都走一遍）
* snapshot 的字段与前端 HTML 读取的字段**必须一致**（防止 UI 与后端脱节）
* 各个动作（改配置、拦域名、备注、限速）都能正确落到配置里
* 停止后 pid 文件被清理
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trm import caps as caps_mod, config as config_mod, daemon as daemon_mod, paths, web  # noqa: E402
from trm import net as net_mod  # noqa: E402
from trm.exec import Runner  # noqa: E402

FRONTEND_KEYS = {"app", "caps", "plane", "counters", "dhcp", "dns", "clients",
                 "client_summary", "hotspot", "shaper", "phone", "web", "config", "logs"}


class DaemonTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._old_home = os.environ.get("TRM_HOME")
        os.environ["TRM_HOME"] = self.tmp.name
        paths.ensure_dirs()
        self.cfg = config_mod.Config(path=paths.config_file())
        self.cfg.set("web.host", "127.0.0.1")
        self.cfg.set("web.port", 0)          # 让内核分配端口，避免测试互相冲突
        self.cfg.set("dns.upstream", ["1.1.1.1"])
        self.cfg.ensure_token()
        self.cfg.save()
        self.daemon = daemon_mod.RouterDaemon(self.cfg, dry_run=True, log_to_file=True)

    def tearDown(self):
        try:
            self.daemon.stop()
        except Exception:
            pass
        if self._old_home is None:
            os.environ.pop("TRM_HOME", None)
        else:
            os.environ["TRM_HOME"] = self._old_home
        self.tmp.cleanup()


class TestDaemonStartup(DaemonTestCase):
    def test_start_and_stop(self):
        self.assertTrue(self.daemon.start())
        self.assertTrue(self.daemon.plane_applied)
        self.assertIsNotNone(self.daemon.web_server)
        self.assertTrue(self.daemon.web_server.running)
        self.assertIsNotNone(self.daemon.responder)
        self.assertIsNotNone(self.daemon.dns_proxy)
        self.assertTrue(paths.pid_file().exists())

        self.daemon.stop()
        self.assertFalse(paths.pid_file().exists(), "停止后必须清理 pid 文件")

    def test_dry_run_reports_simulation_not_reality(self):
        self.daemon.start()
        snap = self.daemon.snapshot()
        self.assertTrue(snap["app"]["dry_run"])
        self.assertTrue(snap["dhcp"].get("simulated"), "dry-run 下 DHCP 必须标为模拟")
        self.assertTrue(snap["dns"].get("simulated"), "dry-run 下 DNS 必须标为模拟")
        self.assertTrue(any("dry-run" in note for note in snap["caps"]["notes"]))

    def test_web_only_mode_skips_data_plane(self):
        daemon = daemon_mod.RouterDaemon(self.cfg, dry_run=True, web_only=True)
        try:
            self.assertTrue(daemon.start())
            self.assertFalse(daemon.plane_applied)
            self.assertIsNone(daemon.dhcp_server)
            self.assertIsNotNone(daemon.web_server)
        finally:
            daemon.stop()

    def test_rules_are_only_logged_in_dry_run(self):
        self.daemon.start()
        # dry-run 的 Runner 记录历史但不真正执行；iptables 不应出现在真实子进程里
        self.assertTrue(all(not cmd[0].endswith("iptables") for cmd in self.daemon.runner.history),
                        "dry-run 不允许真的调用 iptables")

    def test_logs_are_written_to_file(self):
        self.daemon.start()
        self.daemon.stop()
        log = paths.log_file().read_text(encoding="utf-8")
        self.assertIn("启动", log)
        self.assertIn("已停止", log)


class TestSnapshotContract(DaemonTestCase):
    def test_snapshot_has_all_frontend_keys(self):
        self.daemon.start()
        snap = self.daemon.snapshot()
        missing = FRONTEND_KEYS - set(snap)
        self.assertEqual(missing, set(), f"前端要用的字段后端没提供: {missing}")

    def test_frontend_keys_discovered_from_html(self):
        """直接从 HTML 里解析出前端读取的字段，与本测试的常量对照。

        这样以后有人只改前端不改后端（或反过来）会立刻失败。
        """
        html = (web.WEBUI_DIR / "index.html").read_text(encoding="utf-8")
        found = set(re.findall(r"\bd\.([a-z_]+)", html))
        self.assertTrue(FRONTEND_KEYS <= found,
                        f"HTML 里解析出的字段少了: {FRONTEND_KEYS - found}")

    def test_snapshot_json_serializable(self):
        import json

        self.daemon.start()
        json.dumps(self.daemon.snapshot(), ensure_ascii=False)

    def test_snapshot_mode_matches_caps(self):
        self.daemon.start()
        snap = self.daemon.snapshot()
        self.assertEqual(snap["app"]["mode"], snap["caps"]["mode"])

    def test_counters_report_readability(self):
        self.daemon.start()
        snap = self.daemon.snapshot()
        for direction in ("wan", "lan"):
            self.assertIn("available", snap["counters"][direction])


class TestDaemonActions(DaemonTestCase):
    def setUp(self):
        super().setUp()
        self.daemon.start()

    def test_config_set_persists(self):
        result = self.daemon.handle_action("config.set", {"key": "lan.gateway", "value": "192.168.99.1"})
        self.assertTrue(result["ok"])
        reloaded = config_mod.Config.load()
        self.assertEqual(reloaded.get("lan.gateway"), "192.168.99.1")

    def test_config_set_rejects_unknown_key(self):
        result = self.daemon.handle_action("config.set", {"key": "shell.evil", "value": "rm -rf /"})
        self.assertFalse(result["ok"])
        self.assertIn("未知配置项", result["error"])

    def test_unknown_action_is_rejected(self):
        result = self.daemon.handle_action("definitely.not.an.action", {})
        self.assertFalse(result["ok"])

    def test_dns_block_and_unblock_persist(self):
        self.assertTrue(self.daemon.handle_action("dns.block", {"domain": "ads.example.com"})["ok"])
        self.assertIn("ads.example.com", config_mod.Config.load().get("dns.blocked"))
        self.assertTrue(self.daemon.dns_proxy.blocklist.match("ads.example.com"))

        self.assertTrue(self.daemon.handle_action("dns.unblock", {"domain": "ads.example.com"})["ok"])
        self.assertNotIn("ads.example.com", config_mod.Config.load().get("dns.blocked"))
        self.assertFalse(self.daemon.dns_proxy.blocklist.match("ads.example.com"))

    def test_dns_block_rejects_empty_domain(self):
        self.assertFalse(self.daemon.handle_action("dns.block", {"domain": "   "})["ok"])

    def test_dns_cache_clear(self):
        self.assertTrue(self.daemon.handle_action("dns.cache.clear", {})["ok"])

    def test_client_name_persists_and_clears(self):
        self.daemon.handle_action("client.name", {"ip": "192.168.43.50", "name": "客厅电视"})
        self.assertEqual(config_mod.Config.load().get("client_names")["192.168.43.50"], "客厅电视")
        self.daemon.handle_action("client.name", {"ip": "192.168.43.50", "name": ""})
        self.assertNotIn("192.168.43.50", config_mod.Config.load().get("client_names") or {})

    def test_limit_records_even_without_shaper_and_says_so(self):
        """关键诚实性检查：限速没真正下发时必须明说，不能报"成功"。"""
        result = self.daemon.handle_action("client.limit", {"ip": "192.168.43.50", "down_kbps": 2048, "up_kbps": 512})
        self.assertTrue(result["ok"])
        self.assertFalse(result["applied"], "shaper 未启用时不能声称已下发")
        self.assertIn("shaper 未启用", result["message"])
        self.assertEqual(config_mod.Config.load().get("limits")["192.168.43.50"]["down_kbps"], 2048)

    def test_limit_with_shaper_enabled_applies_in_dry_run(self):
        self.cfg.set("shaper.enabled", True)
        self.daemon.cfg.set("shaper.enabled", True)
        self.daemon.caps.tc = "/system/bin/tc"
        result = self.daemon.apply_limit("192.168.43.51", 1024, 256)
        self.assertTrue(result["ok"])
        self.assertTrue(result.get("dry_run"), "dry-run 下应说明未真正执行")
        self.assertIsNotNone(self.daemon.shaper_map.get("192.168.43.51"))

    def test_unlimit_removes_record(self):
        self.daemon.apply_limit("192.168.43.52", 100, 100)
        result = self.daemon.handle_action("client.unlimit", {"ip": "192.168.43.52"})
        self.assertTrue(result["ok"])
        self.assertNotIn("192.168.43.52", config_mod.Config.load().get("limits") or {})

    def test_forget_clears_lease(self):
        import struct

        from trm import dhcpd

        header = struct.pack("!BBBBIHHIIII16s64s128s", 1, 1, 6, 0, 1, 0, 0x8000, 0, 0, 0, 0,
                             b"\xaa\xbb\xcc\xdd\xee\x01" + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128)
        request = header + dhcpd.MAGIC_COOKIE + dhcpd.encode_options({dhcpd.OPT_MSG_TYPE: bytes([dhcpd.DISCOVER])})
        self.daemon.responder.respond(request)
        lease = self.daemon.responder.leases.by_mac("aa:bb:cc:dd:ee:01")
        self.assertIsNotNone(lease)
        result = self.daemon.handle_action("client.forget", {"ip": lease.ip})
        self.assertTrue(result["ok"])
        self.assertIsNone(self.daemon.responder.leases.by_ip(lease.ip))

    def test_net_down_reports_state(self):
        result = self.daemon.handle_action("net.down", {})
        self.assertTrue(result["ok"])
        self.assertFalse(self.daemon.plane_applied)

    def test_net_up_again(self):
        self.daemon.handle_action("net.down", {})
        result = self.daemon.handle_action("net.up", {})
        self.assertTrue(result["ok"])
        self.assertTrue(self.daemon.plane_applied)

    def test_hotspot_start_without_ssid_explains(self):
        result = self.daemon.handle_action("hotspot.start", {})
        self.assertFalse(result["ok"])
        self.assertIn("ssid", (result.get("reason") or "").lower() + str(result))


class TestInterfacePreflight(DaemonTestCase):
    """接口不存在时必须拒绝下发规则。

    iptables 不校验接口名，给不存在的 ap0 下规则会"成功"但永不匹配，
    表现为"规则都在、就是不通"——第一次用 root 的人最容易卡在这里。
    这里用一个 dry-run 的 Runner 兜底，保证即使防线失效也不会真的改系统。
    """

    def _daemon_with_interfaces(self, interfaces, *, force=False, dry_run=False):
        # 关掉 DHCP/DNS：本类只测"规则下发前的接口拦截"，
        # 不能让测试真的去 bind 67/53（在真机上那会启动真实服务）
        self.cfg.set("dhcp.enabled", False)
        self.cfg.set("dns.enabled", False)
        daemon = daemon_mod.RouterDaemon(self.cfg, dry_run=dry_run, force=force)
        daemon.started_at = 1.0
        daemon.caps = caps_mod.detect(self.daemon.runner, deep=False)
        daemon.caps.real_root = True
        daemon.caps.netfilter_ok = True
        daemon.caps.interfaces = interfaces
        # 真 Runner 换成 dry-run 的：即使防线失效也不会真的改内核
        daemon.runner = Runner(dry_run=True)
        daemon.plane_ctx = net_mod.PlaneContext(lan_iface="ap0", wan_iface="rmnet_data0",
                                                backend="iptables")
        # 屏蔽 sysctl 写入（真机上会真的改 ip_forward，测试不该有这个副作用）
        patcher = mock.patch.object(net_mod, "apply_sysctl", lambda *a, **k: [])
        patcher.start()
        self.addCleanup(patcher.stop)
        return daemon

    def test_skips_when_lan_iface_missing(self):
        daemon = self._daemon_with_interfaces(["lo", "rmnet_data0"])
        daemon._bring_up_plane()
        self.assertFalse(daemon.plane_applied)
        self.assertEqual(daemon.runner.history, [], "接口不存在时不该执行任何命令")
        self.assertTrue(any("拒绝下发" in p for p in daemon.boot_problems))
        self.assertTrue(any("热点" in p for p in daemon.boot_problems), "提示要说清去开热点")

    def test_skips_when_wan_iface_missing(self):
        daemon = self._daemon_with_interfaces(["lo", "ap0"])
        daemon._bring_up_plane()
        self.assertFalse(daemon.plane_applied)
        self.assertTrue(any("外网" in p for p in daemon.boot_problems))

    def test_force_overrides_guard(self):
        daemon = self._daemon_with_interfaces(["lo", "rmnet_data0"], force=True)
        daemon._bring_up_plane()
        self.assertTrue(daemon.plane_applied, "--force 应当允许强行下发")
        self.assertTrue(len(daemon.runner.history) > 0)

    def test_proceeds_when_interfaces_exist(self):
        daemon = self._daemon_with_interfaces(["lo", "ap0", "rmnet_data0"])
        daemon._bring_up_plane()
        self.assertTrue(daemon.plane_applied)
        self.assertTrue(len(daemon.runner.history) > 0, "接口存在时应正常下发")
        self.assertEqual(daemon.boot_problems, [])

    def test_dry_run_previews_even_without_iface(self):
        """dry-run 的用途就是"让我看看全部命令"，不该被这道防线挡住。

        注意 dry-run 下命令是写进日志的（而不是走 Runner 执行），
        所以这里断言日志，不能断言 runner.history。
        """
        daemon = self._daemon_with_interfaces(["lo"], dry_run=True)
        daemon._bring_up_plane()
        self.assertTrue(daemon.plane_applied, "dry-run 下应完整预演")
        preview = [line for line in daemon.logs.all() if "[dry-run]" in line]
        self.assertTrue(preview, "dry-run 应把每条命令打进日志")
        self.assertTrue(any("MASQUERADE" in line for line in preview),
                        "预演里必须包含关键的 NAT 规则")


class TestBindFailureHints(DaemonTestCase):
    """端口被占用时要给出能照抄的处理命令。

    真机上 Android 热点自带 dnsmasq，67/53 很可能被系统占着——这是
    rooted 用户必然会遇到的情况，一句"启动失败"帮不上任何忙。
    """

    def test_dhcp_port_in_use_suggests_disabling_our_dhcp(self):
        hint = daemon_mod.bind_failure_hint("dhcp", "绑定 0.0.0.0:67 失败: [Errno 98] Address already in use")
        self.assertIn("dhcp.enabled false", hint)
        self.assertIn("trm down", hint)

    def test_dns_port_in_use_suggests_alt_port_and_hijack(self):
        hint = daemon_mod.bind_failure_hint("dns", "UDP 绑定 0.0.0.0:53 失败: [Errno 98] Address already in use")
        self.assertIn("dns.port 5353", hint)
        self.assertIn("hijack_dns true", hint)

    def test_permission_denied_gets_no_port_hint(self):
        """权限问题给"换端口"的建议是误导，必须区分开。"""
        self.assertEqual(
            daemon_mod.bind_failure_hint("dns", "绑定失败: [Errno 13] Permission denied"), "")

    def test_unknown_error_gets_no_hint(self):
        self.assertEqual(daemon_mod.bind_failure_hint("dns", "something odd"), "")


class TestDaemonStatusHelpers(DaemonTestCase):
    def test_daemon_running_false_when_no_pidfile(self):
        self.assertIsNone(daemon_mod.daemon_running())

    def test_daemon_running_detects_live_process(self):
        self.daemon.start()
        info = daemon_mod.daemon_running()
        self.assertIsNotNone(info)
        self.assertEqual(int(info["pid"]), os.getpid())
        self.daemon.stop()
        self.assertIsNone(daemon_mod.daemon_running())

    def test_stale_pidfile_is_ignored(self):
        from trm import store

        store.write_json(paths.pid_file(), {"pid": 999_999_99, "mode": "router"})
        self.assertIsNone(daemon_mod.daemon_running(), "进程不存在的 pid 文件必须视为过期")


if __name__ == "__main__":
    unittest.main(verbosity=2)
