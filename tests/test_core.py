"""核心工具与能力探测的单元测试。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trm import caps, config, iputil, store  # noqa: E402
from trm.exec import Runner  # noqa: E402


class TestIpUtil(unittest.TestCase):
    def test_roundtrip(self):
        for ip in ("0.0.0.0", "192.168.43.1", "255.255.255.255", "10.20.30.40"):
            self.assertEqual(iputil.int_to_ip(iputil.ip_to_int(ip)), ip)

    def test_invalid_input(self):
        for bad in ("256.1.1.1", "1.2.3", "a.b.c.d", "1.2.3.4.5", ""):
            with self.assertRaises(ValueError):
                iputil.ip_to_int(bad)
        self.assertFalse(iputil.is_valid_ip("1.2.3"))
        self.assertTrue(iputil.is_valid_ip("1.2.3.4"))

    def test_cidr_math(self):
        net, prefix = iputil.parse_cidr("192.168.43.7/24")
        self.assertEqual(prefix, 24)
        self.assertEqual(iputil.int_to_ip(net), "192.168.43.0")
        self.assertEqual(iputil.netmask_str(24), "255.255.255.0")
        self.assertEqual(iputil.netmask_str(0), "0.0.0.0")
        self.assertEqual(iputil.netmask_str(32), "255.255.255.255")
        self.assertEqual(iputil.int_to_ip(iputil.broadcast_address("192.168.43.0/24")), "192.168.43.255")
        self.assertTrue(iputil.in_cidr("192.168.43.99", "192.168.43.0/24"))
        self.assertFalse(iputil.in_cidr("192.168.44.1", "192.168.43.0/24"))

    def test_wildcard(self):
        self.assertEqual(iputil.wildcard_str(24), "0.0.0.255")

    def test_ip_range(self):
        got = list(iputil.ip_range("10.0.0.1", "10.0.0.3"))
        self.assertEqual(got, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        with self.assertRaises(ValueError):
            list(iputil.ip_range("10.0.0.5", "10.0.0.1"))

    def test_mac_helpers(self):
        self.assertEqual(iputil.normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(iputil.bytes_to_mac(iputil.mac_to_bytes("aa:bb:cc:dd:ee:ff")), "aa:bb:cc:dd:ee:ff")
        for bad in ("aa:bb:cc:dd:ee", "zz:bb:cc:dd:ee:ff", "aabbccddeeff"):
            with self.assertRaises(ValueError):
                iputil.normalize_mac(bad)

    def test_is_multicast_or_broadcast(self):
        self.assertTrue(iputil.is_multicast_or_broadcast("255.255.255.255"))
        self.assertTrue(iputil.is_multicast_or_broadcast("224.0.0.1"))
        self.assertFalse(iputil.is_multicast_or_broadcast("8.8.8.8"))


class TestConfig(unittest.TestCase):
    def test_deep_merge_does_not_mutate_inputs(self):
        base = {"a": {"b": 1, "c": 2}, "d": 3}
        merged = config.deep_merge(base, {"a": {"c": 9}})
        self.assertEqual(merged["a"], {"b": 1, "c": 9})
        self.assertEqual(base["a"]["c"], 2, "原字典不能被改动")

    def test_defaults_are_complete(self):
        cfg = config.Config()
        self.assertEqual(cfg.get("lan.gateway"), "192.168.43.1")
        self.assertEqual(cfg.get("dns.port"), 53)
        self.assertEqual(cfg.get("dns.blocked"), [])

    def test_dotted_get_set_unset(self):
        cfg = config.Config()
        cfg.set("lan.gateway", "10.0.0.1")
        self.assertEqual(cfg.get("lan.gateway"), "10.0.0.1")
        cfg.set("brand.new.deep", "x")
        self.assertEqual(cfg.get("brand.new.deep"), "x")
        self.assertTrue(cfg.unset("brand.new.deep"))
        self.assertIsNone(cfg.get("brand.new.deep"))
        self.assertEqual(cfg.get("nope.nope", "fallback"), "fallback")

    def test_coerce_scalar(self):
        self.assertIs(config.coerce_scalar("true"), True)
        self.assertIs(config.coerce_scalar("off"), False)
        self.assertEqual(config.coerce_scalar("42"), 42)
        self.assertEqual(config.coerce_scalar("1.5"), 1.5)
        self.assertEqual(config.coerce_scalar("[1,2]"), [1, 2])
        self.assertEqual(config.coerce_scalar('{"a":1}'), {"a": 1})
        self.assertEqual(config.coerce_scalar("1.1.1.1"), "1.1.1.1")

    def test_save_load_roundtrip_and_permissions(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            path = Path(tmp.name) / "config.json"
            cfg = config.Config(path=path)
            cfg.set("lan.gateway", "192.168.9.1")
            cfg.ensure_token()
            cfg.save()
            self.assertTrue(path.exists())
            if os.name == "posix":
                self.assertEqual(oct(path.stat().st_mode)[-3:], "600", "配置含令牌，权限须为 600")
            reloaded = config.Config.load(path)
            self.assertEqual(reloaded.get("lan.gateway"), "192.168.9.1")
            self.assertTrue(reloaded.get("web.token"))
        finally:
            tmp.cleanup()

    def test_token_generated_once_and_stable(self):
        cfg = config.Config()
        first = cfg.ensure_token()
        self.assertGreaterEqual(len(first), 20)
        self.assertEqual(cfg.ensure_token(), first)

    def test_corrupt_config_raises(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            path = Path(tmp.name) / "config.json"
            path.write_text("{ not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                config.Config.load(path)
        finally:
            tmp.cleanup()

    def test_flatten_keys_lists_every_leaf(self):
        keys = config.flatten_keys()
        self.assertIn("lan.subnet", keys)
        self.assertIn("dns.upstream", keys)
        self.assertIn("web.token", keys)
        self.assertIn("netfilter.mss_clamp", keys)
        # 不含中间节点
        self.assertNotIn("lan", keys)
        self.assertNotIn("dns", keys)

    def test_flatten_keys_concrete_tree(self):
        self.assertEqual(config.flatten_keys({"a": {"b": 1, "c": {"d": 2}}}), {"a.b", "a.c.d"})

    def test_validate_catches_real_problems(self):
        cfg = config.Config()
        self.assertEqual(config.validate(cfg), [], "默认配置应当没问题")

        cfg.set("lan.gateway", "10.9.9.9")           # 不在子网内
        cfg.set("lan.pool_start", "192.168.43.250")
        cfg.set("lan.pool_end", "192.168.43.10")     # 起点大于终点
        cfg.set("dns.upstream", ["999.1.1.1"])       # 非法 IP
        cfg.set("static_leases", {"bogus-mac": "192.168.43.9"})
        cfg.set("dns.blocklists", ["/definitely/not/here.txt"])
        problems = " ".join(config.validate(cfg))
        self.assertIn("不在 lan.subnet", problems)
        self.assertIn("pool_start 大于", problems)
        self.assertIn("dns.upstream", problems)
        self.assertIn("MAC 非法", problems)
        self.assertIn("文件不存在", problems)

    def test_validate_warns_about_open_panel(self):
        cfg = config.Config()
        cfg.set("web.host", "0.0.0.0")
        cfg.set("web.token", "")
        problems = " ".join(config.validate(cfg))
        self.assertIn("web.token", problems)

    def test_dns_servers_defaults_to_gateway(self):
        cfg = config.Config()
        self.assertEqual(cfg.dns_servers(), ["192.168.43.1"])
        cfg.set("dhcp.dns", ["9.9.9.9"])
        self.assertEqual(cfg.dns_servers(), ["9.9.9.9"])


class TestCaps(unittest.TestCase):
    def test_real_uid_matches_proc(self):
        uid = caps.real_uid()
        self.assertIsInstance(uid, int)
        text = Path("/proc/self/status").read_text()
        expected = int([l for l in text.splitlines() if l.startswith("Uid:")][0].split()[1])
        self.assertEqual(uid, expected)

    def test_proot_detection_logic(self):
        # 本测试环境本身就是 proot，但断言的是"逻辑自洽"而非环境事实
        if os.getuid() != caps.real_uid():
            self.assertTrue(caps.is_proot(), "getuid 与真实 uid 不一致时必须判定为 proot")

    def test_mode_transitions(self):
        c = caps.Caps(real_uid=1000, real_root=False)
        self.assertEqual(c.mode, "monitor")
        self.assertFalse(c.can_route)

        c = caps.Caps(real_uid=0, real_root=True, iptables="/system/bin/iptables", netfilter_ok=True)
        self.assertEqual(c.mode, "router")
        self.assertTrue(c.can_route)

        c = caps.Caps(real_uid=0, real_root=True, iptables=None, nft=None, netfilter_ok=True)
        self.assertEqual(c.mode, "partial")

    def test_missing_for_router_explains_proot(self):
        c = caps.Caps(real_uid=10408, real_root=False, is_proot=True, is_termux=True)
        text = " ".join(c.missing_for_router())
        self.assertIn("PRoot", text)
        self.assertIn("root", text)
        self.assertTrue(any("tsu" in s for s in c.suggestions()))

    def test_iface_heuristics(self):
        c = caps.Caps(interfaces=["lo", "wlan0", "ap0", "rmnet_data0"], default_iface="rmnet_data0")
        self.assertEqual(c.lan_iface("auto"), "ap0")
        self.assertEqual(c.wan_iface("auto"), "rmnet_data0")
        self.assertEqual(c.lan_iface("wlan1"), "wlan1", "显式配置优先")

    def test_wan_iface_falls_back_to_hints(self):
        c = caps.Caps(interfaces=["lo", "ap0", "rmnet_data1"], default_iface=None)
        self.assertEqual(c.wan_iface("auto"), "rmnet_data1")

    def test_unknown_interfaces_flags_missing(self):
        c = caps.Caps(interfaces=["lo", "rmnet_data0"])
        self.assertEqual(c.unknown_interfaces([("内网", "ap0"), ("外网", "rmnet_data0")]),
                         [("内网", "ap0")])
        self.assertEqual(c.unknown_interfaces([("内网", "lo"), ("外网", "rmnet_data0")]), [])

    def test_unknown_interfaces_silent_when_list_unavailable(self):
        """读不到接口列表时不能乱拦——无法判断就不做无根据的拒绝。"""
        self.assertEqual(caps.Caps(interfaces=[]).unknown_interfaces([("内网", "ap0")]), [])

    def test_unknown_interfaces_ignores_empty_names(self):
        c = caps.Caps(interfaces=["lo"])
        self.assertEqual(c.unknown_interfaces([("内网", None), ("外网", "")]), [])

    def test_doctor_report_shape(self):
        rows = caps.doctor_report(caps.Caps(real_uid=0, real_root=True))
        self.assertTrue(all(len(r) == 3 for r in rows))
        labels = [r[0] for r in rows]
        self.assertIn("真 root", labels)
        self.assertIn("工作模式", labels)

    def test_to_dict_is_json_serializable(self):
        data = caps.Caps(real_uid=0).to_dict()
        json.dumps(data, ensure_ascii=False)


class TestStore(unittest.TestCase):
    def test_ring_buffer_keeps_latest(self):
        ring = store.RingBuffer(3)
        for i in range(6):
            ring.add({"i": i})
        self.assertEqual(len(ring), 3)
        self.assertEqual([x["i"] for x in ring.all()], [3, 4, 5])
        self.assertEqual([x["i"] for x in ring.latest(2)], [5, 4], "latest 应是最新在前")

    def test_ring_buffer_edge_cases(self):
        ring = store.RingBuffer(0)  # 会被夹到 1
        ring.add({"a": 1})
        self.assertEqual(len(ring), 1)
        self.assertEqual(ring.latest(0), [])
        ring.clear()
        self.assertEqual(len(ring), 0)

    def test_json_roundtrip_and_atomicity(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            path = Path(tmp.name) / "sub" / "data.json"
            store.write_json(path, {"中文": "值", "n": 1})
            self.assertEqual(store.read_json(path)["中文"], "值")
            self.assertFalse((Path(tmp.name) / "sub" / "data.json.tmp").exists(),
                             "临时文件必须被 rename 掉")
            self.assertEqual(store.read_json(Path(tmp.name) / "missing.json", {"d": 1}), {"d": 1})
        finally:
            tmp.cleanup()

    def test_corrupt_json_returns_default(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            path = Path(tmp.name) / "bad.json"
            path.write_text("{{{", encoding="utf-8")
            self.assertEqual(store.read_json(path, "fallback"), "fallback")
        finally:
            tmp.cleanup()


class TestRunner(unittest.TestCase):
    def test_dry_run_records_without_executing(self):
        runner = Runner(dry_run=True)
        result = runner.run(["iptables", "-L"])
        self.assertTrue(result.ok)
        self.assertTrue(result.dry_run)
        self.assertEqual(runner.history, [["iptables", "-L"]])

    def test_real_run_captures_output(self):
        runner = Runner(dry_run=False, timeout=10)
        result = runner.run([sys.executable, "-c", "print('hello')"])
        self.assertTrue(result.ok)
        self.assertEqual(result.text, "hello")

    def test_failure_is_reported_not_raised(self):
        runner = Runner()
        result = runner.run([sys.executable, "-c", "raise SystemExit(3)"])
        self.assertFalse(result.ok)
        self.assertEqual(result.code, 3)

    def test_missing_binary(self):
        result = Runner().run(["/definitely/not/a/binary"])
        self.assertEqual(result.code, 127)

    def test_which_and_first_available(self):
        runner = Runner()
        found = runner.which("sh") or runner.which("su")
        self.assertIsNotNone(found)
        self.assertIsNone(runner.which("definitely-not-a-real-binary-xyz"))
        self.assertIsNotNone(runner.first_available(["nope-xyz", "sh"]))

    def test_check_raises(self):
        from trm.exec import CommandError

        with self.assertRaises(CommandError):
            Runner().run([sys.executable, "-c", "raise SystemExit(2)"], check=True)

    def test_timeout(self):
        result = Runner(timeout=0.4).run([sys.executable, "-c", "import time; time.sleep(3)"])
        self.assertTrue(result.timed_out)
        self.assertEqual(result.code, 124)


if __name__ == "__main__":
    unittest.main(verbosity=2)
