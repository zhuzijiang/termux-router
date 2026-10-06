"""数据面规则生成的单元测试（dry-run，不需要 root）。

这是本项目最值得测试的部分：规则写错会**断网**，而这类错误在真机上
用眼睛很难发现。把规则生成写成纯函数，就能在这里逐条断言。
"""

from __future__ import annotations

import socket
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trm import net, shaper  # noqa: E402
from trm.exec import Runner  # noqa: E402


def ctx(**overrides) -> net.PlaneContext:
    base = dict(lan_iface="ap0", wan_iface="rmnet_data0", backend="iptables")
    base.update(overrides)
    return net.PlaneContext(**base)


def argv_list(steps) -> list:
    return [s.argv for s in steps]


class TestIptablesPlan(unittest.TestCase):
    def test_enable_plan_contains_essentials(self):
        plan = argv_list(net.iptables_enable_plan(ctx()))
        self.assertIn(["iptables", "-t", "nat", "-A", "TRM_NAT", "-j", "MASQUERADE"], plan)
        self.assertIn(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "rmnet_data0", "-j", "TRM_NAT"], plan)
        self.assertIn(["iptables", "-A", "FORWARD", "-j", "TRM_FWD"], plan)
        self.assertIn(["iptables", "-A", "TRM_FWD", "-i", "ap0", "-o", "rmnet_data0", "-j", "ACCEPT"], plan)
        self.assertIn(["iptables", "-A", "TRM_FWD", "-i", "rmnet_data0", "-o", "ap0",
                       "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], plan)

    def test_mss_clamp_present_by_default(self):
        plan = argv_list(net.iptables_enable_plan(ctx()))
        self.assertIn(["iptables", "-t", "mangle", "-A", "TRM_MSS", "-p", "tcp",
                       "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"], plan)

    def test_mss_clamp_can_be_disabled(self):
        plan = argv_list(net.iptables_enable_plan(ctx(mss_clamp=False)))
        self.assertFalse(any("TRM_MSS" in str(step) for step in plan))

    def test_masquerade_can_be_disabled(self):
        plan = argv_list(net.iptables_enable_plan(ctx(masquerade=False)))
        self.assertFalse(any(step[-1] == "MASQUERADE" for step in plan))

    def test_jump_rules_are_deleted_before_added_for_idempotency(self):
        plan = argv_list(net.iptables_enable_plan(ctx()))
        for chain_arg in ("POSTROUTING", "FORWARD"):
            deletes = [i for i, s in enumerate(plan) if s[2:4] == ["-D", chain_arg] or
                       ("-D" in s and chain_arg in s)]
            adds = [i for i, s in enumerate(plan) if "-A" in s and chain_arg in s]
            self.assertTrue(deletes, f"{chain_arg} 必须先删除旧跳转")
            self.assertTrue(adds)
            self.assertLess(min(deletes), max(adds), "删除必须在添加之前，否则会重复堆叠规则")

    def test_enable_is_idempotent_by_construction(self):
        """同一份计划跑两次，产出的命令序列必须完全一致（没有随机/状态依赖）。"""
        first = argv_list(net.iptables_enable_plan(ctx()))
        second = argv_list(net.iptables_enable_plan(ctx()))
        self.assertEqual(first, second)

    def test_custom_chains_are_used_not_builtin_flush(self):
        """绝不能出现 `-F FORWARD` 这种清空系统链的操作。"""
        plan = argv_list(net.iptables_enable_plan(ctx()))
        self.assertNotIn(["iptables", "-F", "FORWARD"], plan)
        self.assertNotIn(["iptables", "-F", "POSTROUTING"], plan)
        self.assertNotIn(["iptables", "-t", "nat", "-F", "POSTROUTING"], plan)

    def test_dns_hijack_rules(self):
        plan = argv_list(net.iptables_enable_plan(ctx(hijack_dns=True, dns_port=5353)))
        self.assertIn(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", "ap0", "-p", "udp",
                       "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"], plan)
        self.assertIn(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", "ap0", "-p", "tcp",
                       "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"], plan)

    def test_dns_hijack_off_by_default(self):
        plan = argv_list(net.iptables_enable_plan(ctx()))
        self.assertFalse(any("REDIRECT" in str(step) for step in plan))

    def test_disable_plan_removes_everything_it_created(self):
        plan = argv_list(net.iptables_disable_plan(ctx()))
        for chain in (net.CHAIN_NAT, net.CHAIN_FWD, net.CHAIN_MSS):
            self.assertTrue(any(step and step[-1] == chain and "-X" in step for step in plan),
                            f"{chain} 必须被 -X 删除")

    def test_disable_also_removes_hijack_rules(self):
        plan = argv_list(net.iptables_disable_plan(ctx(hijack_dns=True)))
        self.assertTrue(any("REDIRECT" in str(step) and "-D" in step for step in plan))


class TestNftPlan(unittest.TestCase):
    def test_script_contains_table_and_hooks(self):
        script = net.nft_script(ctx(backend="nft"))
        self.assertIn("table ip trm {", script)
        self.assertIn("type nat hook postrouting priority srcnat;", script)
        self.assertIn('oifname "rmnet_data0" masquerade', script)
        self.assertIn('iifname "ap0" oifname "rmnet_data0" accept', script)
        self.assertIn("ct state established,related accept", script)
        self.assertIn("tcp option maxseg size set rt mtu", script)
        self.assertTrue(script.rstrip().endswith("}"))

    def test_script_braces_balanced(self):
        script = net.nft_script(ctx(backend="nft"))
        self.assertEqual(script.count("{"), script.count("}"))

    def test_mss_chain_omitted_when_disabled(self):
        script = net.nft_script(ctx(backend="nft", mss_clamp=False))
        self.assertNotIn("maxseg", script)

    def test_hijack_rules_in_script(self):
        script = net.nft_script(ctx(backend="nft", hijack_dns=True, dns_port=5353))
        self.assertIn("udp dport 53 redirect to :5353", script)

    def test_enable_plan_deletes_then_feeds_script(self):
        steps = net.nft_enable_plan(ctx(backend="nft"), nft="nft")
        self.assertEqual(steps[0].argv, ["nft", "delete", "table", "ip", "trm"])
        self.assertEqual(steps[1].argv, ["nft", "-f", "-"])
        self.assertIn("table ip trm", steps[1].stdin_text)

    def test_masquerade_off(self):
        script = net.nft_script(ctx(backend="nft", masquerade=False))
        self.assertNotIn("masquerade", script)


class TestSysctl(unittest.TestCase):
    def test_plan_includes_forwarding(self):
        pairs = dict(net.plan_sysctl(ctx()))
        self.assertEqual(pairs["net.ipv4.ip_forward"], "1")
        self.assertEqual(pairs["net.ipv4.conf.all.send_redirects"], "0")
        self.assertEqual(pairs["net.ipv4.conf.ap0.send_redirects"], "0")

    def test_apply_sysctl_writes_files(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            # /proc/sys 下这些目录本来就在；tmp 里要自己造
            (root / "net" / "ipv4").mkdir(parents=True)
            failures = net.apply_sysctl([("net.ipv4.ip_forward", "1")], root=str(root))
            self.assertEqual(failures, [])
            written = (root / "net" / "ipv4" / "ip_forward").read_text()
            self.assertEqual(written, "1")
        finally:
            tmp.cleanup()

    def test_apply_sysctl_reports_missing_key(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            failures = net.apply_sysctl([("net.ipv4.nonexistent", "1")], root=tmp.name)
            self.assertEqual(len(failures), 1)
            self.assertIn("nonexistent", failures[0])
        finally:
            tmp.cleanup()

    def test_stable_path_mapping(self):
        self.assertEqual(str(net.sysctl_path("net.ipv4.ip_forward")), "/proc/sys/net/ipv4/ip_forward")


class TestCounters(unittest.TestCase):
    def test_interface_counters_from_sysfs(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            stats = root / "ap0" / "statistics"
            stats.mkdir(parents=True)
            (stats / "rx_bytes").write_text("1234\n")
            (stats / "tx_bytes").write_text("5678\n")
            self.assertEqual(net.interface_counters("ap0", root=str(root)), (1234, 5678))
            self.assertEqual(net.interface_counters("missing", root=str(root)), (0, 0))
        finally:
            tmp.cleanup()


class TestConntrack(unittest.TestCase):
    LINE = ("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.43.50 dst=142.250.1.1 "
            "sport=41234 dport=443 packets=12 bytes=2048 src=142.250.1.1 dst=192.168.43.50 "
            "sport=443 dport=41234 packets=10 bytes=8192 [ASSURED] mark=0 use=1")

    def test_parse_line(self):
        entry = net.parse_conntrack_line(self.LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["src"], "192.168.43.50")
        self.assertEqual(entry["dst"], "142.250.1.1")
        self.assertEqual(entry["bytes"], 2048)
        self.assertEqual(entry["reply_src"], "142.250.1.1")
        self.assertEqual(entry["reply_dst"], "192.168.43.50", "回复方向的目的地址才是内网客户端")
        self.assertEqual(entry["reply_bytes"], 8192)
        self.assertEqual(entry["state"], "ESTABLISHED")
        self.assertEqual(entry["proto"], "tcp")

    def test_parse_udp_line(self):
        line = ("ipv4     2 udp      17 29 src=10.0.0.5 dst=1.1.1.1 sport=5353 dport=53 "
                "packets=1 bytes=60 src=1.1.1.1 dst=10.0.0.5 sport=53 dport=5353 packets=1 bytes=90 mark=0 use=1")
        entry = net.parse_conntrack_line(line)
        self.assertEqual(entry["src"], "10.0.0.5")
        self.assertEqual(entry["reply_bytes"], 90)

    def test_parse_garbage(self):
        self.assertIsNone(net.parse_conntrack_line(""))
        self.assertIsNone(net.parse_conntrack_line("nothing useful"))

    def test_aggregate_directions(self):
        """客户端上行=原始方向字节，下行=回复方向字节。这是最容易搞反的地方。"""
        entries = [
            net.parse_conntrack_line(self.LINE),
            net.parse_conntrack_line(self.LINE.replace("192.168.43.50", "192.168.43.51")),
            # 非内网地址不应计入
            net.parse_conntrack_line(self.LINE.replace("192.168.43.50", "8.8.8.8")
                                     .replace("142.250.1.1", "9.9.9.9")),
        ]
        stats = net.aggregate_lan_traffic(entries)
        self.assertIn("192.168.43.50", stats)
        self.assertIn("192.168.43.51", stats)
        self.assertNotIn("8.8.8.8", stats)
        self.assertEqual(stats["192.168.43.50"]["up"], 2048)
        self.assertEqual(stats["192.168.43.50"]["down"], 8192)
        self.assertEqual(stats["192.168.43.50"]["conns"], 1)

    def test_read_conntrack_missing_file(self):
        self.assertEqual(net.read_conntrack(path="/definitely/missing"), [])


class TestApply(unittest.TestCase):
    def test_apply_records_failures_but_continues(self):
        runner = Runner(dry_run=True)
        steps = [net.Step(argv=["iptables", "-A", "X"]), net.Step(argv=["iptables", "-A", "Y"])]
        problems = net.apply(runner, steps)
        self.assertEqual(problems, [], "dry-run 下全部视为成功")
        self.assertEqual(len(runner.history), 2)

    def test_apply_reports_real_failures(self):
        runner = Runner()
        steps = [net.Step(argv=[sys.executable, "-c", "raise SystemExit(1)"], note="故意失败"),
                 net.Step(argv=[sys.executable, "-c", "pass"])]
        problems = net.apply(runner, steps)
        self.assertEqual(len(problems), 1)
        self.assertEqual(len(runner.history), 2, "一条失败不应中断后续规则下发")

    def test_step_display(self):
        self.assertEqual(net.Step(argv=["a", "b"]).display(), "a b")
        self.assertIn("script", net.Step(stdin_text="x", note="脚本").display())


class TestShaperMap(unittest.TestCase):
    def test_allocation_is_stable(self):
        m = shaper.ShaperMap()
        first = m.alloc("192.168.43.50")
        self.assertEqual(m.alloc("192.168.43.50"), first, "同一 IP 必须拿到同一 classid")
        second = m.alloc("192.168.43.51")
        self.assertNotEqual(first["minor"], second["minor"])
        self.assertNotEqual(first["prio"], second["prio"])

    def test_never_collides_with_default_class(self):
        m = shaper.ShaperMap()
        for i in range(1, 30):
            entry = m.alloc(f"192.168.43.{i}")
            self.assertNotEqual(entry["minor"], shaper.DEFAULT_CLASS_MINOR)

    def test_roundtrip(self):
        m = shaper.ShaperMap()
        m.alloc("10.0.0.1")
        restored = shaper.ShaperMap.from_dict(m.to_dict())
        self.assertEqual(restored.get("10.0.0.1"), m.get("10.0.0.1"))

    def test_from_dict_ignores_junk(self):
        restored = shaper.ShaperMap.from_dict({"1.2.3.4": {"minor": "x"}, "5.6.7.8": "nope"})
        self.assertEqual(restored.to_dict(), {})


class TestShaperPlan(unittest.TestCase):
    def test_setup_commands(self):
        steps = argv_list(shaper.plan_setup("ap0"))
        self.assertIn(["tc", "qdisc", "replace", "dev", "ap0", "root", "handle", "1:", "htb", "default", "30"], steps)
        self.assertIn(["tc", "qdisc", "replace", "dev", "ap0", "handle", "ffff:", "ingress"], steps)

    def test_default_rate_when_unlimited(self):
        commands = " ".join(str(s) for s in argv_list(shaper.plan_setup("ap0", default_down_kbps=0)))
        self.assertIn("1000mbit", commands)

    def test_limit_downlink_and_uplink(self):
        entry = {"minor": 0x100, "prio": 10}
        steps = argv_list(shaper.plan_limit("192.168.43.50", 2048, 512, "ap0", entry))
        self.assertIn(["tc", "class", "replace", "dev", "ap0", "parent", "1:", "classid", "1:256",
                       "htb", "rate", "2048kbit", "ceil", "2048kbit", "burst", "32k"], steps)
        self.assertIn(["tc", "filter", "replace", "dev", "ap0", "protocol", "ip", "parent", "1:",
                       "prio", "10", "u32", "match", "ip", "dst", "192.168.43.50/32", "flowid", "1:256"], steps)
        self.assertIn(["tc", "filter", "replace", "dev", "ap0", "protocol", "ip", "parent", "ffff:",
                       "prio", "10", "u32", "match", "ip", "src", "192.168.43.50/32",
                       "police", "rate", "512kbit", "burst", "64k", "drop", "flowid", ":1"], steps)

    def test_zero_up_removes_ingress_filter(self):
        entry = {"minor": 0x100, "prio": 10}
        steps = argv_list(shaper.plan_limit("192.168.43.50", 1024, 0, "ap0", entry))
        self.assertTrue(any(s[:5] == ["tc", "filter", "del", "dev", "ap0"] for s in steps))
        self.assertFalse(any("police" in s for s in steps))

    def test_unlimit_removes_filters_and_class(self):
        entry = {"minor": 0x100, "prio": 10}
        steps = argv_list(shaper.plan_unlimit("192.168.43.50", "ap0", entry))
        self.assertTrue(any(s[-1] == "1:256" and "class" in s and "del" in s for s in steps))
        self.assertEqual(len(steps), 3)

    def test_teardown(self):
        steps = argv_list(shaper.plan_teardown("ap0"))
        self.assertIn(["tc", "qdisc", "del", "dev", "ap0", "root"], steps)

    def test_parse_class_stats(self):
        text = (
            "class htb 1:30 root prio 0 rate 1000Mbit ceil 1000Mbit\n"
            " Sent 100 bytes 2 pkt (dropped 0, overlimits 0 requeues 0)\n"
            "class htb 1:256 parent 1: prio 0 rate 2048Kbit ceil 2048Kbit\n"
            " Sent 55555 bytes 78 pkt (dropped 3, overlimits 1 requeues 0)\n"
        )
        stats = shaper.parse_class_stats(text)
        self.assertIn("1:256", stats)
        self.assertEqual(stats["1:256"]["bytes"], 55555)
        self.assertEqual(stats["1:256"]["dropped"], 3)
        self.assertEqual(stats["1:30"]["bytes"], 100)


class TestLocalAddresses(unittest.TestCase):
    class FakeRunner:
        """只实现 run()，用来喂一段假的 ip 输出。"""

        def __init__(self, output: str, code: int = 0):
            self.output = output
            self.code = code
            self.history = []

        def which(self, name):
            return "/system/bin/ip"

        def run(self, cmd, **kwargs):
            self.history.append(cmd)

            class R:
                ok = True
                code = 0
                out = self.output
                err = ""
                lines = staticmethod(lambda: [l for l in self.output.splitlines() if l.strip()])

            return R()

    IP_OUTPUT = (
        "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
        "2: rmnet_data1    inet 10.27.204.100/29 brd 10.27.204.103 scope global rmnet_data1\n"
        "3: wlan0    inet 192.168.1.99/24 brd 192.168.1.255 scope global wlan0\n"
    )

    def test_parses_all_addresses(self):
        got = net.local_ipv4(self.FakeRunner(self.IP_OUTPUT))
        self.assertEqual(got, [("lo", "127.0.0.1"), ("rmnet_data1", "10.27.204.100"),
                               ("wlan0", "192.168.1.99")])

    def test_empty_output(self):
        self.assertEqual(net.local_ipv4(self.FakeRunner("")), [])

    def test_no_ip_command(self):
        class NoIp:
            def which(self, name):
                return None

            def run(self, cmd, **kwargs):
                raise AssertionError("没有 ip 命令时不该执行命令")

        self.assertEqual(net.local_ipv4(NoIp()), [])

    def test_is_private_ip(self):
        for addr in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "100.64.0.1"):
            self.assertTrue(net.is_private_ip(addr), addr)
        for addr in ("8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1"):
            self.assertFalse(net.is_private_ip(addr), addr)
        self.assertFalse(net.is_private_ip("garbage"))


class TestBackendSelection(unittest.TestCase):
    def test_selects_iptables_when_usable(self):
        class C:
            iptables = "/system/bin/iptables"
            nft = None
            netfilter_ok = True
            real_root = True
        self.assertEqual(net.select_backend(C()), "iptables")

    def test_prefers_iptables_over_nft(self):
        class C:
            iptables = "/system/bin/iptables"
            nft = "/system/bin/nft"
            netfilter_ok = True
            real_root = True
        self.assertEqual(net.select_backend(C()), "iptables")

    def test_falls_back_to_nft(self):
        class C:
            iptables = None
            nft = "/system/bin/nft"
            netfilter_ok = True
            real_root = True
        self.assertEqual(net.select_backend(C()), "nft")

    def test_returns_none_without_privilege(self):
        class C:
            iptables = "/system/bin/iptables"
            nft = None
            netfilter_ok = False
            real_root = False
        self.assertIsNone(net.select_backend(C()))

    def test_plane_context_from_config(self):
        from trm import config as config_mod

        class C:
            iptables = "/system/bin/iptables"
            nft = None
            netfilter_ok = True
            real_root = True
            interfaces = ["ap0", "rmnet_data0"]
            default_iface = "rmnet_data0"

            def lan_iface(self, cfg="auto"):
                return "ap0"

            def wan_iface(self, cfg="auto"):
                return "rmnet_data0"

        cfg = config_mod.Config()
        context = net.PlaneContext.from_config(cfg, C())
        self.assertEqual(context.lan_iface, "ap0")
        self.assertEqual(context.wan_iface, "rmnet_data0")
        self.assertEqual(context.backend, "iptables")
        self.assertEqual(context.lan_subnet, "192.168.43.0/24")


if __name__ == "__main__":
    unittest.main(verbosity=2)
