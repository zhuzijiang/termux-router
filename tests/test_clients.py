"""客户端聚合逻辑的单元测试（纯数据，不碰系统）。"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trm import clients, config  # noqa: E402


def cfg_with(**overrides) -> config.Config:
    cfg = config.Config()
    for key, value in overrides.items():
        cfg.set(key.replace("__", "."), value)
    return cfg


class TestArpParsing(unittest.TestCase):
    HEADER = "IP address       HW type     Flags       HW address            Mask     Device\n"

    def test_parses_complete_entries_only(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            path = Path(tmp.name) / "arp"
            path.write_text(
                self.HEADER
                + "192.168.43.50    0x1         0x2         aa:bb:cc:dd:ee:01     *        ap0\n"
                + "192.168.43.51    0x1         0x0         00:00:00:00:00:00     *        ap0\n"  # 未完成
                + "192.168.43.52    0x1         0x2         AA:BB:CC:DD:EE:03     *        ap0\n"
                + "\n",
                encoding="utf-8",
            )
            table = clients.read_arp_table(str(path))
            self.assertIn("192.168.43.50", table)
            self.assertNotIn("192.168.43.51", table, "flags 不含 0x2 的表项要忽略")
            self.assertEqual(table["192.168.43.50"], "aa:bb:cc:dd:ee:01")
            self.assertEqual(table["192.168.43.52"], "aa:bb:cc:dd:ee:03", "MAC 应统一小写")
        finally:
            tmp.cleanup()

    def test_missing_file_returns_empty(self):
        self.assertEqual(clients.read_arp_table("/definitely/missing/arp"), {})


class TestCollectClients(unittest.TestCase):
    def test_merges_lease_arp_traffic_limits_and_names(self):
        cfg = cfg_with(client_names={"192.168.43.50": "客厅电视"},
                       limits={"192.168.43.50": {"down_kbps": 4096, "up_kbps": 512}})
        leases = [{"ip": "192.168.43.50", "mac": "aa:bb:cc:dd:ee:01",
                   "hostname": "tv-box", "static": False, "remaining": 1800}]
        arp = {"192.168.43.50": "aa:bb:cc:dd:ee:01"}
        traffic = {"192.168.43.50": {"up": 1000, "down": 9000, "conns": 3}}
        result = clients.collect_clients(cfg, leases=leases, arp=arp, traffic=traffic)
        self.assertEqual(len(result), 1)
        c = result[0]
        self.assertEqual(c.ip, "192.168.43.50")
        self.assertEqual(c.name, "客厅电视")
        self.assertEqual(c.label, "客厅电视", "备注名优先于主机名")
        self.assertEqual(c.hostname, "tv-box")
        self.assertIs(c.online, True)
        self.assertEqual((c.up, c.down, c.conns), (1000, 9000, 3))
        self.assertEqual((c.down_kbps, c.up_kbps), (4096, 512))

    def test_label_fallback_order(self):
        cfg = config.Config()
        result = clients.collect_clients(cfg, leases=[
            {"ip": "192.168.43.60", "mac": "aa:bb:cc:dd:ee:02", "hostname": "phone", "remaining": 60},
            {"ip": "192.168.43.61", "mac": "aa:bb:cc:dd:ee:03", "hostname": "", "remaining": 60},
        ])
        labels = {c.ip: c.label for c in result}
        self.assertEqual(labels["192.168.43.60"], "phone")
        self.assertEqual(labels["192.168.43.61"], "aa:bb:cc:dd:ee:03", "没有主机名就用 MAC")

    def test_device_without_lease_but_in_arp_is_listed(self):
        cfg = config.Config()
        result = clients.collect_clients(cfg, arp={"192.168.43.77": "aa:bb:cc:dd:ee:09"})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].ip, "192.168.43.77")
        self.assertIs(result[0].online, True)

    def test_addresses_outside_subnet_are_filtered(self):
        cfg = config.Config()
        result = clients.collect_clients(cfg, arp={"8.8.8.8": "aa:bb:cc:dd:ee:01"},
                                         traffic={"1.2.3.4": {"up": 5, "down": 5, "conns": 1}})
        self.assertEqual(result, [])

    def test_lease_without_arp_reports_unknown_not_offline(self):
        """没有 root 就没有 ARP 表：这时必须说"未知"，不能瞎报"离线"。"""
        cfg = config.Config()
        result = clients.collect_clients(cfg, leases=[
            {"ip": "192.168.43.70", "mac": "aa:bb:cc:dd:ee:04", "remaining": 600}])
        self.assertIsNone(result[0].online, "只有租约时在线状态应为未知")

    def test_traffic_marks_online(self):
        cfg = config.Config()
        result = clients.collect_clients(cfg, leases=[
            {"ip": "192.168.43.71", "mac": "aa:bb:cc:dd:ee:05", "remaining": 600}],
            traffic={"192.168.43.71": {"up": 1, "down": 1, "conns": 2}})
        self.assertIs(result[0].online, True, "有活跃连接就能判定在线")

    def test_sorted_by_ip(self):
        cfg = config.Config()
        result = clients.collect_clients(cfg, arp={
            "192.168.43.99": "aa:bb:cc:dd:ee:01",
            "192.168.43.10": "aa:bb:cc:dd:ee:02",
            "192.168.43.50": "aa:bb:cc:dd:ee:03",
        })
        self.assertEqual([c.ip for c in result],
                         ["192.168.43.10", "192.168.43.50", "192.168.43.99"])

    def test_malformed_limit_ignored(self):
        cfg = cfg_with(limits={"192.168.43.50": "garbage"})
        result = clients.collect_clients(cfg, leases=[
            {"ip": "192.168.43.50", "mac": "aa:bb:cc:dd:ee:01", "remaining": 60}])
        self.assertEqual(result[0].down_kbps, 0)

    def test_to_dict_contains_derived_fields(self):
        cfg = cfg_with(limits={"192.168.43.50": {"down_kbps": 100, "up_kbps": 0}})
        result = clients.collect_clients(cfg, leases=[
            {"ip": "192.168.43.50", "mac": "aa:bb:cc:dd:ee:01", "remaining": 60}])
        data = result[0].to_dict()
        self.assertTrue(data["limited"])
        self.assertEqual(data["total"], 0)
        self.assertIn("label", data)


class TestSummary(unittest.TestCase):
    def test_counts(self):
        cfg = config.Config()
        result = clients.collect_clients(cfg, leases=[
            {"ip": "192.168.43.50", "mac": "aa:bb:cc:dd:ee:01", "remaining": 60},   # 未知
            {"ip": "192.168.43.51", "mac": "aa:bb:cc:dd:ee:02", "remaining": 60},
        ], arp={"192.168.43.51": "aa:bb:cc:dd:ee:02"})                              # 在线
        summary = clients.summarize(result)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["online"], 1)
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["offline"], 0)

    def test_empty(self):
        summary = clients.summarize([])
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["up"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
