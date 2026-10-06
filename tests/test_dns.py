"""DNS 转发器 / 缓存 / 拦截表 的单元测试。

同样不需要 root 和真实网络：上游用一个假的 ``_forward_udp`` 顶替。
"""

from __future__ import annotations

import socket
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trm import dnsd  # noqa: E402


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def make_query(name: str, qtype: int = dnsd.TYPE_A, xid: int = 0x1234, flags: int = 0x0100) -> bytes:
    return (struct.pack("!HHHHHH", xid, flags, 1, 0, 0, 0)
            + encode_name(name) + struct.pack("!HH", qtype, 1))


def make_upstream_response(query: bytes, ip: str = "93.184.216.34", ttl: int = 120) -> bytes:
    question = dnsd.parse_question(query)
    flags = 0x8180
    header = struct.pack("!HHHHHH", dnsd.transaction_id(query), flags, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", dnsd.TYPE_A, 1, ttl, 4) + socket.inet_aton(ip)
    return header + query[12 : question.end] + answer


class TestNameCodec(unittest.TestCase):
    def test_parse_simple_question(self):
        q = dnsd.parse_question(make_query("ads.example.com"))
        self.assertEqual(q.name, "ads.example.com")
        self.assertEqual(q.qtype, dnsd.TYPE_A)
        self.assertEqual(q.qclass, 1)
        self.assertEqual(q.type_name, "A")

    def test_parse_question_rejects_short(self):
        with self.assertRaises(ValueError):
            dnsd.parse_question(b"\x00" * 5)
        with self.assertRaises(ValueError):
            dnsd.parse_question(struct.pack("!HHHHHH", 0, 0, 0, 0, 0, 0))

    def test_decode_name_with_compression_pointer(self):
        # 报文里偏移 12 处是 "example.com"，偏移 30 处用指针指回 12
        base = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + encode_name("example.com") + struct.pack("!HH", 1, 1)
        pointer_off = len(base)
        packet = base + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("1.2.3.4")
        name, nxt = dnsd.decode_name(packet, pointer_off)
        self.assertEqual(name, "example.com")
        self.assertEqual(nxt, pointer_off + 2)

    def test_compression_loop_is_detected(self):
        packet = struct.pack("!HHHHHH", 0, 0, 0, 0, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(ValueError):
            dnsd.decode_name(packet, 12)

    def test_walk_ttl_offsets_and_rewrite(self):
        response = make_upstream_response(make_query("example.com"), ttl=120)
        offsets = dnsd.walk_ttl_offsets(response)
        self.assertEqual(len(offsets), 1, "应答里应有 1 个 RR")
        self.assertEqual(dnsd.min_ttl(response), 120)
        rewritten = dnsd.rewrite_ttls(response, 42)
        self.assertEqual(len(rewritten), len(response), "改写 TTL 不应改变长度")
        self.assertEqual(dnsd.min_ttl(rewritten), 42)

    def test_walk_handles_truncated_packet(self):
        response = make_upstream_response(make_query("example.com"))
        # 砍掉 RR 尾部 8 字节，TTL 字段本身就不完整了 → 应认为没有可用 TTL
        self.assertEqual(dnsd.min_ttl(response[: len(response) - 8]), 0)
        # 只砍 rdata 的话，TTL 字段仍然完好，应该能读出来（宽容但正确）
        self.assertEqual(dnsd.min_ttl(response[: len(response) - 3]), 120)


class TestBlocklist(unittest.TestCase):
    def test_exact_and_subdomain_semantics(self):
        bl = dnsd.DomainBlocklist()
        bl.add("example.com")
        self.assertTrue(bl.match("example.com"))
        self.assertTrue(bl.match("a.b.example.com"), "父域被封，子域也应被封")
        self.assertFalse(bl.match("notexample.com"))
        self.assertFalse(bl.match("example.com.evil.net"))

    def test_wildcard_only_matches_subdomains(self):
        bl = dnsd.DomainBlocklist()
        bl.add("*.tracker.net")
        self.assertFalse(bl.match("tracker.net"))
        self.assertTrue(bl.match("a.tracker.net"))

    def test_allow_overrides_at_same_level(self):
        bl = dnsd.DomainBlocklist()
        bl.add("doubleclick.net")
        bl.allow_domain("safe.doubleclick.net")
        self.assertTrue(bl.match("ads.doubleclick.net"))
        self.assertFalse(bl.match("safe.doubleclick.net"), "白名单应放行")

    def test_normalization(self):
        bl = dnsd.DomainBlocklist()
        bl.add("https://Ads.Example.CoM/path?x=1")
        self.assertTrue(bl.match("ads.example.com"))

    def test_load_hosts_file(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            p = Path(tmp.name) / "hosts.txt"
            p.write_text(
                "# 注释\n"
                "0.0.0.0 ads.example.com\n"
                "127.0.0.1\t tracker.example.com  # 行尾注释\n"
                "plain-domain.net\n"
                "! 另一种注释\n"
                "0.0.0.0 localhost\n"
                "\n",
                encoding="utf-8",
            )
            bl = dnsd.DomainBlocklist()
            n = bl.load_file(str(p))
            self.assertEqual(n, 3, "localhost 这类应被忽略")
            self.assertTrue(bl.match("ads.example.com"))
            self.assertTrue(bl.match("plain-domain.net"))
            self.assertFalse(bl.match("localhost"))
        finally:
            tmp.cleanup()

    def test_load_missing_file_is_not_fatal(self):
        bl = dnsd.DomainBlocklist()
        self.assertEqual(bl.load_file("/nonexistent/path/hosts.txt"), 0)


class TestCache(unittest.TestCase):
    def test_put_get_and_ttl_decay(self):
        cache = dnsd.DNSCache(capacity=8, min_ttl=1, max_ttl=3600)
        query = make_query("example.com", xid=0xAAAA)
        response = make_upstream_response(query, ttl=100)
        q = dnsd.parse_question(query)
        self.assertTrue(cache.put(q, response, now=1000.0))
        hit = cache.get(q, now=1030.0)
        self.assertIsNotNone(hit)
        self.assertEqual(dnsd.min_ttl(hit), 70, "剩余 TTL 应为 100-30")
        self.assertEqual(dnsd.transaction_id(hit), 0)

    def test_expired_entry_is_miss(self):
        cache = dnsd.DNSCache(min_ttl=1, max_ttl=3600)
        query = make_query("example.com")
        response = make_upstream_response(query, ttl=10)
        q = dnsd.parse_question(query)
        cache.put(q, response, now=1000.0)
        self.assertIsNone(cache.get(q, now=1011.0))
        self.assertEqual(cache.stats()["misses"], 1)

    def test_errors_are_not_cached(self):
        cache = dnsd.DNSCache()
        query = make_query("nope.example")
        q = dnsd.parse_question(query)
        servfail = dnsd.build_response(query, dnsd.RCODE_SERVFAIL)
        self.assertFalse(cache.put(q, servfail, now=1000.0))
        self.assertEqual(cache.stats()["size"], 0)

    def test_zero_ttl_not_cached(self):
        cache = dnsd.DNSCache(min_ttl=0)
        query = make_query("example.com")
        q = dnsd.parse_question(query)
        self.assertFalse(cache.put(q, make_upstream_response(query, ttl=0), now=1000.0))

    def test_capacity_eviction(self):
        cache = dnsd.DNSCache(capacity=32, min_ttl=1)
        for i in range(60):
            q = dnsd.parse_question(make_query(f"host{i}.example.com"))
            cache.put(q, make_upstream_response(make_query(f"host{i}.example.com"), ttl=60), now=1000.0)
            self.assertLessEqual(cache.stats()["size"], cache.capacity)
        self.assertGreater(cache.stats()["evictions"], 0)

    def test_small_capacity_is_respected(self):
        cache = dnsd.DNSCache(capacity=8, min_ttl=1)
        for i in range(40):
            name = f"h{i}.example.com"
            q = dnsd.parse_question(make_query(name))
            cache.put(q, make_upstream_response(make_query(name), ttl=60), now=1000.0)
            self.assertLessEqual(cache.stats()["size"], cache.capacity)

    def test_clear(self):
        cache = dnsd.DNSCache()
        q = dnsd.parse_question(make_query("example.com"))
        cache.put(q, make_upstream_response(make_query("example.com"), ttl=60), now=1000.0)
        self.assertEqual(cache.clear(), 1)
        self.assertEqual(cache.stats()["size"], 0)


class TestProxyHandling(unittest.TestCase):
    def setUp(self):
        self.upstream_calls = []
        self.proxy = dnsd.DNSProxy(upstream=["1.1.1.1"], log_queries=True)

        def fake_forward(data: bytes, upstream: str):
            self.upstream_calls.append(upstream)
            return make_upstream_response(data, ttl=60)

        self.proxy._forward_udp = fake_forward  # type: ignore[method-assign]

    def test_forward_then_cache_hit(self):
        q1 = make_query("example.com", xid=0x1111)
        r1 = self.proxy.handle(q1, client="192.168.43.50")
        self.assertEqual(dnsd.transaction_id(r1), 0x1111, "响应必须带客户端的事务 ID")
        self.assertEqual(self.proxy.stats["forwarded"], 1)

        q2 = make_query("example.com", xid=0x2222)
        r2 = self.proxy.handle(q2, client="192.168.43.51")
        self.assertEqual(dnsd.transaction_id(r2), 0x2222)
        self.assertEqual(self.proxy.stats["cached"], 1)
        self.assertEqual(len(self.upstream_calls), 1, "第二次应命中缓存，不再问上游")

    def test_blocked_a_query_returns_configured_ip(self):
        self.proxy.blocklist.add("ads.example.com")
        r = self.proxy.handle(make_query("ads.example.com"), client="192.168.43.50")
        self.assertEqual(self.proxy.stats["blocked"], 1)
        self.assertEqual(self.upstream_calls, [], "被拦截的域名绝不能去问上游")
        # 解析应答，确认返回 0.0.0.0
        question = dnsd.parse_question(r)
        offsets = dnsd.walk_ttl_offsets(r)
        self.assertEqual(len(offsets), 1)
        rdlength_off = offsets[0] + 4  # TTL(4) 之后紧跟 rdlength(2)
        rdlength = struct.unpack("!H", r[rdlength_off : rdlength_off + 2])[0]
        rdata = r[rdlength_off + 2 : rdlength_off + 2 + rdlength]
        self.assertEqual(socket.inet_ntoa(rdata), "0.0.0.0")
        self.assertEqual(question.name, "ads.example.com")

    def test_blocked_aaaa_returns_nodata(self):
        self.proxy.blocklist.add("ads.example.com")
        r = self.proxy.handle(make_query("ads.example.com", qtype=dnsd.TYPE_AAAA))
        self.assertEqual(len(dnsd.walk_ttl_offsets(r)), 0, "AAAA 应返回无答案")
        self.assertEqual(r[3] & 0x0F, dnsd.RCODE_NOERROR)

    def test_blocked_https_record_returns_nodata(self):
        """只拦 A 记录是漏洞：HTTPS(65) 记录会泄露真实地址。"""
        self.proxy.blocklist.add("ads.example.com")
        r = self.proxy.handle(make_query("ads.example.com", qtype=dnsd.TYPE_HTTPS))
        self.assertEqual(len(dnsd.walk_ttl_offsets(r)), 0)
        self.assertEqual(self.upstream_calls, [])

    def test_nxdomain_mode(self):
        self.proxy.block_response = "nxdomain"
        self.proxy.blocklist.add("ads.example.com")
        r = self.proxy.handle(make_query("ads.example.com"))
        self.assertEqual(r[3] & 0x0F, dnsd.RCODE_NXDOMAIN)

    def test_upstream_failure_yields_servfail(self):
        self.proxy._forward_udp = lambda data, upstream: None  # type: ignore[method-assign]
        r = self.proxy.handle(make_query("example.com"))
        self.assertEqual(r[3] & 0x0F, dnsd.RCODE_SERVFAIL)

    def test_truncated_response_falls_back_to_tcp(self):
        tc_response = bytearray(make_upstream_response(make_query("big.example.com")))
        tc_response[2] |= 0x02  # 置 TC 位
        self.proxy._forward_udp = lambda data, upstream: bytes(tc_response)  # type: ignore[method-assign]
        self.proxy._forward_tcp = lambda data, upstream: make_upstream_response(data, ip="5.6.7.8")  # type: ignore[method-assign]
        r = self.proxy.handle(make_query("big.example.com"))
        self.assertNotEqual(r[3] & 0x02, 0x02, "不应把截断的响应交给客户端")
        self.assertEqual(self.proxy.stats["forwarded"], 1)

    def test_upstream_id_mismatch_is_rejected(self):
        wrong = make_upstream_response(make_query("example.com", xid=0x9999))
        self.proxy._forward_udp = lambda data, upstream: wrong  # type: ignore[method-assign]
        r = self.proxy.handle(make_query("example.com", xid=0x1111))
        self.assertEqual(r[3] & 0x0F, dnsd.RCODE_SERVFAIL, "ID 不匹配必须丢弃，防投毒")

    def test_garbage_query_is_ignored(self):
        self.assertIsNone(self.proxy.handle(b"\x00\x01\x02"))
        self.assertEqual(self.proxy.stats["errors"], 1)

    def test_query_log_records_actions(self):
        self.proxy.blocklist.add("ads.example.com")
        self.proxy.handle(make_query("ads.example.com"), client="10.0.0.5")
        self.proxy.handle(make_query("example.com"), client="10.0.0.5")
        entries = self.proxy.query_log.latest(10)
        self.assertEqual(len(entries), 2)
        actions = {e["name"]: e["action"] for e in entries}
        self.assertEqual(actions["ads.example.com"], "blocked")
        self.assertEqual(actions["example.com"], "forward")

    def test_snapshot_shape(self):
        self.proxy.handle(make_query("example.com"))
        snap = self.proxy.snapshot()
        for key in ("running", "bind", "upstream", "stats", "cache", "blocklist"):
            self.assertIn(key, snap)
        self.assertEqual(snap["upstream"], ["1.1.1.1"])


class TestBuildProxyFromConfig(unittest.TestCase):
    def test_builds_from_config(self):
        from trm import config

        tmp = tempfile.TemporaryDirectory()
        try:
            hosts = Path(tmp.name) / "block.txt"
            hosts.write_text("0.0.0.0 ads.example.com\n", encoding="utf-8")
            cfg = config.Config()
            cfg.set("dns.blocklists", [str(hosts)])
            cfg.set("dns.upstream", ["9.9.9.9"])
            proxy = dnsd.build_proxy(cfg)
            self.assertEqual(proxy.upstream, ["9.9.9.9"])
            self.assertTrue(proxy.blocklist.match("ads.example.com"))
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
