"""DHCP 协议与响应逻辑的单元测试。

这些测试**不需要 root、不需要网络、不碰真实套接字**，因此在任何设备上
都能跑。这正是把"响应逻辑"和"套接字层"拆开的价值。
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trm import dhcpd, iputil  # noqa: E402


def mac_bytes(mac: str) -> bytes:
    return iputil.mac_to_bytes(mac) + b"\x00" * 10


def make_request(
    msg_type: int,
    mac: str = "aa:bb:cc:dd:ee:01",
    xid: int = 0x12345678,
    ciaddr: str = "0.0.0.0",
    flags: int = dhcpd.FLAG_BROADCAST,
    extra: dict | None = None,
) -> bytes:
    header = struct.pack(
        "!BBBBIHHIIII16s64s128s",
        dhcpd.BOOTREQUEST, 1, 6, 0, xid, 0, flags,
        iputil.ip_to_int(ciaddr), 0, 0, 0,
        mac_bytes(mac), b"\x00" * 64, b"\x00" * 128,
    )
    options = {dhcpd.OPT_MSG_TYPE: bytes([msg_type])}
    options.update(extra or {})
    return header + dhcpd.MAGIC_COOKIE + dhcpd.encode_options(options)


def make_responder(**overrides):
    kwargs = dict(
        server_ip="192.168.43.1",
        subnet="192.168.43.0/24",
        pool_start="192.168.43.50",
        pool_end="192.168.43.52",
        lease_time=3600,
        dns=["192.168.43.1"],
        domain="lan",
        mtu=1500,
        static_leases={},
    )
    kwargs.update(overrides)
    return dhcpd.DHCPResponder(**kwargs)


class TestChecksum(unittest.TestCase):
    def test_ip_header_checksum_verifies_to_zero(self):
        frame = dhcpd.build_udp_ip_frame(
            b"\x02\x00\x00\x00\x00\x01", b"\xff" * 6,
            "192.168.43.1", "255.255.255.255", 67, 68, b"hello",
        )
        ip_header = frame[14:34]
        self.assertEqual(dhcpd.ip_checksum(ip_header), 0, "IP 头校验和自校验应为 0")

    def test_frame_structure(self):
        payload = b"payload-bytes"
        frame = dhcpd.build_udp_ip_frame(
            b"\x02\x00\x00\x00\x00\x01", b"\xaa\xbb\xcc\xdd\xee\xff",
            "10.0.0.1", "10.0.0.2", 67, 68, payload,
        )
        self.assertGreaterEqual(len(frame), 60, "以太网帧不足 60 字节需要填充")
        self.assertEqual(frame[0:6], b"\xaa\xbb\xcc\xdd\xee\xff", "目的 MAC 应在最前")
        self.assertEqual(frame[12:14], struct.pack("!H", dhcpd.ETH_P_IP))
        self.assertEqual(frame[14], 0x45, "IPv4 + IHL=5")
        self.assertEqual(frame[23], socket.IPPROTO_UDP)
        udp = frame[34:]
        sport, dport, ulen, uck = struct.unpack("!HHHH", udp[:8])
        self.assertEqual((sport, dport), (67, 68))
        self.assertEqual(ulen, 8 + len(payload))
        # 注意：帧尾可能有以太网最小长度填充，所以只比较 payload 那一段
        self.assertEqual(udp[8 : 8 + len(payload)], payload)
        # UDP 校验和（含伪头部）必须自校验为 0
        pseudo = (socket.inet_aton("10.0.0.1") + socket.inet_aton("10.0.0.2")
                  + struct.pack("!BBH", 0, socket.IPPROTO_UDP, ulen))
        self.assertEqual(dhcpd.ip_checksum(pseudo + udp[:ulen]), 0)


class TestCodec(unittest.TestCase):
    def test_parse_discover(self):
        raw = make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:07",
                           extra={dhcpd.OPT_HOSTNAME: b"my-phone"})
        pkt = dhcpd.parse_packet(raw)
        self.assertEqual(pkt.op, dhcpd.BOOTREQUEST)
        self.assertEqual(pkt.msg_type, dhcpd.DISCOVER)
        self.assertEqual(pkt.mac, "aa:bb:cc:dd:ee:07")
        self.assertEqual(pkt.opt_str(dhcpd.OPT_HOSTNAME), "my-phone")
        self.assertTrue(pkt.broadcast_requested)

    def test_parse_rejects_garbage(self):
        with self.assertRaises(ValueError):
            dhcpd.parse_packet(b"\x00" * 10)
        with self.assertRaises(ValueError):
            dhcpd.parse_packet(b"\x01" * 240)  # 没有 magic cookie

    def test_reply_is_bootreply_and_padded(self):
        pkt = dhcpd.parse_packet(make_request(dhcpd.DISCOVER))
        reply = dhcpd.build_reply(pkt, dhcpd.OFFER, "192.168.43.50", "192.168.43.1")
        self.assertGreaterEqual(len(reply), dhcpd.MIN_PACKET)
        parsed = dhcpd.parse_packet(reply)
        self.assertEqual(parsed.op, dhcpd.BOOTREPLY)
        self.assertEqual(parsed.yiaddr, "192.168.43.50")
        self.assertEqual(parsed.msg_type, dhcpd.OFFER)
        self.assertEqual(parsed.opt_ip(dhcpd.OPT_SERVER_ID), "192.168.43.1")
        self.assertEqual(parsed.xid, pkt.xid)


class TestResponder(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store_path = Path(self.tmp.name) / "leases.json"
        # 基准时间必须贴近真实时间：LeaseStore.by_mac() 在不传 now 时用真实时钟，
        # 如果这里用 1e6（1970 年附近）会让所有租约看起来都过期了。
        self.now = [time.time()]

    def tearDown(self):
        self.tmp.cleanup()

    def _responder(self, **kw):
        kw.setdefault("store_obj", dhcpd.LeaseStore(self.store_path))
        kw.setdefault("now_fn", lambda: self.now[0])
        return make_responder(**kw)

    def test_discover_offer_request_ack_flow(self):
        r = self._responder()
        reply, action, mac = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:01"))
        self.assertIn("OFFER", action)
        offered = dhcpd.parse_packet(reply)
        self.assertEqual(offered.msg_type, dhcpd.OFFER)
        self.assertTrue(iputil.in_cidr(offered.yiaddr, "192.168.43.0/24"))
        self.assertEqual(offered.opt_ip(dhcpd.OPT_ROUTER), "192.168.43.1")
        self.assertEqual(offered.opt_ip(dhcpd.OPT_NETMASK), "255.255.255.0")
        self.assertEqual(offered.opt_ip(dhcpd.OPT_DNS), "192.168.43.1")
        self.assertEqual(offered.opt_int(dhcpd.OPT_LEASE_TIME), 3600)

        req = make_request(dhcpd.REQUEST, mac="aa:bb:cc:dd:ee:01", extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton(offered.yiaddr),
            dhcpd.OPT_SERVER_ID: socket.inet_aton("192.168.43.1"),
        })
        reply2, action2, _ = r.respond(req)
        ack = dhcpd.parse_packet(reply2)
        self.assertEqual(ack.msg_type, dhcpd.ACK)
        self.assertEqual(ack.yiaddr, offered.yiaddr)
        self.assertEqual(ack.opt_int(dhcpd.OPT_LEASE_TIME), 3600)
        self.assertEqual(ack.opt_int(dhcpd.OPT_RENEWAL_T1), 1800)
        lease = r.leases.by_mac("aa:bb:cc:dd:ee:01")
        self.assertEqual(lease.state, "bound")
        self.assertFalse(lease.static)

    def test_lease_persists_and_reloads(self):
        r = self._responder()
        r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:02"))
        r.leases.save(force=True)
        reloaded = dhcpd.LeaseStore(self.store_path).load()
        self.assertIsNotNone(reloaded.by_mac("aa:bb:cc:dd:ee:02"))

    def test_request_for_taken_ip_is_nak(self):
        r = self._responder()
        # 01 号先占住 43.50
        reply, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:01"))
        ip = dhcpd.parse_packet(reply).yiaddr
        r.respond(make_request(dhcpd.REQUEST, mac="aa:bb:cc:dd:ee:01", extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton(ip),
            dhcpd.OPT_SERVER_ID: socket.inet_aton("192.168.43.1"),
        }))
        # 02 号硬要同一个地址 → 必须 NAK
        reply2, action2, _ = r.respond(make_request(dhcpd.REQUEST, mac="aa:bb:cc:dd:ee:02", extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton(ip),
            dhcpd.OPT_SERVER_ID: socket.inet_aton("192.168.43.1"),
        }))
        self.assertEqual(dhcpd.parse_packet(reply2).msg_type, dhcpd.NAK)
        self.assertGreaterEqual(r.counters["nak"], 1)

    def test_request_for_other_server_is_ignored(self):
        r = self._responder()
        out = r.respond(make_request(dhcpd.REQUEST, extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton("192.168.43.50"),
            dhcpd.OPT_SERVER_ID: socket.inet_aton("192.168.43.99"),
        }))
        self.assertIsNone(out, "客户端选了别的服务器时不应回应")
        self.assertEqual(r.counters["ignored"], 1)

    def test_release_frees_address(self):
        r = self._responder()
        reply, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:03"))
        ip = dhcpd.parse_packet(reply).yiaddr
        r.respond(make_request(dhcpd.REQUEST, mac="aa:bb:cc:dd:ee:03", extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton(ip),
            dhcpd.OPT_SERVER_ID: socket.inet_aton("192.168.43.1"),
        }))
        self.assertIsNotNone(r.leases.by_ip(ip))
        out = r.respond(make_request(dhcpd.RELEASE, mac="aa:bb:cc:dd:ee:03", ciaddr=ip))
        self.assertIsNone(out, "RELEASE 不需要回应")
        self.assertIsNone(r.leases.by_ip(ip))

    def test_decline_blacklists_address(self):
        r = self._responder()
        reply, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:04"))
        ip = dhcpd.parse_packet(reply).yiaddr
        r.respond(make_request(dhcpd.DECLINE, mac="aa:bb:cc:dd:ee:04", extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton(ip),
        }))
        self.assertIn(ip, r.declined)
        # 再问一次，必须换一个地址
        reply2, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:05"))
        self.assertNotEqual(dhcpd.parse_packet(reply2).yiaddr, ip)

    def test_static_lease_wins(self):
        r = self._responder(static_leases={"aa:bb:cc:dd:ee:09": "192.168.43.200"})
        reply, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:09"))
        self.assertEqual(dhcpd.parse_packet(reply).yiaddr, "192.168.43.200")
        # 固定租约地址在池外，也照样要能 ACK
        reply2, _, _ = r.respond(make_request(dhcpd.REQUEST, mac="aa:bb:cc:dd:ee:09", extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton("192.168.43.200"),
            dhcpd.OPT_SERVER_ID: socket.inet_aton("192.168.43.1"),
        }))
        self.assertEqual(dhcpd.parse_packet(reply2).msg_type, dhcpd.ACK)
        self.assertTrue(r.leases.by_ip("192.168.43.200").static)

    def test_static_lease_wrong_request_is_nak(self):
        r = self._responder(static_leases={"aa:bb:cc:dd:ee:09": "192.168.43.200"})
        reply, _, _ = r.respond(make_request(dhcpd.REQUEST, mac="aa:bb:cc:dd:ee:09", extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton("192.168.43.77"),
            dhcpd.OPT_SERVER_ID: socket.inet_aton("192.168.43.1"),
        }))
        self.assertEqual(dhcpd.parse_packet(reply).msg_type, dhcpd.NAK)

    def test_pool_exhaustion_returns_none(self):
        r = self._responder(pool_start="192.168.43.50", pool_end="192.168.43.50")
        first, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:0a"))
        self.assertIsNotNone(first)
        for i in range(5):
            out = r.respond(make_request(dhcpd.DISCOVER, mac=f"aa:bb:cc:dd:ee:{0x10 + i:02x}"))
            self.assertIsNone(out, "地址池只有 1 个地址，第二个请求应无回应")

    def test_inform_gets_ack_without_lease(self):
        r = self._responder()
        reply, action, _ = r.respond(make_request(
            dhcpd.INFORM, mac="aa:bb:cc:dd:ee:0b", ciaddr="192.168.43.55"))
        ack = dhcpd.parse_packet(reply)
        self.assertEqual(ack.msg_type, dhcpd.ACK)
        self.assertEqual(ack.yiaddr, "0.0.0.0", "INFORM 不应分配地址")
        self.assertEqual(len(r.leases.active()), 0)

    def test_dns_and_domain_options_use_configured_values(self):
        r = self._responder(dns=["9.9.9.9", "1.1.1.1"], domain="home.lan", mtu=1400)
        reply, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:0c"))
        pkt = dhcpd.parse_packet(reply)
        raw = pkt.options[dhcpd.OPT_DNS]
        got = [socket.inet_ntoa(raw[i:i + 4]) for i in range(0, len(raw), 4)]
        self.assertEqual(got, ["9.9.9.9", "1.1.1.1"])
        self.assertEqual(pkt.opt_str(dhcpd.OPT_DOMAIN), "home.lan")
        self.assertEqual(pkt.opt_int(dhcpd.OPT_MTU), 1400)

    def test_lease_not_offered_to_another_mac_while_active(self):
        r = self._responder()
        reply, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:0d"))
        ip = dhcpd.parse_packet(reply).yiaddr
        r.respond(make_request(dhcpd.REQUEST, mac="aa:bb:cc:dd:ee:0d", extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton(ip),
            dhcpd.OPT_SERVER_ID: socket.inet_aton("192.168.43.1"),
        }))
        reply2, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:0e",
                                              extra={dhcpd.OPT_REQUESTED_IP: socket.inet_aton(ip)}))
        self.assertNotEqual(dhcpd.parse_packet(reply2).yiaddr, ip, "已绑定给别人的地址不能再给")

    def test_expired_lease_is_reusable(self):
        r = self._responder()
        reply, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:0f"))
        ip = dhcpd.parse_packet(reply).yiaddr
        r.respond(make_request(dhcpd.REQUEST, mac="aa:bb:cc:dd:ee:0f", extra={
            dhcpd.OPT_REQUESTED_IP: socket.inet_aton(ip),
            dhcpd.OPT_SERVER_ID: socket.inet_aton("192.168.43.1"),
        }))
        self.now[0] += 3601  # 租约过期
        # LeaseStore 内部用真实时钟，测试里必须把假时钟显式传进去
        self.assertEqual(r.leases.sweep(now=self.now[0]), 1)
        reply2, _, _ = r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:11",
                                              extra={dhcpd.OPT_REQUESTED_IP: socket.inet_aton(ip)}))
        self.assertEqual(dhcpd.parse_packet(reply2).yiaddr, ip)

    def test_snapshot_shape(self):
        r = self._responder()
        r.respond(make_request(dhcpd.DISCOVER, mac="aa:bb:cc:dd:ee:12"))
        snap = r.snapshot()
        self.assertEqual(snap["server_ip"], "192.168.43.1")
        self.assertEqual(snap["pool_size"], 3)
        self.assertEqual(len(snap["leases"]), 1)
        self.assertIn("remaining", snap["leases"][0])


class TestLeaseStore(unittest.TestCase):
    def test_sweep_and_remove(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            ls = dhcpd.LeaseStore(Path(tmp.name) / "l.json")
            ls.put(dhcpd.Lease(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:01", expires=10.0))
            ls.put(dhcpd.Lease(ip="10.0.0.6", mac="aa:bb:cc:dd:ee:02", expires=10_000.0))
            self.assertEqual(len(ls.active(now=50.0)), 1)
            self.assertEqual(ls.sweep(now=50.0), 1)
            self.assertEqual(len(ls.active(now=50.0)), 1)
            self.assertEqual(ls.remove_mac("aa:bb:cc:dd:ee:02"), 1)
            self.assertEqual(len(ls.leases), 0)
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
