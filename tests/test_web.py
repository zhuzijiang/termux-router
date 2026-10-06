"""管理面板的端到端测试。

面板能改防火墙规则、能踢设备，所以它的**认证**和**路由**必须被测到。
这里真的起一个 HTTP 服务（监听 127.0.0.1 的随机端口）并用标准库请求它。
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trm import web  # noqa: E402

TOKEN = "test-token-1234567890"


def fake_state() -> Dict[str, Any]:
    return {
        "app": {"name": "termux-router", "version": "test", "pid": 1, "uptime": 5, "dry_run": False, "mode": "monitor"},
        "caps": {"mode": "monitor", "mode_label": "监控模式", "missing": ["没有 root"], "suggestions": []},
        "plane": {"applied": False, "backend": None, "lan_iface": None, "wan_iface": "rmnet_data0", "problems": []},
        "counters": {"wan": {"rx": 1, "tx": 2}, "lan": {"rx": 3, "tx": 4}},
        "dhcp": {"running": False},
        "dns": {"running": False, "queries": [{"name": "example.com", "action": "blocked"}]},
        "clients": [{"ip": "192.168.43.50", "up": 10, "down": 20}],
        "client_summary": {"total": 1, "online": 0, "unknown": 1, "limited": 0},
        "hotspot": {"state": "unknown"},
        "phone": {},
        "web": {"url": "http://127.0.0.1:1/"},
        "config": {"lan": {"gateway": "192.168.43.1"}},
        "logs": ["log line"],
    }


class WebTestCase(unittest.TestCase):
    token = TOKEN
    dry_run = False

    def setUp(self):
        self.actions: List[Tuple[str, Dict[str, Any]]] = []

        def handler(action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
            self.actions.append((action, payload))
            return {"ok": True, "message": f"did {action}"}

        self.server = web.WebServer(
            host="127.0.0.1", port=0, token=self.token,
            state_provider=fake_state, action_handler=handler, dry_run=self.dry_run,
        )
        started = self.server.start()
        self.assertTrue(started, f"服务未能启动: {self.server.last_error}")
        self.base = f"http://127.0.0.1:{self.server.port}"

    def tearDown(self):
        self.server.stop()

    # ------------------------------------------------------------- 请求工具
    def request(self, path: str, method: str = "GET", body: Any = None,
                token: str | None = TOKEN, headers: Dict[str, str] | None = None):
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if token:
            req.add_header("X-TRM-Token", token)
        if data:
            req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                raw = response.read()
                return response.status, raw, response.headers
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read(), exc.headers
            finally:
                exc.close()

    def json_of(self, path: str, **kwargs):
        status, raw, _ = self.request(path, **kwargs)
        return status, json.loads(raw.decode("utf-8")) if raw else {}


class TestAuthAndRouting(WebTestCase):
    def test_ping_needs_no_token(self):
        status, payload = self.json_of("/api/ping", token=None)
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["auth_required"])

    def test_status_requires_token(self):
        status, payload = self.json_of("/api/status", token=None)
        self.assertEqual(status, 401)
        self.assertFalse(payload["ok"])

    def test_wrong_token_rejected(self):
        status, _payload = self.json_of("/api/status", token="wrong-token")
        self.assertEqual(status, 401)

    def test_bearer_header_also_works(self):
        status, payload = self.json_of("/api/status", token=None,
                                       headers={"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_token_in_query_string(self):
        status, payload = self.json_of(f"/api/status?token={TOKEN}", token=None)
        self.assertEqual(status, 200)

    def test_status_payload_shape(self):
        status, payload = self.json_of("/api/status")
        self.assertEqual(status, 200)
        self.assertIn("clients", payload["data"])
        self.assertIn("caps", payload["data"])

    def test_clients_endpoint(self):
        status, payload = self.json_of("/api/clients")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["data"]), 1)
        self.assertEqual(payload["data"][0]["ip"], "192.168.43.50")

    def test_dns_queries_endpoint(self):
        status, payload = self.json_of("/api/dns/queries")
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"][0]["name"], "example.com")

    def test_unknown_path_404(self):
        status, payload = self.json_of("/api/definitely-not-here")
        self.assertEqual(status, 404)
        self.assertFalse(payload["ok"])

    def test_index_served_with_html(self):
        status, raw, headers = self.request("/", token=None)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn(b"termux-router", raw)
        self.assertIn("no-store", headers.get("Cache-Control", ""))
        self.assertIn("Content-Security-Policy", headers)

    def test_unauthorized_action_does_not_reach_handler(self):
        status, _payload = self.json_of("/api/net/up", method="POST", body={}, token=None)
        self.assertEqual(status, 401)
        self.assertEqual(self.actions, [], "未认证的请求绝不能触发动作")

    def test_denied_counter_increments(self):
        before = self.server.counters["denied"]
        self.json_of("/api/status", token=None)
        self.assertGreater(self.server.counters["denied"], before)


class TestActions(WebTestCase):
    def test_simple_action(self):
        status, payload = self.json_of("/api/net/up", method="POST", body={})
        self.assertEqual(status, 200)
        self.assertEqual(self.actions[-1][0], "net.up")

    def test_client_limit_route_extracts_ip(self):
        status, payload = self.json_of("/api/clients/192.168.43.50/limit", method="POST",
                                       body={"down_kbps": 2048, "up_kbps": 512})
        self.assertEqual(status, 200)
        action, payload_sent = self.actions[-1]
        self.assertEqual(action, "client.limit")
        self.assertEqual(payload_sent["ip"], "192.168.43.50")
        self.assertEqual(payload_sent["down_kbps"], 2048)

    def test_client_unlimit_and_name_and_forget(self):
        for suffix, expected in (("unlimit", "client.unlimit"),
                                 ("name", "client.name"),
                                 ("forget", "client.forget")):
            self.json_of(f"/api/clients/10.0.0.5/{suffix}", method="POST",
                         body={"name": "客厅电视"} if suffix == "name" else {})
            self.assertEqual(self.actions[-1][0], expected)
            self.assertEqual(self.actions[-1][1]["ip"], "10.0.0.5")

    def test_dns_block_requires_domain(self):
        status, payload = self.json_of("/api/dns/block", method="POST", body={})
        self.assertEqual(status, 400)
        self.assertIn("domain", payload["error"])
        self.assertEqual(self.actions, [])

    def test_dns_block_with_domain(self):
        status, _payload = self.json_of("/api/dns/block", method="POST", body={"domain": "ads.example.com"})
        self.assertEqual(status, 200)
        self.assertEqual(self.actions[-1], ("dns.block", {"domain": "ads.example.com"}))

    def test_config_set_route(self):
        status, _payload = self.json_of("/api/config", method="POST",
                                        body={"key": "lan.gateway", "value": "192.168.9.1"})
        self.assertEqual(status, 200)
        self.assertEqual(self.actions[-1][0], "config.set")

    def test_handler_failure_returns_400(self):
        def failing(_action, _payload):
            return {"ok": False, "error": "故意失败"}

        self.server.action_handler = failing
        status, payload = self.json_of("/api/net/up", method="POST", body={})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "故意失败")

    def test_malformed_json_body_is_tolerated(self):
        url = self.base + "/api/net/up"
        req = urllib.request.Request(url, data=b"{not json", method="POST")
        req.add_header("X-TRM-Token", TOKEN)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(self.actions[-1][0], "net.up")

    def test_get_on_action_path_is_404(self):
        status, _payload = self.json_of("/api/net/up")
        self.assertEqual(status, 404)


class TestDryRunServer(WebTestCase):
    dry_run = True

    def test_actions_are_short_circuited(self):
        status, payload = self.json_of("/api/net/up", method="POST", body={})
        self.assertEqual(status, 200)
        self.assertTrue(payload.get("dry_run"))
        self.assertEqual(self.actions, [], "dry-run 下不得真正执行动作")

    def test_config_set_still_works_in_dry_run(self):
        status, _payload = self.json_of("/api/config", method="POST",
                                        body={"key": "lan.gateway", "value": "10.0.0.1"})
        self.assertEqual(status, 200)
        self.assertEqual(self.actions[-1][0], "config.set")


class TestTokenlessServer(unittest.TestCase):
    """令牌为空时只允许本机访问（本测试就在本机，所以应当通过）。"""

    def setUp(self):
        self.server = web.WebServer(host="127.0.0.1", port=0, token="",
                                    state_provider=fake_state,
                                    action_handler=lambda a, p: {"ok": True})
        self.assertTrue(self.server.start())
        self.base = f"http://127.0.0.1:{self.server.port}"

    def tearDown(self):
        self.server.stop()

    def test_loopback_allowed_without_token(self):
        with urllib.request.urlopen(self.base + "/api/status", timeout=10) as response:
            self.assertEqual(response.status, 200)

    def test_snapshot_reports_no_token(self):
        self.assertFalse(self.server.snapshot()["token_required"])


class TestServerLifecycle(unittest.TestCase):
    def test_stop_is_idempotent(self):
        server = web.WebServer(host="127.0.0.1", port=0, token="x",
                               state_provider=fake_state,
                               action_handler=lambda a, p: {"ok": True})
        server.start()
        server.stop()
        server.stop()
        self.assertFalse(server.running)

    def test_port_conflict_reported(self):
        first = web.WebServer(host="127.0.0.1", port=0, token="x",
                              state_provider=fake_state,
                              action_handler=lambda a, p: {"ok": True})
        self.assertTrue(first.start())
        port = first.port
        second = web.WebServer(host="127.0.0.1", port=port, token="x",
                               state_provider=fake_state,
                               action_handler=lambda a, p: {"ok": True})
        try:
            self.assertFalse(second.start())
            self.assertIn("失败", second.last_error)
        finally:
            first.stop()

    def test_webui_file_exists(self):
        self.assertTrue((web.WEBUI_DIR / "index.html").exists(), "面板 HTML 必须随包提供")

    def test_concurrent_requests(self):
        server = web.WebServer(host="127.0.0.1", port=0, token="x",
                               state_provider=fake_state,
                               action_handler=lambda a, p: {"ok": True})
        server.start()
        errors: List[Exception] = []

        def worker():
            try:
                with urllib.request.urlopen(
                        urllib.request.Request(server.url() + "api/status",
                                               headers={"X-TRM-Token": "x"}), timeout=10) as resp:
                    assert resp.status == 200
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        server.stop()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
