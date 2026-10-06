"""管理面板的 HTTP 服务（只用标准库 ``http.server``）。

安全设计（很重要，因为这东西能改防火墙规则）：

* 默认只监听 ``127.0.0.1``。想用手机浏览器从局域网访问时才改成 ``0.0.0.0``。
* 令牌认证是**强制**的：除了 ``/``（登录页）和 ``/api/ping``，
  所有接口都要带令牌，用 ``hmac.compare_digest`` 做定时安全比较。
* 令牌为空时只允许回环地址访问，避免"忘了设密码"变成"对全网开放"。
* 不提供任何目录遍历；静态资源只有内置的一个 HTML 文件。
"""

from __future__ import annotations

import hmac
import json
import re
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from . import __version__, paths

TOKEN_HEADER = "X-TRM-Token"
MAX_BODY = 256 * 1024
WEBUI_DIR = Path(__file__).parent / "webui"

StateProvider = Callable[[], Dict[str, Any]]
ActionHandler = Callable[[str, Dict[str, Any]], Dict[str, Any]]


def _json_bytes(payload: Any, status: int = 200) -> Tuple[int, bytes, str]:
    return status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8"


class WebServer:
    """把 ``state_provider`` 和 ``action_handler`` 暴露成 REST 接口。"""

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        state_provider: StateProvider,
        action_handler: ActionHandler,
        log: Optional[Callable[[str], None]] = None,
        dry_run: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.token = token or ""
        self.state_provider = state_provider
        self.action_handler = action_handler
        self.log = log or (lambda _m: None)
        self.dry_run = dry_run
        self.httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.last_error = ""
        self.started_at = 0.0
        self.counters = {"requests": 0, "errors": 0, "denied": 0}

    # ------------------------------------------------------------ 生命周期
    def start(self) -> bool:
        try:
            server = ThreadingHTTPServer((self.host, self.port), self._make_handler())
        except OSError as exc:
            self.last_error = f"HTTP 绑定 {self.host}:{self.port} 失败: {exc}"
            return False
        server.daemon_threads = True
        server.allow_reuse_address = True
        # port=0 时由内核分配，测试里很方便；这里把真实端口回填
        self.port = int(server.server_address[1])
        self.httpd = server
        self.started_at = time.time()
        # poll_interval 默认 0.5s：会让 shutdown() 白等半秒。手机上关服务能快就快。
        self._thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=0.05),
            name="web", daemon=True,
        )
        self._thread.start()
        self.log(f"管理面板: http://{self.host}:{self.port}/ （令牌见 trm token）")
        return True

    def stop(self) -> None:
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except OSError:
                pass
        self.httpd = None

    @property
    def running(self) -> bool:
        return self.httpd is not None and (self._thread is not None and self._thread.is_alive())

    def url(self) -> str:
        host = "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host
        return f"http://{host}:{self.port}/"

    def snapshot(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "host": self.host,
            "port": self.port,
            "url": self.url(),
            "token_required": bool(self.token),
            "last_error": self.last_error,
            "counters": dict(self.counters),
            "uptime": int(time.time() - self.started_at) if self.started_at else 0,
        }

    # ---------------------------------------------------------------- 处理器
    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            server_version = f"termux-router/{__version__}"
            protocol_version = "HTTP/1.1"

            # -------------------------------------------------- 基础工具
            def log_message(self, fmt: str, *args: Any) -> None:  # 静音默认 stderr 日志
                return

            def _client_ip(self) -> str:
                return self.client_address[0] if self.client_address else ""

            def _is_loopback(self) -> bool:
                ip = self._client_ip()
                return ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127.")

            def _supplied_token(self, query: Dict[str, List[str]]) -> str:
                header = self.headers.get(TOKEN_HEADER) or ""
                if not header:
                    auth = self.headers.get("Authorization") or ""
                    if auth.lower().startswith("bearer "):
                        header = auth[7:].strip()
                if not header:
                    header = (query.get("token") or [""])[0]
                return header

            def _authorized(self, query: Dict[str, List[str]]) -> Tuple[bool, str]:
                if not server.token:
                    # 没设令牌：只允许本机访问，绝不对外裸奔
                    if self._is_loopback():
                        return True, ""
                    server.counters["denied"] += 1
                    return False, "未设置访问令牌，且请求不是来自本机"
                supplied = self._supplied_token(query)
                if supplied and hmac.compare_digest(supplied, server.token):
                    return True, ""
                server.counters["denied"] += 1
                return False, "令牌无效或缺失"

            def _send(self, status: int, body: bytes, content_type: str,
                      extra: Optional[Dict[str, str]] = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy",
                                 "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
                for key, value in (extra or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _send_json(self, status: int, payload: Any) -> None:
                code, body, ctype = _json_bytes(payload, status)
                self._send(code, body, ctype)

            def _read_body(self) -> Dict[str, Any]:
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    return {}
                if length <= 0:
                    return {}
                if length > MAX_BODY:
                    raise ValueError("请求体过大")
                raw = self.rfile.read(length)
                ctype = (self.headers.get("Content-Type") or "").lower()
                if "json" in ctype:
                    try:
                        data = json.loads(raw.decode("utf-8"))
                        return data if isinstance(data, dict) else {"value": data}
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        return {}
                parsed = parse_qs(raw.decode("utf-8", "replace"))
                return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}

            # -------------------------------------------------- 路由分发
            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_HEAD(self) -> None:
                self._dispatch("GET")

            def do_POST(self) -> None:
                self._dispatch("POST")

            def _dispatch(self, method: str) -> None:
                server.counters["requests"] += 1
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/") or "/"
                query = parse_qs(parsed.query)
                try:
                    if path == "/" or path == "/index.html":
                        self._serve_index()
                        return
                    if path == "/favicon.ico":
                        self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
                        return
                    if path == "/api/ping":
                        self._send_json(200, {"ok": True, "app": "termux-router",
                                              "version": __version__, "auth_required": bool(server.token)})
                        return

                    allowed, why = self._authorized(query)
                    if not allowed:
                        self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": why})
                        return

                    if method == "POST":
                        body = self._read_body()
                        if self._handle_action(path, body):
                            return
                    if self._handle_get(path, query):
                        return
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": f"未知路径 {path}"})
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                except BrokenPipeError:
                    return
                except Exception as exc:  # 面板绝不能因为一个异常整体挂掉
                    server.counters["errors"] += 1
                    server.log(f"面板请求异常 {path}: {exc!r}")
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": repr(exc)})

            def _serve_index(self) -> None:
                index = WEBUI_DIR / "index.html"
                try:
                    body = index.read_bytes()
                except OSError:
                    body = "<h1>termux-router</h1><p>webui/index.html 丢失</p>".encode("utf-8")
                self._send(HTTPStatus.OK, body, "text/html; charset=utf-8")

            def _handle_get(self, path: str, query: Dict[str, List[str]]) -> bool:
                state = server.state_provider
                if path == "/api/status":
                    self._send_json(200, {"ok": True, "data": state()})
                    return True
                if path == "/api/clients":
                    data = state()
                    self._send_json(200, {"ok": True, "data": data.get("clients", []),
                                          "summary": data.get("client_summary", {})})
                    return True
                if path == "/api/dns/queries":
                    limit = int((query.get("limit") or ["100"])[0])
                    data = state()
                    self._send_json(200, {"ok": True, "data": data.get("dns", {}).get("queries", [])[:limit]})
                    return True
                if path == "/api/logs":
                    limit = int((query.get("limit") or ["200"])[0])
                    self._send_json(200, {"ok": True, "data": state().get("logs", [])[:limit]})
                    return True
                if path == "/api/config":
                    self._send_json(200, {"ok": True, "data": state().get("config", {})})
                    return True
                if path in ("/api/net/status", "/api/hotspot"):
                    data = state()
                    key = "plane" if path == "/api/net/status" else "hotspot"
                    self._send_json(200, {"ok": True, "data": data.get(key, {})})
                    return True
                return False

            def _handle_action(self, path: str, body: Dict[str, Any]) -> bool:
                routes: List[Tuple[str, str, List[str]]] = [
                    (r"^/api/net/up$", "net.up", []),
                    (r"^/api/net/down$", "net.down", []),
                    (r"^/api/hotspot/start$", "hotspot.start", []),
                    (r"^/api/hotspot/stop$", "hotspot.stop", []),
                    (r"^/api/dns/cache/clear$", "dns.cache.clear", []),
                    (r"^/api/dns/block$", "dns.block", ["domain"]),
                    (r"^/api/dns/unblock$", "dns.unblock", ["domain"]),
                    (r"^/api/daemon/stop$", "daemon.stop", []),
                    (r"^/api/clients/(?P<ip>[0-9.]+)/limit$", "client.limit", ["ip"]),
                    (r"^/api/clients/(?P<ip>[0-9.]+)/unlimit$", "client.unlimit", ["ip"]),
                    (r"^/api/clients/(?P<ip>[0-9.]+)/name$", "client.name", ["ip"]),
                    (r"^/api/clients/(?P<ip>[0-9.]+)/forget$", "client.forget", ["ip"]),
                    (r"^/api/config$", "config.set", []),
                ]
                for pattern, action, required in routes:
                    match = re.match(pattern, path)
                    if not match:
                        continue
                    payload: Dict[str, Any] = dict(body)
                    payload.update({k: v for k, v in match.groupdict().items() if v})
                    missing = [key for key in required if not payload.get(key)]
                    if missing:
                        self._send_json(HTTPStatus.BAD_REQUEST,
                                        {"ok": False, "error": f"缺少参数: {', '.join(missing)}"})
                        return True
                    if server.dry_run and action not in ("config.set",):
                        self._send_json(200, {"ok": True, "dry_run": True,
                                              "message": f"dry-run 模式：{action} 未真正执行",
                                              "data": payload})
                        return True
                    result = server.action_handler(action, payload)
                    self._send_json(200 if result.get("ok", True) else HTTPStatus.BAD_REQUEST, result)
                    return True
                return False

        return Handler
