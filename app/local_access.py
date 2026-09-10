"""Lightweight boundaries for a single-user, local-only workbench. No login."""
from __future__ import annotations

import os
from ipaddress import ip_address
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse


def loopback(host: str) -> bool:
    host = str(host or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        address = ip_address(host)
        return address.is_loopback or bool(
            getattr(address, "ipv4_mapped", None) and address.ipv4_mapped.is_loopback)
    except ValueError:
        return False


def _allowed_hosts() -> set[str]:
    # SPK-OS patch: LAN 访问白名单（宿主机经 192.168.56.101 访问），
    # 环境变量 CREATORHUB_ALLOWED_HOSTS 逗号分隔，未配置时保持上游 loopback-only 行为。
    raw = os.environ.get("CREATORHUB_ALLOWED_HOSTS", "")
    return {h.strip().strip("[]").lower() for h in raw.split(",") if h.strip()}


def local_request(request: Request) -> bool:
    # Both the peer and Host matter: a DNS-rebinding Host or a local reverse
    # proxy does not turn an arbitrary remote page into the local workbench.
    if request.client and request.client.host in _allowed_hosts() \
            and (request.url.hostname or "").lower() in _allowed_hosts():
        return True
    return bool(request.client and loopback(request.client.host)
                and loopback(request.url.hostname or ""))


def _same_origin(request: Request, value: str) -> bool:
    try:
        origin, target = urlsplit(value), urlsplit(str(request.url))
        def identity(url):
            return (url.scheme, (url.hostname or "").lower(),
                    url.port or (443 if url.scheme == "https" else 80))
        return (not origin.username and not origin.password
                and origin.scheme in {"http", "https"}
                and origin.path in {"", "/"} and not origin.query and not origin.fragment
                and identity(origin) == identity(target))
    except ValueError:
        return False


class LocalAccessMiddleware:
    """Protect local data/actions, without users, passwords, sessions or roles."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        path = scope.get("path", "")
        api = path == "/api" or path.startswith("/api/")
        error = None
        try:
            valid_local = local_request(request) and len(request.headers.getlist("host")) == 1
            request.url.port
        except ValueError:
            valid_local = False
        if not valid_local:
            error = "当前工作台仅供本机使用，请通过 127.0.0.1 或 localhost 访问"
        elif api and (request.headers.get("sec-fetch-site", "") in {"cross-site", "same-site"}
                      or ("origin" in request.headers and not _same_origin(request, request.headers["origin"]))):
            error = "请从 CreatorHub 同源页面发起请求"
        if error:
            await JSONResponse({"detail": error}, status_code=403,
                               headers={"Cache-Control": "no-store"})(scope, receive, send)
            return

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers += [(b"x-content-type-options", b"nosniff"),
                            (b"x-frame-options", b"DENY"),
                            (b"referrer-policy", b"no-referrer")]
                if not path.startswith("/static/"):
                    headers = [(k, v) for k, v in headers if k.lower() != b"cache-control"]
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)
        # Pure ASGI: do not buffer media, exports or SSE streams.
        await self.app(scope, receive, secure_send)
