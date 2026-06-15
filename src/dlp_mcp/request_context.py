from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any

from starlette.requests import Request

_caller_context: ContextVar[dict[str, str] | None] = ContextVar("caller_context", default=None)


def _first_forwarded_ip(value: str) -> str:
    return value.split(",")[0].strip()


def extract_caller_info(request: Request) -> dict[str, str]:
    """Extract caller metadata from an HTTP request."""
    info: dict[str, str] = {}

    client_ip = request.headers.get("fly-client-ip")
    if not client_ip:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = _first_forwarded_ip(forwarded_for)
    if not client_ip:
        client_ip = request.headers.get("x-real-ip")
    if not client_ip and request.client is not None:
        client_ip = request.client.host
    if client_ip:
        info["client_ip"] = client_ip

    host = request.headers.get("host")
    if host:
        info["hostname"] = host.split(":", 1)[0]

    user_agent = request.headers.get("user-agent")
    if user_agent:
        info["user_agent"] = user_agent[:512]

    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        info["forwarded_for"] = forwarded_for[:512]

    info["request_method"] = request.method
    info["request_path"] = request.url.path
    return info


def bind_caller_info(info: dict[str, str]) -> Token[dict[str, str] | None]:
    return _caller_context.set(info)


def reset_caller_info(token: Token[dict[str, str] | None]) -> None:
    _caller_context.reset(token)


def current_caller_info() -> dict[str, str] | None:
    return _caller_context.get()


def audit_caller_fields() -> dict[str, Any]:
    caller = current_caller_info()
    if not caller:
        return {}
    return {"caller": caller}
