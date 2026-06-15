from starlette.requests import Request

from dlp_mcp.request_context import (
    audit_caller_fields,
    bind_caller_info,
    current_caller_info,
    extract_caller_info,
    reset_caller_info,
)


def _make_request(
    *,
    path: str = "/mcp",
    headers: list[tuple[bytes, bytes]] | None = None,
    client: tuple[str, int] = ("198.51.100.10", 12345),
) -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "scheme": "https",
        "query_string": b"",
        "headers": headers or [],
        "client": client,
        "server": ("dlp-mcp.fly.dev", 443),
    }
    return Request(scope)


def test_extract_caller_info_prefers_fly_client_ip():
    request = _make_request(
        headers=[
            (b"host", b"dlp-mcp.fly.dev"),
            (b"fly-client-ip", b"203.0.113.7"),
            (b"x-forwarded-for", b"10.0.0.1, 203.0.113.7"),
            (b"user-agent", b"ChatGPT-User"),
        ]
    )
    info = extract_caller_info(request)
    assert info["client_ip"] == "203.0.113.7"
    assert info["hostname"] == "dlp-mcp.fly.dev"
    assert info["user_agent"] == "ChatGPT-User"
    assert info["forwarded_for"] == "10.0.0.1, 203.0.113.7"
    assert info["request_method"] == "POST"
    assert info["request_path"] == "/mcp"


def test_extract_caller_info_falls_back_to_socket_client():
    request = _make_request(headers=[(b"host", b"localhost:8000")])
    info = extract_caller_info(request)
    assert info["client_ip"] == "198.51.100.10"
    assert info["hostname"] == "localhost"


def test_caller_context_binding():
    assert current_caller_info() is None
    token = bind_caller_info({"client_ip": "203.0.113.1", "hostname": "example.com"})
    try:
        assert current_caller_info() == {
            "client_ip": "203.0.113.1",
            "hostname": "example.com",
        }
        assert audit_caller_fields() == {
            "caller": {
                "client_ip": "203.0.113.1",
                "hostname": "example.com",
            }
        }
    finally:
        reset_caller_info(token)
    assert current_caller_info() is None
