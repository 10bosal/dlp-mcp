from __future__ import annotations

import contextlib
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from dlp_mcp.config import Settings
from dlp_mcp.decrypt import (
    DecryptionError,
    decode_base64_payload,
    decrypt_aes_gcm,
    encode_base64,
)

logger = logging.getLogger(__name__)


def _transport_security() -> TransportSecuritySettings:
    default_hosts = "dlp-mcp.fly.dev,localhost,127.0.0.1"
    default_origins = "https://chatgpt.com,https://chat.openai.com,https://www.chatgpt.com"
    hosts = os.environ.get("MCP_ALLOWED_HOSTS", default_hosts)
    origins = os.environ.get("MCP_ALLOWED_ORIGINS", default_origins)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host.strip() for host in hosts.split(",") if host.strip()],
        allowed_origins=[origin.strip() for origin in origins.split(",") if origin.strip()],
    )


mcp = FastMCP(
    "DLP",
    instructions=(
        "Use decrypt_file to decrypt AES-GCM encrypted documents provided by the user. "
        "Pass encrypted_data_b64, filename, and mime_type when available."
    ),
    stateless_http=True,
    json_response=True,
    transport_security=_transport_security(),
)


def _load_settings() -> Settings:
    return Settings.from_env()


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
async def decrypt_file(
    encrypted_data_b64: str,
    filename: str = "decrypted.bin",
    mime_type: str | None = None,
    nonce_b64: str | None = None,
    associated_data_b64: str | None = None,
) -> dict[str, Any]:
    """
    Decrypt an AES-GCM encrypted file and return the plaintext for ChatGPT inference.

    Args:
        encrypted_data_b64: Base64-encoded encrypted file bytes.
            Default format: [12-byte nonce][ciphertext + auth tag].
        filename: Original filename (used for temp storage and response metadata).
        mime_type: Optional MIME type hint (e.g. text/plain, application/pdf).
        nonce_b64: Optional base64 nonce when not embedded in ciphertext.
        associated_data_b64: Optional base64 AAD for AES-GCM.

    Returns:
        Decrypted content as base64, temp file path, size, and metadata.
    """
    settings = _load_settings()

    try:
        ciphertext = decode_base64_payload(encrypted_data_b64)
    except DecryptionError as exc:
        return {"success": False, "error": str(exc)}

    max_bytes = settings.max_file_size_mb * 1024 * 1024
    if len(ciphertext) > max_bytes:
        return {
            "success": False,
            "error": f"Encrypted payload exceeds {settings.max_file_size_mb}MB limit",
        }

    nonce = decode_base64_payload(nonce_b64) if nonce_b64 else None
    aad = decode_base64_payload(associated_data_b64) if associated_data_b64 else None

    try:
        result = decrypt_aes_gcm(
            ciphertext=ciphertext,
            key=settings.decryption_key,
            nonce=nonce,
            associated_data=aad,
            filename=filename,
            mime_type=mime_type,
            temp_dir=settings.temp_dir,
        )
    except DecryptionError as exc:
        return {"success": False, "error": str(exc)}

    logger.info("Decrypted file saved to %s (%d bytes)", result.temp_path, len(result.plaintext))

    return {
        "success": True,
        "filename": result.filename,
        "mime_type": result.mime_type,
        "size_bytes": len(result.plaintext),
        "temp_path": str(result.temp_path),
        "expires_in_seconds": settings.temp_ttl_seconds,
        "content_b64": encode_base64(result.plaintext),
        "content_text": _maybe_decode_text(result.plaintext, result.mime_type),
    }


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
async def cleanup_temp_files() -> dict[str, Any]:
    """Remove expired temporary decrypted files from the server temp directory."""
    settings = _load_settings()
    settings.temp_dir.mkdir(parents=True, exist_ok=True)

    now = time.time()
    removed: list[str] = []
    errors: list[str] = []

    for path in settings.temp_dir.iterdir():
        if not path.is_file():
            continue
        age = now - path.stat().st_mtime
        if age < settings.temp_ttl_seconds:
            continue
        try:
            path.unlink()
            removed.append(path.name)
        except OSError as exc:
            errors.append(f"{path.name}: {exc}")

    return {"success": True, "removed": removed, "errors": errors}


def _maybe_decode_text(data: bytes, mime_type: str | None) -> str | None:
    if mime_type and not mime_type.startswith("text/"):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "healthy", "service": "dlp-mcp"})


def _verify_api_key(request: Request, settings: Settings) -> bool:
    if not settings.api_key:
        return True
    provided = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    return secrets_compare(provided, settings.api_key)


def secrets_compare(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a.encode(), b.encode())


@asynccontextmanager
async def lifespan(app: Starlette):
    settings = _load_settings()
    settings.temp_dir.mkdir(parents=True, exist_ok=True)
    logger.info("DLP MCP starting — temp_dir=%s", settings.temp_dir)
    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(mcp.session_manager.run())
        yield


def create_app() -> Starlette:
    settings = _load_settings()

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if request.url.path in ("/health",):
                return await call_next(request)
            if not _verify_api_key(request, settings):
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            return await call_next(request)

    app = Starlette(
        routes=[
            Route("/health", health),
            Mount("/", app=mcp.streamable_http_app()),
        ],
        lifespan=lifespan,
    )
    app.add_middleware(AuthMiddleware)
    return app


app = create_app()


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    port = int(__import__("os").environ.get("PORT", "8000"))
    uvicorn.run("dlp_mcp.server:app", host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
