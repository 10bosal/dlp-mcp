from __future__ import annotations

import contextlib
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route

from dlp_mcp.config import Settings
from dlp_mcp.sharepoint import SharePointDownloadError, fetch_document_bytes
from dlp_mcp.decrypt import (
    DecryptionError,
    decode_base64_payload,
    decrypt_aes_gcm,
    encode_base64,
    extract_docx_text,
    extract_pdf_text,
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
        "Use decrypt_file when the user uploads an encrypted document as encrypted_file. "
        "Use decrypt_sharepoint_file when the user provides a SharePoint, OneDrive, or M365 document link. "
        "Read answers from content_text when present."
    ),
    stateless_http=True,
    json_response=True,
    transport_security=_transport_security(),
)


class EncryptedFileRef(BaseModel):
    """ChatGPT file reference for an uploaded encrypted document."""

    model_config = ConfigDict(extra="ignore")

    download_url: str
    file_id: str
    mime_type: str | None = None
    file_name: str | None = None


def _load_settings() -> Settings:
    return Settings.from_env()


def _public_base_url() -> str:
    return os.environ.get("PUBLIC_BASE_URL", "https://dlp-mcp.fly.dev").rstrip("/")


def _guess_mime_type(filename: str, mime_type: str | None) -> str | None:
    if mime_type:
        return mime_type
    ext = os.path.splitext(filename)[1].lower()
    return {
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".pdf": "application/pdf",
        ".txt": "text/plain",
    }.get(ext)


def _extract_readable_text(data: bytes, filename: str, mime_type: str | None) -> str | None:
    text = _maybe_decode_text(data, mime_type)
    if text is not None:
        return text
    if filename.lower().endswith(".docx") or (mime_type or "").endswith("wordprocessingml.document"):
        return extract_docx_text(data)
    if filename.lower().endswith(".pdf") or (mime_type or "") == "application/pdf":
        return extract_pdf_text(data)
    return None


async def _load_encrypted_bytes(
    encrypted_file: EncryptedFileRef | None,
    encrypted_data_b64: str | None,
) -> bytes:
    if encrypted_file is not None:
        content, _ = await fetch_document_bytes(encrypted_file.download_url)
        return content

    if encrypted_data_b64:
        return decode_base64_payload(encrypted_data_b64)

    raise DecryptionError(
        "Provide encrypted_file for uploaded documents or encrypted_data_b64 for inline ciphertext"
    )


def _format_decrypt_result(result, settings: Settings) -> dict[str, Any]:
    resolved_mime = _guess_mime_type(result.filename, result.mime_type)
    file_id = result.temp_path.name
    download_url = f"{_public_base_url()}/files/{file_id}"
    content_text = _extract_readable_text(result.plaintext, result.filename, resolved_mime)

    return {
        "success": True,
        "filename": result.filename,
        "mime_type": resolved_mime,
        "size_bytes": len(result.plaintext),
        "expires_in_seconds": settings.temp_ttl_seconds,
        "content_b64": encode_base64(result.plaintext),
        "content_text": content_text,
        "download_url": download_url,
        "file_uri": {
            "download_url": download_url,
            "file_id": file_id,
            "mime_type": resolved_mime,
            "file_name": result.filename,
        },
        "message": (
            "Decryption succeeded. Use content_text for document body. "
            "If content_text is empty, fetch file_uri.download_url for the decrypted file."
        ),
    }


async def _decrypt_ciphertext(
    *,
    settings: Settings,
    ciphertext: bytes,
    filename: str,
    mime_type: str | None,
    nonce_b64: str | None = None,
    associated_data_b64: str | None = None,
) -> dict[str, Any]:
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
    return _format_decrypt_result(result, settings)


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
    meta={"openai/fileParams": ["encrypted_file"]},
)
async def decrypt_file(
    encrypted_file: EncryptedFileRef | None = None,
    encrypted_data_b64: str | None = None,
    filename: str = "decrypted.bin",
    mime_type: str | None = None,
    nonce_b64: str | None = None,
    associated_data_b64: str | None = None,
) -> dict[str, Any]:
    """
    Decrypt an AES-GCM encrypted file and return the plaintext for ChatGPT inference.

    Use this when the user uploads an encrypted document (.enc or encrypted .docx).
    Pass the uploaded file as encrypted_file. Do not pass local file paths.

    Encrypted format: [12-byte nonce][ciphertext + 16-byte auth tag].
  """
    settings = _load_settings()

    if encrypted_file is not None:
        if not filename or filename == "decrypted.bin":
            filename = encrypted_file.file_name or filename
        if mime_type is None:
            mime_type = encrypted_file.mime_type

    try:
        ciphertext = await _load_encrypted_bytes(encrypted_file, encrypted_data_b64)
    except (DecryptionError, SharePointDownloadError, httpx.HTTPError) as exc:
        return {"success": False, "error": str(exc)}

    return await _decrypt_ciphertext(
        settings=settings,
        ciphertext=ciphertext,
        filename=filename,
        mime_type=mime_type,
        nonce_b64=nonce_b64,
        associated_data_b64=associated_data_b64,
    )


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
async def decrypt_sharepoint_file(
    document_url: str,
    filename: str | None = None,
    mime_type: str | None = None,
    access_token: str | None = None,
    nonce_b64: str | None = None,
    associated_data_b64: str | None = None,
) -> dict[str, Any]:
    """
    Decrypt an AES-GCM encrypted document downloaded from SharePoint, OneDrive, or M365.

    Use this when the user provides a SharePoint or Microsoft 365 document link.
    Do not use this for files uploaded directly in ChatGPT; use decrypt_file instead.

    Encrypted format: [12-byte nonce][ciphertext + 16-byte auth tag].
    """
    settings = _load_settings()

    try:
        ciphertext, detected_name = await fetch_document_bytes(
            document_url,
            access_token=access_token,
        )
    except SharePointDownloadError as exc:
        return {"success": False, "error": str(exc)}

    resolved_filename = filename or detected_name or "decrypted.bin"
    return await _decrypt_ciphertext(
        settings=settings,
        ciphertext=ciphertext,
        filename=resolved_filename,
        mime_type=mime_type,
        nonce_b64=nonce_b64,
        associated_data_b64=associated_data_b64,
    )


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


async def download_decrypted_file(request: Request) -> Response:
    settings = _load_settings()
    file_id = request.path_params["file_id"]
    if not file_id or "/" in file_id or ".." in file_id:
        return JSONResponse({"error": "Not found"}, status_code=404)

    path = settings.temp_dir / file_id
    if not path.is_file():
        return JSONResponse({"error": "Not found"}, status_code=404)

    age = time.time() - path.stat().st_mtime
    if age > settings.temp_ttl_seconds:
        return JSONResponse({"error": "Expired"}, status_code=410)

    filename = path.name.split("_", 1)[-1] if "_" in path.name else path.name
    media_type = _guess_mime_type(filename, None) or "application/octet-stream"
    return FileResponse(path, filename=filename, media_type=media_type)


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
            if request.url.path in ("/health",) or request.url.path.startswith("/files/"):
                return await call_next(request)
            if not _verify_api_key(request, settings):
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            return await call_next(request)

    app = Starlette(
        routes=[
            Route("/health", health),
            Route("/files/{file_id}", download_decrypted_file, methods=["GET"]),
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
