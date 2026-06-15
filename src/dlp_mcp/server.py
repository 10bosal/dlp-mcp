from __future__ import annotations

import asyncio
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
from dlp_mcp.temp_cleanup import cleanup_expired_temp_files, temp_cleanup_worker
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
    "DLP Decrypt",
    instructions=(
        "Always invoke decrypt_file when the user asks to decrypt a DLP *_enc* file. "
        "Do not claim the tool is missing until decrypt_file has been called in this chat. "
        "The decryption key is on the server; never ask the user for a password. "
        "Files named *_enc* are AES-GCM ciphertext, not Office password protection. "
        "Preferred inputs: (1) encrypted_file for chat or SharePoint-fetched files, "
        "(2) document_url using the SharePoint link from the user's message. "
        "After decrypt_file succeeds, summarize content_text."
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


def _normalize_file_dict(value: dict[str, Any]) -> dict[str, Any]:
    aliases = {
        "fileId": "file_id",
        "downloadUrl": "download_url",
        "fileName": "file_name",
        "mimeType": "mime_type",
    }
    normalized = dict(value)
    for src, dest in aliases.items():
        if src in normalized and dest not in normalized:
            normalized[dest] = normalized[src]
    return normalized


def _coerce_encrypted_file(value: EncryptedFileRef | dict[str, Any] | str | None) -> EncryptedFileRef | None:
    if value is None:
        return None
    if isinstance(value, EncryptedFileRef):
        return value
    if isinstance(value, str):
        raise DecryptionError(
            "encrypted_file was not attached by ChatGPT. Re-run decrypt_file and bind the chat file "
            "to encrypted_file, or pass document_url with the SharePoint link from the user message."
        )
    if isinstance(value, dict):
        normalized = _normalize_file_dict(value)
        if normalized.get("file_id") and not normalized.get("download_url"):
            raise DecryptionError(
                "encrypted_file is missing download_url. Re-run decrypt_file with the chat file "
                "bound to encrypted_file, or pass document_url with the SharePoint link."
            )
        return EncryptedFileRef.model_validate(normalized)
    raise DecryptionError(f"Unsupported encrypted_file type: {type(value).__name__}")


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
    *,
    settings: Settings,
    encrypted_file: EncryptedFileRef | dict[str, Any] | str | None = None,
    document_url: str | None = None,
    encrypted_data_b64: str | None = None,
    access_token: str | None = None,
) -> tuple[bytes, str | None]:
    file_ref = _coerce_encrypted_file(encrypted_file)
    azure = settings.azure_graph
    if file_ref is not None:
        content, detected_name = await fetch_document_bytes(
            file_ref.download_url,
            azure=azure,
        )
        return content, detected_name or file_ref.file_name

    if document_url:
        content, detected_name = await fetch_document_bytes(
            document_url,
            access_token=access_token,
            azure=azure,
        )
        return content, detected_name

    if encrypted_data_b64:
        return decode_base64_payload(encrypted_data_b64), None

    raise DecryptionError(
        "Provide encrypted_file for chat attachments, document_url for SharePoint/M365 links, "
        "or encrypted_data_b64 for inline ciphertext"
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


_DECRYPT_FILE_DESCRIPTION = (
    "Decrypt DLP AES-256-GCM encrypted documents (for example *_enc.docx). "
    "Server-side key; never ask the user for a password. "
    "Call this tool when a SharePoint *_enc* file is already in chat (encrypted_file) "
    "or when the user provided a SharePoint/M365 link (document_url)."
)


@mcp.tool(
    title="Decrypt DLP encrypted file",
    description=_DECRYPT_FILE_DESCRIPTION,
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True),
    meta={
        "openai/fileParams": ["encrypted_file"],
        "openai/toolInvocation/invoking": "DLP 문서 복호화 중…",
        "openai/toolInvocation/invoked": "복호화 완료",
    },
)
async def decrypt_file(
    encrypted_file: EncryptedFileRef | None = None,
    document_url: str | None = None,
    encrypted_data_b64: str | None = None,
    filename: str = "decrypted.bin",
    mime_type: str | None = None,
    access_token: str | None = None,
    nonce_b64: str | None = None,
    associated_data_b64: str | None = None,
) -> dict[str, Any]:
    """
    Decrypt a DLP AES-GCM encrypted file and return plaintext for inference.

    Input (provide exactly one):
    - encrypted_file: chat upload or SharePoint-fetched encrypted file
    - document_url: SharePoint, OneDrive, or M365 link to encrypted file
    - encrypted_data_b64: inline base64 ciphertext

    Format: [12-byte nonce][ciphertext + 16-byte auth tag]. No user password required.
    """
    settings = _load_settings()
    file_ref = _coerce_encrypted_file(encrypted_file)

    if file_ref is not None:
        if not filename or filename == "decrypted.bin":
            filename = file_ref.file_name or filename
        if mime_type is None:
            mime_type = file_ref.mime_type

    if not file_ref and not document_url and not encrypted_data_b64:
        return {
            "success": False,
            "error": (
                "No input provided. Pass encrypted_file for a chat/SharePoint file, "
                "or document_url with the SharePoint link from the user message."
            ),
        }

    logger.info(
        "decrypt_file called (encrypted_file=%s, document_url=%s, filename=%s)",
        bool(file_ref),
        bool(document_url),
        filename,
    )

    try:
        ciphertext, detected_name = await _load_encrypted_bytes(
            settings=settings,
            encrypted_file=encrypted_file,
            document_url=document_url,
            encrypted_data_b64=encrypted_data_b64,
            access_token=access_token,
        )
    except (DecryptionError, SharePointDownloadError, httpx.HTTPError) as exc:
        return {"success": False, "error": str(exc)}

    resolved_filename = filename
    if resolved_filename == "decrypted.bin" and detected_name:
        resolved_filename = detected_name

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
    result = cleanup_expired_temp_files(settings)
    return {"success": True, "removed": result.removed, "errors": result.errors}


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

    stop_cleanup = asyncio.Event()
    cleanup_task = asyncio.create_task(temp_cleanup_worker(settings, stop_cleanup))

    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(mcp.session_manager.run())
        try:
            yield
        finally:
            stop_cleanup.set()
            cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cleanup_task


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
