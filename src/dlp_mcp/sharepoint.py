from __future__ import annotations

import base64
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse

import httpx

if TYPE_CHECKING:
    from dlp_mcp.config import AzureGraphSettings

_CLIENT_CREDENTIALS_CACHE: tuple[str, float] | None = None


class SharePointDownloadError(Exception):
    """Raised when a SharePoint or document URL cannot be fetched."""


def graph_share_id(url: str) -> str:
    """Encode a sharing URL for Microsoft Graph /shares/{shareId}/driveItem/content."""
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    return f"u!{encoded}"


def is_m365_document_url(url: str) -> bool:
    lowered = url.lower()
    return any(
        host in lowered
        for host in (
            "sharepoint.com",
            "1drv.ms",
            "onedrive.live.com",
            "microsoft.com",
        )
    )


def normalize_document_url(url: str) -> str:
    """Best-effort conversion of M365 sharing links to direct download URLs."""
    normalized = url.strip()
    parsed = urlparse(normalized)
    host = parsed.netloc.lower()

    if "1drv.ms" in host or "onedrive.live.com" in host:
        return normalized

    if "sharepoint.com" not in host:
        return normalized

    if "download.aspx" in normalized or "download=1" in normalized:
        return normalized

    separator = "&" if parsed.query else "?"
    return f"{normalized}{separator}download=1"


def filename_from_url(url: str) -> str | None:
    path = unquote(urlparse(url).path)
    candidate = path.rsplit("/", 1)[-1]
    if candidate and "." in candidate and not candidate.startswith(":"):
        return candidate
    return None


def _filename_from_content_disposition(header: str | None) -> str | None:
    if not header:
        return None
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', header, re.IGNORECASE)
    if not match:
        return None
    return unquote(match.group(1).strip())


def m365_auth_required_message(url: str, status_code: int | None = None) -> str:
    host = urlparse(url).netloc or "SharePoint"
    status_hint = f"{status_code} " if status_code else ""
    return (
        f"{host} requires Microsoft Graph authentication ({status_hint}private M365 link). "
        "The DLP MCP server does not have Azure credentials configured yet. "
        "An administrator must set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET "
        "on fly.io with Graph application permissions Sites.Read.All or Files.Read.All. "
        "Until then, upload the *_enc* file in ChatGPT and call decrypt_file with encrypted_file, "
        "or ask ChatGPT SharePoint connector to fetch the file first and bind it to encrypted_file."
    )


async def fetch_client_credentials_token(azure: AzureGraphSettings) -> str:
    global _CLIENT_CREDENTIALS_CACHE

    now = time.time()
    if _CLIENT_CREDENTIALS_CACHE and _CLIENT_CREDENTIALS_CACHE[1] > now:
        return _CLIENT_CREDENTIALS_CACHE[0]

    token_url = f"https://login.microsoftonline.com/{azure.tenant_id}/oauth2/v2.0/token"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                token_url,
                data={
                    "client_id": azure.client_id,
                    "client_secret": azure.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError as exc:
        raise SharePointDownloadError(f"Failed to acquire Microsoft Graph token: {exc}") from exc

    token = payload.get("access_token")
    if not token:
        raise SharePointDownloadError("Microsoft Graph token response did not include access_token")

    expires_in = int(payload.get("expires_in", 3600))
    _CLIENT_CREDENTIALS_CACHE = (token, now + max(expires_in - 120, 60))
    return token


async def resolve_graph_access_token(
    *,
    explicit_token: str | None = None,
    azure: AzureGraphSettings | None = None,
) -> str | None:
    if explicit_token:
        return explicit_token

    try:
        from mcp.server.auth.middleware.auth_context import get_access_token

        oauth_token = get_access_token()
        if oauth_token is not None:
            return oauth_token.token
    except Exception:
        pass

    if azure is not None:
        return await fetch_client_credentials_token(azure)

    return None


def _graph_content_url(url: str) -> str:
    return (
        "https://graph.microsoft.com/v1.0/shares/"
        f"{graph_share_id(url)}/driveItem/content"
    )


async def fetch_document_bytes(
    url: str,
    *,
    access_token: str | None = None,
    azure: AzureGraphSettings | None = None,
) -> tuple[bytes, str | None]:
    """
    Download document bytes from a SharePoint, OneDrive, or HTTPS URL.

    M365 sharing links use Microsoft Graph when a token is available from the tool
    argument, MCP OAuth context, or configured Azure application credentials.
    """
    fetch_url = url.strip()
    graph_token = await resolve_graph_access_token(explicit_token=access_token, azure=azure)

    if is_m365_document_url(fetch_url) and not graph_token:
        raise SharePointDownloadError(m365_auth_required_message(fetch_url))

    try:
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
            if is_m365_document_url(fetch_url) and graph_token:
                response = await client.get(
                    _graph_content_url(fetch_url),
                    headers={"Authorization": f"Bearer {graph_token}"},
                )
            else:
                response = await client.get(fetch_url)

            if response.status_code in (401, 403) and is_m365_document_url(fetch_url):
                raise SharePointDownloadError(
                    m365_auth_required_message(fetch_url, response.status_code)
                )

            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if is_m365_document_url(fetch_url) and status in (401, 403):
            raise SharePointDownloadError(
                m365_auth_required_message(fetch_url, status)
            ) from exc
        raise SharePointDownloadError(f"Failed to download document: {exc}") from exc
    except httpx.HTTPError as exc:
        raise SharePointDownloadError(f"Failed to download document: {exc}") from exc

    filename = _filename_from_content_disposition(response.headers.get("content-disposition"))
    if not filename:
        filename = filename_from_url(str(response.url)) or filename_from_url(url)

    content = response.content
    if not content:
        raise SharePointDownloadError("Downloaded document is empty")

    return content, filename
