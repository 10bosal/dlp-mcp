from __future__ import annotations

import base64
import re
from urllib.parse import unquote, urlparse

import httpx


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


async def fetch_document_bytes(
    url: str,
    *,
    access_token: str | None = None,
) -> tuple[bytes, str | None]:
    """
    Download document bytes from a SharePoint, OneDrive, or HTTPS URL.

    When access_token is provided for an M365 URL, Microsoft Graph is used.
    """
    headers: dict[str, str] = {}
    fetch_url = url.strip()

    if access_token and is_m365_document_url(fetch_url):
        fetch_url = (
            "https://graph.microsoft.com/v1.0/shares/"
            f"{graph_share_id(fetch_url)}/driveItem/content"
        )
        headers["Authorization"] = f"Bearer {access_token}"
    else:
        fetch_url = normalize_document_url(fetch_url)

    try:
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
            response = await client.get(fetch_url, headers=headers)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise SharePointDownloadError(f"Failed to download document: {exc}") from exc

    filename = _filename_from_content_disposition(response.headers.get("content-disposition"))
    if not filename:
        filename = filename_from_url(str(response.url)) or filename_from_url(url)

    content = response.content
    if not content:
        raise SharePointDownloadError("Downloaded document is empty")

    return content, filename
