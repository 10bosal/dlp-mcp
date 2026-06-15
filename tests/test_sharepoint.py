import pytest
from unittest.mock import AsyncMock, patch

import httpx

from dlp_mcp.config import AzureGraphSettings, Settings
from dlp_mcp.sharepoint import (
    SharePointDownloadError,
    fetch_client_credentials_token,
    fetch_document_bytes,
    graph_share_id,
    is_m365_document_url,
    m365_auth_required_message,
    normalize_document_url,
)


def test_is_m365_document_url():
    assert is_m365_document_url("https://contoso.sharepoint.com/:w:/g/personal/user/file")
    assert is_m365_document_url("https://skax.sharepoint.com/:w:/s/SKAX/IQB0l7mI73")
    assert is_m365_document_url("https://contoso-my.sharepoint.com/personal/user/doc.docx")
    assert not is_m365_document_url("https://example.com/file.enc")


def test_normalize_sharepoint_url_adds_download_flag():
    url = "https://contoso.sharepoint.com/sites/demo/Shared%20Documents/file_enc.docx"
    normalized = normalize_document_url(url)
    assert "download=1" in normalized


def test_graph_share_id_is_stable():
    url = "https://contoso.sharepoint.com/:w:/g/personal/user/abc"
    assert graph_share_id(url).startswith("u!")


def test_m365_auth_required_message_mentions_graph_setup():
    url = "https://skax.sharepoint.com/:w:/s/SKAX/doc"
    message = m365_auth_required_message(url, 403)
    assert "403" in message
    assert "AZURE_TENANT_ID" in message
    assert "encrypted_file" in message


@pytest.mark.asyncio
async def test_fetch_document_bytes_uses_graph_when_token_available():
    azure = AzureGraphSettings(
        tenant_id="tenant",
        client_id="client",
        client_secret="secret",
    )
    share_url = "https://skax.sharepoint.com/:w:/s/SKAX/file_enc.docx?e=abc"

    with patch(
        "dlp_mcp.sharepoint.resolve_graph_access_token",
        new_callable=AsyncMock,
        return_value="graph-token",
    ) as mock_resolve:
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_response = httpx.Response(
                200,
                content=b"encrypted-bytes",
                headers={"content-disposition": 'attachment; filename="file_enc.docx"'},
                request=httpx.Request("GET", "https://graph.microsoft.com"),
            )
            mock_get.return_value = mock_response

            content, filename = await fetch_document_bytes(share_url, azure=azure)

    assert content == b"encrypted-bytes"
    assert filename == "file_enc.docx"
    mock_resolve.assert_awaited_once()
    called_url = mock_get.await_args.args[0]
    assert called_url.startswith("https://graph.microsoft.com/v1.0/shares/u!")
    assert mock_get.await_args.kwargs["headers"]["Authorization"] == "Bearer graph-token"


@pytest.mark.asyncio
async def test_fetch_document_bytes_403_returns_actionable_error():
    share_url = "https://skax.sharepoint.com/:w:/s/SKAX/file_enc.docx?e=abc"

    with patch(
        "dlp_mcp.sharepoint.resolve_graph_access_token",
        new_callable=AsyncMock,
        return_value=None,
    ):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_response = httpx.Response(
                403,
                request=httpx.Request("GET", share_url),
            )
            mock_get.return_value = mock_response

            with pytest.raises(SharePointDownloadError, match="403 Forbidden"):
                await fetch_document_bytes(share_url)


@pytest.mark.asyncio
async def test_fetch_client_credentials_token_caches_result():
    azure = AzureGraphSettings(
        tenant_id="tenant",
        client_id="client",
        client_secret="secret",
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = httpx.Response(
            200,
            json={"access_token": "token-1", "expires_in": 3600},
            request=httpx.Request("POST", "https://login.microsoftonline.com"),
        )

        first = await fetch_client_credentials_token(azure)
        second = await fetch_client_credentials_token(azure)

    assert first == "token-1"
    assert second == "token-1"
    mock_post.assert_awaited_once()


def test_settings_requires_all_azure_values(monkeypatch):
    monkeypatch.setenv("DECRYPTION_KEY_HEX", "00" * 32)
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")

    with pytest.raises(ValueError, match="AZURE_TENANT_ID"):
        Settings.from_env()
