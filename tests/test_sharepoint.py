import os

import pytest

from dlp_mcp.sharepoint import (
    graph_share_id,
    is_m365_document_url,
    normalize_document_url,
)


def test_is_m365_document_url():
    assert is_m365_document_url("https://contoso.sharepoint.com/:w:/g/personal/user/file")
    assert is_m365_document_url("https://contoso-my.sharepoint.com/personal/user/doc.docx")
    assert not is_m365_document_url("https://example.com/file.enc")


def test_normalize_sharepoint_url_adds_download_flag():
    url = "https://contoso.sharepoint.com/sites/demo/Shared%20Documents/file_enc.docx"
    normalized = normalize_document_url(url)
    assert "download=1" in normalized


def test_graph_share_id_is_stable():
    url = "https://contoso.sharepoint.com/:w:/g/personal/user/abc"
    assert graph_share_id(url).startswith("u!")
