import asyncio
import base64
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dlp_mcp.decrypt import DecryptionError, decode_base64_payload, extract_docx_text
from dlp_mcp.server import EncryptedFileRef, decrypt_file, decrypt_sharepoint_file


@pytest.fixture
def aes_key(monkeypatch) -> bytes:
    key = os.urandom(32)
    monkeypatch.setenv("DECRYPTION_KEY_HEX", key.hex())
    return key


def test_decode_data_uri_base64():
    payload = b"cipher-bytes"
    encoded = base64.b64encode(payload).decode()
    data_uri = f"data:application/octet-stream;name=test.enc;base64,{encoded}"
    assert decode_base64_payload(data_uri) == payload


def test_decrypt_file_with_inline_base64(aes_key, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP_DIR", str(tmp_path))
    plaintext = b"hello via base64"
    nonce = os.urandom(12)
    encrypted = nonce + AESGCM(aes_key).encrypt(nonce, plaintext, None)

    result = asyncio.run(
        decrypt_file(
            encrypted_data_b64=base64.b64encode(encrypted).decode(),
            filename="test.txt",
            mime_type="text/plain",
        )
    )

    assert result["success"] is True
    assert result["content_text"] == "hello via base64"


@patch("dlp_mcp.server.fetch_document_bytes", new_callable=AsyncMock)
def test_decrypt_file_with_uploaded_file_ref(mock_fetch, aes_key, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP_DIR", str(tmp_path))
    plaintext = b"hello via file ref"
    nonce = os.urandom(12)
    encrypted = nonce + AESGCM(aes_key).encrypt(nonce, plaintext, None)
    mock_fetch.return_value = (encrypted, "sample.txt")

    result = asyncio.run(
        decrypt_file(
            encrypted_file=EncryptedFileRef(
                download_url="https://files.example/answers.enc",
                file_id="file_test",
                file_name="sample.txt",
                mime_type="text/plain",
            ),
        )
    )

    assert result["success"] is True
    assert result["content_text"] == "hello via file ref"
    assert result["download_url"].startswith("https://")
    assert result["file_uri"]["file_name"] == "sample.txt"


@patch("dlp_mcp.server.fetch_document_bytes", new_callable=AsyncMock)
def test_decrypt_sharepoint_file(mock_fetch, aes_key, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP_DIR", str(tmp_path))
    plaintext = b"hello sharepoint"
    nonce = os.urandom(12)
    encrypted = nonce + AESGCM(aes_key).encrypt(nonce, plaintext, None)
    mock_fetch.return_value = (encrypted, "answers_enc.docx")

    result = asyncio.run(
        decrypt_sharepoint_file(
            document_url="https://contoso.sharepoint.com/sites/demo/answers_enc.docx",
            filename="answers.docx",
            mime_type="text/plain",
        )
    )

    assert result["success"] is True
    assert result["content_text"] == "hello sharepoint"
    mock_fetch.assert_awaited_once()


@patch("dlp_mcp.server.fetch_document_bytes", new_callable=AsyncMock)
def test_decrypt_file_with_document_url(mock_fetch, aes_key, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP_DIR", str(tmp_path))
    plaintext = b"hello via sharepoint url"
    nonce = os.urandom(12)
    encrypted = nonce + AESGCM(aes_key).encrypt(nonce, plaintext, None)
    mock_fetch.return_value = (encrypted, "report_enc.txt")

    result = asyncio.run(
        decrypt_file(
            document_url="https://contoso.sharepoint.com/sites/demo/report_enc.txt",
        )
    )

    assert result["success"] is True
    assert result["content_text"] == "hello via sharepoint url"
    assert result["filename"] == "report_enc.txt"


def test_coerce_encrypted_file_rejects_bare_file_id():
    with pytest.raises(DecryptionError, match="download_url"):
        from dlp_mcp.server import _coerce_encrypted_file

        _coerce_encrypted_file({"file_id": "file-abc"})


def test_extract_docx_text_from_decrypted_file():
    docx_path = Path(__file__).resolve().parents[2] / "dlp-encrypt/tests/answers.docx"
    if not docx_path.is_file():
        pytest.skip("answers.docx not available")

    text = extract_docx_text(docx_path.read_bytes())
    assert text
    assert "3.14" in text
