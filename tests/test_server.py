import asyncio
import base64
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dlp_mcp.decrypt import decode_base64_payload
from dlp_mcp.server import EncryptedFileRef, decrypt_file


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


@patch("dlp_mcp.server.httpx.AsyncClient")
def test_decrypt_file_with_uploaded_file_ref(mock_client_cls, aes_key, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP_DIR", str(tmp_path))
    plaintext = b"hello via file ref"
    nonce = os.urandom(12)
    encrypted = nonce + AESGCM(aes_key).encrypt(nonce, plaintext, None)

    mock_client = AsyncMock()
    mock_client_cls.return_value.__aenter__.return_value = mock_client
    mock_response = MagicMock()
    mock_response.content = encrypted
    mock_response.raise_for_status = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_response)

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
