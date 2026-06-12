import base64
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dlp_mcp.decrypt import decrypt_aes_gcm, encode_base64


@pytest.fixture
def aes_key() -> bytes:
    return os.urandom(32)


def _encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def test_decrypt_embedded_nonce(tmp_path, aes_key):
    plaintext = b"hello dlp-mcp"
    encrypted = _encrypt(aes_key, plaintext)

    result = decrypt_aes_gcm(
        ciphertext=encrypted,
        key=aes_key,
        filename="test.txt",
        mime_type="text/plain",
        temp_dir=tmp_path,
    )

    assert result.plaintext == plaintext
    assert result.temp_path.exists()
    assert result.temp_path.read_bytes() == plaintext


def test_decrypt_with_external_nonce(tmp_path, aes_key):
    plaintext = b"external nonce test"
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    result = decrypt_aes_gcm(
        ciphertext=ciphertext,
        key=aes_key,
        nonce=nonce,
        filename="out.bin",
        temp_dir=tmp_path,
    )

    assert result.plaintext == plaintext


def test_roundtrip_base64(aes_key):
    plaintext = b"base64 roundtrip"
    encrypted = _encrypt(aes_key, plaintext)
    encoded = encode_base64(encrypted)
    decoded = base64.b64decode(encoded)
    assert decoded == encrypted
