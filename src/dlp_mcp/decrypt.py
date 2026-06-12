from __future__ import annotations

import base64
import secrets
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree as ET

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class DecryptResult:
    """Result of a successful decryption."""

    plaintext: bytes
    filename: str
    mime_type: str | None
    temp_path: Path


class DecryptionError(Exception):
    """Raised when decryption fails."""


def decrypt_aes_gcm(
    *,
    ciphertext: bytes,
    key: bytes,
    nonce: bytes | None = None,
    associated_data: bytes | None = None,
    filename: str = "decrypted.bin",
    mime_type: str | None = None,
    temp_dir: Path,
) -> DecryptResult:
    """
    Decrypt AES-256-GCM encrypted data.

  File format (default):
    [12-byte nonce][ciphertext + 16-byte auth tag]

  Alternatively, pass `nonce` explicitly when ciphertext does not embed it.
    """
    if nonce is None:
        if len(ciphertext) < 12 + 16:
            raise DecryptionError("Ciphertext too short for embedded nonce format")
        nonce = ciphertext[:12]
        ciphertext = ciphertext[12:]

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:
        raise DecryptionError("Decryption failed — invalid key, nonce, or corrupted data") from exc

    temp_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename).name or "decrypted.bin"
    token = secrets.token_hex(8)
    temp_path = temp_dir / f"{token}_{safe_name}"
    temp_path.write_bytes(plaintext)

    return DecryptResult(
        plaintext=plaintext,
        filename=safe_name,
        mime_type=mime_type,
        temp_path=temp_path,
    )


def decode_base64_payload(data_b64: str) -> bytes:
    """Decode standard, URL-safe, or RFC 2397 data-URI base64 payload."""
    normalized = data_b64.strip()
    if normalized.startswith("data:"):
        marker = ";base64,"
        if marker not in normalized:
            raise DecryptionError("Unsupported data URI without base64 encoding")
        normalized = normalized.split(marker, 1)[1]

    padding = "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized + padding, validate=False)
    except Exception as exc:
        raise DecryptionError("Invalid base64 payload") from exc


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


_DOCX_NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def extract_docx_text(data: bytes) -> str | None:
    """Extract plain text from a .docx file without external dependencies."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            document_xml = archive.read("word/document.xml")
    except (KeyError, zipfile.BadZipFile, OSError):
        return None

    try:
        root = ET.fromstring(document_xml)
    except ET.ParseError:
        return None

    paragraphs: list[str] = []
    for paragraph in root.findall(".//w:p", _DOCX_NS):
        parts = [
            node.text
            for node in paragraph.findall(".//w:t", _DOCX_NS)
            if node.text
        ]
        if parts:
            paragraphs.append("".join(parts))

    text = "\n".join(paragraphs).strip()
    return text or None
