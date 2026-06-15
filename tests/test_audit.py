import asyncio
import base64
import os
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dlp_mcp.audit import AuditLog, get_audit_log, new_audit_record, utc_now_iso
from dlp_mcp.config import Settings
from dlp_mcp.request_context import bind_caller_info, reset_caller_info
from dlp_mcp.server import cleanup_temp_files, decrypt_file, query_audit_logs


@pytest.fixture
def aes_key(monkeypatch, tmp_path) -> bytes:
    key = os.urandom(32)
    monkeypatch.setenv("DECRYPTION_KEY_HEX", key.hex())
    monkeypatch.setenv("TEMP_DIR", str(tmp_path / "temp"))
    monkeypatch.setenv("AUDIT_DIR", str(tmp_path / "audit"))
    return key


def test_audit_log_append_and_query(tmp_path):
    log_path = tmp_path / "audit" / "audit.jsonl"
    audit = AuditLog(log_path)
    audit.append(
        new_audit_record(
            action="decrypt_file",
            success=True,
            encrypted_filename="report_enc.docx",
            size_bytes=5,
        )
    )
    audit.append(
        new_audit_record(
            action="cleanup_temp_files",
            success=True,
            removed_files=["old.bin"],
        )
    )

    entries, total = audit.query(action="decrypt_file")
    assert total == 1
    assert entries[0]["encrypted_filename"] == "report_enc.docx"
    assert entries[0]["size_bytes"] == 5


def test_audit_log_filters_by_filename_and_time(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(log_path)
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    audit.append(
        new_audit_record(
            action="decrypt_file",
            success=True,
            encrypted_filename="old_enc.txt",
        )
    )
    # overwrite timestamp for filter test
    entries = audit._load_entries()
    entries[0]["timestamp"] = old_ts
    log_path.write_text(
        "\n".join(__import__("json").dumps(entry) for entry in entries) + "\n",
        encoding="utf-8",
    )

    audit.append(
        new_audit_record(
            action="decrypt_file",
            success=True,
            encrypted_filename="new_enc.txt",
            size_bytes=5,
        )
    )

    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    entries, total = audit.query(encrypted_filename="new_enc", since=since)
    assert total == 1
    assert entries[0]["encrypted_filename"] == "new_enc.txt"


def test_audit_cleanup_expired(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    audit = AuditLog(log_path)
    old_ts = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    audit.append(
        new_audit_record(
            action="decrypt_file",
            success=True,
            encrypted_filename="stale.txt",
        )
    )
    entries = audit._load_entries()
    entries[0]["timestamp"] = old_ts
    log_path.write_text(
        "\n".join(__import__("json").dumps(entry) for entry in entries) + "\n",
        encoding="utf-8",
    )
    audit.append(
        new_audit_record(
            action="decrypt_file",
            success=True,
            encrypted_filename="fresh.txt",
        )
    )

    removed = audit.cleanup_expired(30 * 24 * 3600)
    assert removed == 1
    entries, total = audit.query()
    assert total == 1
    assert entries[0]["encrypted_filename"] == "fresh.txt"


def test_decrypt_file_writes_audit(aes_key):
    plaintext = b"audit me"
    nonce = os.urandom(12)
    encrypted = nonce + AESGCM(aes_key).encrypt(nonce, plaintext, None)

    token = bind_caller_info(
        {
            "client_ip": "203.0.113.42",
            "hostname": "chatgpt.example",
            "user_agent": "TestAgent/1.0",
            "request_method": "POST",
            "request_path": "/mcp",
        }
    )
    try:
        result = asyncio.run(
            decrypt_file(
                encrypted_data_b64=base64.b64encode(encrypted).decode(),
                filename="sample_enc.txt",
                mime_type="text/plain",
            )
        )
    finally:
        reset_caller_info(token)
    assert result["success"] is True

    settings = Settings.from_env()
    entries, total = get_audit_log(settings).query(action="decrypt_file")
    assert total == 1
    assert entries[0]["encrypted_filename"] == "sample_enc.txt"
    assert entries[0]["success"] is True
    assert "content_text" not in entries[0]
    assert entries[0]["caller"]["client_ip"] == "203.0.113.42"
    assert entries[0]["caller"]["hostname"] == "chatgpt.example"
    assert "timestamp" in entries[0]
    assert "duration_ms" in entries[0]


def test_query_audit_logs_mcp_action(aes_key):
    asyncio.run(decrypt_file())
    result = asyncio.run(query_audit_logs(action="decrypt_file"))
    assert result["success"] is True
    assert result["total"] >= 1
    assert any(entry["action"] == "decrypt_file" for entry in result["entries"])

    query_entries, _ = get_audit_log(Settings.from_env()).query(action="query_audit_logs")
    assert len(query_entries) >= 1


def test_cleanup_temp_files_writes_audit(aes_key, tmp_path, monkeypatch):
    monkeypatch.setenv("TEMP_DIR", str(tmp_path / "temp"))
    monkeypatch.setenv("AUDIT_DIR", str(tmp_path / "audit"))
    stale = tmp_path / "temp" / "stale.bin"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"x")
    old = time.time() - 7200
    os.utime(stale, (old, old))

    result = asyncio.run(cleanup_temp_files())
    assert result["success"] is True
    assert "stale.bin" in result["removed"]

    settings = Settings.from_env()
    entries, total = get_audit_log(settings).query(action="cleanup_temp_files")
    assert total == 1
    assert entries[0]["removed_files"] == ["stale.bin"]
