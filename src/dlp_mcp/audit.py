from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dlp_mcp.config import Settings

logger = logging.getLogger(__name__)

_lock = threading.Lock()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class AuditRecord:
    id: str
    timestamp: str
    action: str
    success: bool
    encrypted_filename: str | None = None
    decrypted_filename: str | None = None
    input_source: str | None = None
    document_url: str | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    error: str | None = None
    removed_files: list[str] | None = None
    errors: list[str] | None = None
    duration_ms: float | None = None
    caller: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


def new_audit_record(
    *,
    action: str,
    success: bool,
    **fields: Any,
) -> AuditRecord:
    return AuditRecord(
        id=str(uuid.uuid4()),
        timestamp=utc_now_iso(),
        action=action,
        success=success,
        **fields,
    )


class AuditLog:
    def __init__(self, path: Path):
        self.path = path

    def ensure_ready(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: AuditRecord) -> AuditRecord:
        self.ensure_ready()
        line = json.dumps(record.to_dict(), ensure_ascii=False) + "\n"
        with _lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        logger.info(
            "AUDIT action=%s success=%s encrypted_filename=%s decrypted_filename=%s "
            "client_ip=%s hostname=%s id=%s",
            record.action,
            record.success,
            record.encrypted_filename,
            record.decrypted_filename,
            (record.caller or {}).get("client_ip"),
            (record.caller or {}).get("hostname"),
            record.id,
        )
        return record

    def _load_entries(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        entries: list[dict[str, Any]] = []
        with _lock:
            text = self.path.read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("Skipping malformed audit log line")
        return entries

    def query(
        self,
        *,
        action: str | None = None,
        encrypted_filename: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        entries = self._load_entries()
        entries.sort(key=lambda item: item.get("timestamp", ""), reverse=True)

        filtered: list[dict[str, Any]] = []
        filename_needle = encrypted_filename.casefold() if encrypted_filename else None
        for entry in entries:
            if action and entry.get("action") != action:
                continue
            if filename_needle:
                candidate = str(entry.get("encrypted_filename") or "").casefold()
                if filename_needle not in candidate:
                    continue
            timestamp = entry.get("timestamp")
            if since and isinstance(timestamp, str) and timestamp < since:
                continue
            if until and isinstance(timestamp, str) and timestamp > until:
                continue
            filtered.append(entry)

        total = len(filtered)
        start = max(offset, 0)
        end = start + max(min(limit, 200), 1)
        return filtered[start:end], total

    def cleanup_expired(self, retention_seconds: int) -> int:
        if retention_seconds <= 0 or not self.path.is_file():
            return 0

        cutoff = datetime.now(timezone.utc).timestamp() - retention_seconds
        kept: list[dict[str, Any]] = []
        removed = 0
        for entry in self._load_entries():
            timestamp = entry.get("timestamp")
            if not isinstance(timestamp, str):
                removed += 1
                continue
            try:
                entry_time = datetime.fromisoformat(timestamp).timestamp()
            except ValueError:
                removed += 1
                continue
            if entry_time < cutoff:
                removed += 1
            else:
                kept.append(entry)

        if removed:
            self.ensure_ready()
            with _lock:
                with self.path.open("w", encoding="utf-8") as handle:
                    for entry in kept:
                        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return removed


def get_audit_log(settings: Settings) -> AuditLog:
    return AuditLog(settings.audit_log_path)
