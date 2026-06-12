from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Runtime configuration loaded from environment variables."""

    decryption_key: bytes
    temp_dir: Path
    api_key: str | None
    max_file_size_mb: int
    temp_ttl_seconds: int

    @classmethod
    def from_env(cls) -> Settings:
        key_hex = os.environ.get("DECRYPTION_KEY_HEX", "").strip()
        if not key_hex:
            raise ValueError("DECRYPTION_KEY_HEX environment variable is required")

        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise ValueError("DECRYPTION_KEY_HEX must be a valid hex string") from exc

        if len(key) not in (16, 24, 32):
            raise ValueError("DECRYPTION_KEY_HEX must decode to 16, 24, or 32 bytes (AES key)")

        temp_dir = Path(os.environ.get("TEMP_DIR", "/tmp/dlp-mcp"))
        api_key = os.environ.get("MCP_API_KEY") or None

        return cls(
            decryption_key=key,
            temp_dir=temp_dir,
            api_key=api_key,
            max_file_size_mb=int(os.environ.get("MAX_FILE_SIZE_MB", "50")),
            temp_ttl_seconds=int(os.environ.get("TEMP_TTL_SECONDS", "3600")),
        )
