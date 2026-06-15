from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AzureGraphSettings:
    tenant_id: str
    client_id: str
    client_secret: str


@dataclass(frozen=True)
class Settings:
    """Runtime configuration loaded from environment variables."""

    decryption_key: bytes
    temp_dir: Path
    api_key: str | None
    max_file_size_mb: int
    temp_ttl_seconds: int
    temp_cleanup_interval_seconds: int
    azure_graph: AzureGraphSettings | None

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

        tenant_id = os.environ.get("AZURE_TENANT_ID", "").strip()
        client_id = os.environ.get("AZURE_CLIENT_ID", "").strip()
        client_secret = os.environ.get("AZURE_CLIENT_SECRET", "").strip()
        azure_values = [tenant_id, client_id, client_secret]
        if any(azure_values) and not all(azure_values):
            raise ValueError(
                "AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET must all be set together"
            )
        azure_graph = (
            AzureGraphSettings(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
            if all(azure_values)
            else None
        )

        return cls(
            decryption_key=key,
            temp_dir=temp_dir,
            api_key=api_key,
            max_file_size_mb=int(os.environ.get("MAX_FILE_SIZE_MB", "50")),
            temp_ttl_seconds=int(os.environ.get("TEMP_TTL_SECONDS", "3600")),
            temp_cleanup_interval_seconds=int(
                os.environ.get("TEMP_CLEANUP_INTERVAL_SECONDS", "3600")
            ),
            azure_graph=azure_graph,
        )
