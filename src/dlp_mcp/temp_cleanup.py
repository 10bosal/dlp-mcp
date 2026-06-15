from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from dlp_mcp.config import Settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CleanupResult:
    removed: list[str]
    errors: list[str]


def cleanup_expired_temp_files(settings: Settings) -> CleanupResult:
    """Delete temp files older than TEMP_TTL_SECONDS."""
    settings.temp_dir.mkdir(parents=True, exist_ok=True)

    now = time.time()
    removed: list[str] = []
    errors: list[str] = []

    for path in settings.temp_dir.iterdir():
        if not path.is_file():
            continue
        age = now - path.stat().st_mtime
        if age < settings.temp_ttl_seconds:
            continue
        try:
            path.unlink()
            removed.append(path.name)
        except OSError as exc:
            errors.append(f"{path.name}: {exc}")

    return CleanupResult(removed=removed, errors=errors)


async def temp_cleanup_worker(settings: Settings, stop: asyncio.Event) -> None:
    """Periodically remove expired files from the temp directory."""
    interval = settings.temp_cleanup_interval_seconds
    logger.info(
        "Temp cleanup worker started (interval=%ds, ttl=%ds, dir=%s)",
        interval,
        settings.temp_ttl_seconds,
        settings.temp_dir,
    )

    while not stop.is_set():
        result = cleanup_expired_temp_files(settings)
        if result.removed:
            logger.info("Auto-removed %d expired temp file(s)", len(result.removed))
        for error in result.errors:
            logger.warning("Temp cleanup error: %s", error)

        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue

    logger.info("Temp cleanup worker stopped")
