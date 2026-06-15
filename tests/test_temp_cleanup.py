import asyncio
import os
import time

import pytest

from dlp_mcp.config import Settings
from dlp_mcp.temp_cleanup import cleanup_expired_temp_files, temp_cleanup_worker


@pytest.fixture
def settings(tmp_path, monkeypatch) -> Settings:
    monkeypatch.setenv("DECRYPTION_KEY_HEX", "00" * 32)
    monkeypatch.setenv("TEMP_DIR", str(tmp_path))
    monkeypatch.setenv("TEMP_TTL_SECONDS", "60")
    monkeypatch.setenv("TEMP_CLEANUP_INTERVAL_SECONDS", "1")
    return Settings.from_env()


def test_cleanup_expired_temp_files_removes_old_files(settings: Settings):
    fresh = settings.temp_dir / "fresh.bin"
    stale = settings.temp_dir / "stale.bin"
    fresh.write_bytes(b"new")
    stale.write_bytes(b"old")

    old = time.time() - 120
    os.utime(stale, (old, old))

    result = cleanup_expired_temp_files(settings)

    assert result.removed == ["stale.bin"]
    assert result.errors == []
    assert fresh.is_file()
    assert not stale.exists()


def test_cleanup_expired_temp_files_keeps_recent_files(settings: Settings):
    recent = settings.temp_dir / "recent.bin"
    recent.write_bytes(b"data")

    result = cleanup_expired_temp_files(settings)

    assert result.removed == []
    assert recent.is_file()


@pytest.mark.asyncio
async def test_temp_cleanup_worker_runs_until_stopped(settings: Settings):
    stale = settings.temp_dir / "stale.bin"
    stale.write_bytes(b"old")
    old = time.time() - 120
    os.utime(stale, (old, old))

    stop = asyncio.Event()
    task = asyncio.create_task(temp_cleanup_worker(settings, stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert not stale.exists()
