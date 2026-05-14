"""Shared test fixtures for the Anansi test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from anansi.db import crawl_db
from anansi.spider.queue import SQLiteQueue

CRAWL_ID = "test-crawl-0000"


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Per-test ephemeral SQLite database path (never touches ~/.anansi)."""
    return tmp_path / "test_crawls.db"


@pytest.fixture
def tmp_sel_db(tmp_path: Path) -> Path:
    """Per-test ephemeral selector database path."""
    return tmp_path / "test_selectors.db"


@pytest.fixture
async def queue(tmp_db: Path) -> SQLiteQueue:
    """SQLiteQueue pre-seeded with the required crawl FK row."""
    async with crawl_db(tmp_db) as db:
        await db.execute(
            "INSERT OR IGNORE INTO crawls (crawl_id, spider_name, state) VALUES (?, ?, ?)",
            (CRAWL_ID, "test", "running"),
        )
        await db.commit()
    return SQLiteQueue(CRAWL_ID, tmp_db, canonicalize=False)
