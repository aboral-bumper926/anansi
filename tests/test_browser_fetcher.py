"""Tests for BrowserFetcher pool bounding and close() correctness."""

from __future__ import annotations

import asyncio

import pytest

from anansi.fetchers.browser import BrowserFetcher


class _MockContext:
    """Minimal browser context stub that tracks close() calls."""

    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True


async def test_context_pool_is_bounded() -> None:
    """Pool maxsize should equal max_contexts; QueueFull is raised (not silently dropped)."""
    fetcher = BrowserFetcher(max_contexts=2)
    # Initialize the pool manually without starting Playwright
    fetcher._context_pool = asyncio.Queue(maxsize=fetcher._max_contexts)

    ctx_a = _MockContext()
    ctx_b = _MockContext()
    ctx_c = _MockContext()

    t_a = (ctx_a, 0.0, 0)
    t_b = (ctx_b, 0.0, 0)
    t_c = (ctx_c, 0.0, 0)

    fetcher._context_pool.put_nowait(t_a)
    fetcher._context_pool.put_nowait(t_b)

    with pytest.raises(asyncio.QueueFull):
        fetcher._context_pool.put_nowait(t_c)  # pool is full


async def test_close_drains_pool_without_error() -> None:
    """close() must unpack (ctx, created_at) tuples and call ctx.close(), not tuple.close()."""
    fetcher = BrowserFetcher(max_contexts=3)
    fetcher._context_pool = asyncio.Queue(maxsize=3)
    fetcher._browser = None
    fetcher._playwright = None

    ctx_a = _MockContext()
    ctx_b = _MockContext()
    fetcher._context_pool.put_nowait((ctx_a, 1000.0, 5))
    fetcher._context_pool.put_nowait((ctx_b, 1001.0, 0))

    # Should not raise AttributeError ("tuple has no attribute close")
    await fetcher.close()

    assert ctx_a.closed
    assert ctx_b.closed
    assert fetcher._context_pool.empty()


async def test_close_with_empty_pool_does_not_raise() -> None:
    fetcher = BrowserFetcher()
    fetcher._context_pool = asyncio.Queue(maxsize=5)
    fetcher._browser = None
    fetcher._playwright = None
    await fetcher.close()  # must not raise
