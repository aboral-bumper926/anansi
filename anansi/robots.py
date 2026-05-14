"""Async robots.txt cache — one RobotFileParser per domain origin, 1-hour TTL."""

from __future__ import annotations

import time
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser


class RobotsCache:
    """
    Fetches and caches robots.txt per domain. Thread-safe for async use.

    On fetch error or non-200 response, assumes all URLs are allowed so
    scraping is not silently blocked by transient network issues.
    """

    def __init__(self, user_agent: str = "*", ttl: float = 3600.0) -> None:
        self._cache: dict[str, tuple[RobotFileParser, float]] = {}
        self._ua = user_agent
        self._ttl = ttl

    async def allowed(self, url: str) -> bool:
        """Return True if robots.txt permits fetching *url*."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        now = time.monotonic()

        cached = self._cache.get(origin)
        if cached and now < cached[1]:
            return cached[0].can_fetch(self._ua, url)

        robots_url = urljoin(origin, "/robots.txt")
        rp = RobotFileParser(robots_url)
        try:
            from anansi.fetchers.http import HTTPFetcher
            async with HTTPFetcher(timeout=10.0, max_retries=1) as f:
                result = await f.fetch(robots_url)
            if result.status == 200:
                rp.parse(result.html.splitlines())
        except Exception:
            pass  # assume allowed if robots.txt is unreachable

        self._cache[origin] = (rp, now + self._ttl)
        return rp.can_fetch(self._ua, url)

    async def crawl_delay(self, url: str) -> float | None:
        """Return the Crawl-delay for url's domain from robots.txt, or None."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        now = time.monotonic()
        cached = self._cache.get(origin)
        if not (cached and now < cached[1]):
            await self.allowed(url)  # populates cache as side effect
            cached = self._cache.get(origin)
        if not cached:
            return None
        rp = cached[0]
        delay = rp.crawl_delay(self._ua)
        if delay is None:
            delay = rp.crawl_delay("*")  # fall back to wildcard agent
        return float(delay) if delay is not None else None
