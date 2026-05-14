"""
Proxy manager with round-robin rotation and background health checking.

Supports HTTP, HTTPS, and SOCKS5 proxies. Dead proxies are quarantined
and periodically rechecked. Raises NoProxiesAvailable when the pool empties.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from enum import Enum
from typing import Any

import httpx

from anansi.security import redact_userinfo

logger = logging.getLogger(__name__)

_HEALTH_CHECK_URL = "https://httpbin.org/ip"
_HEALTH_TIMEOUT = 10.0
_QUARANTINE_RECHECK_SECS = 300  # 5 minutes


class NoProxiesAvailable(Exception):
    pass


class ProxyRotationStrategy(str, Enum):
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    LEAST_USED = "least_used"


class _ProxyEntry:
    __slots__ = ("url", "use_count", "fail_count", "last_fail", "quarantined_until")

    def __init__(self, url: str) -> None:
        self.url = url
        self.use_count = 0
        self.fail_count = 0
        self.last_fail: float = 0.0
        self.quarantined_until: float = 0.0

    @property
    def healthy(self) -> bool:
        return time.monotonic() >= self.quarantined_until


class ProxyManager:
    """
    Manages a pool of proxies with rotation, health checking, and auto-removal.

    Example::

        pm = ProxyManager([
            "http://user:pass@proxy1.example.com:8080",
            "socks5://user:pass@proxy2.example.com:1080",
        ])
        async with pm:
            proxy_url = pm.next()
            # ... use proxy_url with your fetcher
            pm.report_failure(proxy_url)
    """

    def __init__(
        self,
        proxies: list[str],
        *,
        strategy: ProxyRotationStrategy = ProxyRotationStrategy.ROUND_ROBIN,
        max_failures: int = 3,
        health_check_interval: float = 120.0,
        health_check_url: str = _HEALTH_CHECK_URL,
    ) -> None:
        if not proxies:
            raise ValueError("Proxy list cannot be empty")
        self._entries: dict[str, _ProxyEntry] = {
            url: _ProxyEntry(url) for url in proxies
        }
        self._queue: deque[str] = deque(proxies)
        self._strategy = strategy
        self._max_failures = max_failures
        self._health_interval = health_check_interval
        self._health_url = health_check_url
        self._lock = asyncio.Lock()
        self._health_task: asyncio.Task | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Begin background health-check loop."""
        if self._health_task is None or self._health_task.done():
            self._health_task = asyncio.create_task(self._health_loop())

    async def stop(self) -> None:
        if self._health_task and not self._health_task.done():
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass

    async def __aenter__(self) -> "ProxyManager":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # ── Core rotation ─────────────────────────────────────────────────────────

    def next(self) -> str:
        """Return the next healthy proxy URL."""
        healthy = [e for e in self._entries.values() if e.healthy]
        if not healthy:
            raise NoProxiesAvailable("All proxies are quarantined or exhausted")

        if self._strategy == ProxyRotationStrategy.RANDOM:
            entry = random.choice(healthy)
        elif self._strategy == ProxyRotationStrategy.LEAST_USED:
            entry = min(healthy, key=lambda e: e.use_count)
        else:  # ROUND_ROBIN
            # Pop from deque, skip quarantined, push back
            for _ in range(len(self._queue)):
                url = self._queue.popleft()
                self._queue.append(url)
                e = self._entries.get(url)
                if e and e.healthy:
                    entry = e
                    break
            else:
                raise NoProxiesAvailable("All proxies are quarantined")

        entry.use_count += 1
        return entry.url

    def report_success(self, proxy_url: str) -> None:
        """Signal that a request through *proxy_url* succeeded."""
        entry = self._entries.get(proxy_url)
        if entry:
            entry.fail_count = max(0, entry.fail_count - 1)
            entry.quarantined_until = 0.0

    def report_failure(self, proxy_url: str) -> None:
        """Signal that a request through *proxy_url* failed."""
        entry = self._entries.get(proxy_url)
        if not entry:
            return
        entry.fail_count += 1
        entry.last_fail = time.monotonic()
        if entry.fail_count >= self._max_failures:
            entry.quarantined_until = time.monotonic() + _QUARANTINE_RECHECK_SECS
            logger.warning("Proxy quarantined: %s (failures=%d)",
                           redact_userinfo(proxy_url), entry.fail_count)

    def add(self, proxy_url: str) -> None:
        """Dynamically add a proxy to the pool."""
        if proxy_url not in self._entries:
            self._entries[proxy_url] = _ProxyEntry(proxy_url)
            self._queue.append(proxy_url)

    def remove(self, proxy_url: str) -> None:
        """Permanently remove a proxy from the pool."""
        self._entries.pop(proxy_url, None)
        try:
            self._queue.remove(proxy_url)
        except ValueError:
            pass

    @property
    def healthy_count(self) -> int:
        return sum(1 for e in self._entries.values() if e.healthy)

    @property
    def total_count(self) -> int:
        return len(self._entries)

    def stats(self) -> list[dict[str, Any]]:
        return [
            {
                "url": redact_userinfo(e.url),
                "healthy": e.healthy,
                "use_count": e.use_count,
                "fail_count": e.fail_count,
            }
            for e in self._entries.values()
        ]

    # ── Health check loop ─────────────────────────────────────────────────────

    async def _health_loop(self) -> None:
        while True:
            await asyncio.sleep(self._health_interval)
            await self._check_all()

    async def _check_all(self) -> None:
        tasks = [
            asyncio.create_task(self._check_one(entry))
            for entry in self._entries.values()
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_one(self, entry: _ProxyEntry) -> None:
        try:
            transport = httpx.AsyncHTTPTransport(proxy=entry.url)
            async with httpx.AsyncClient(
                transport=transport,
                timeout=_HEALTH_TIMEOUT,
            ) as client:
                resp = await client.get(self._health_url)
                if resp.status_code == 200:
                    if not entry.healthy:
                        logger.info("Proxy recovered: %s", redact_userinfo(entry.url))
                    entry.fail_count = 0
                    entry.quarantined_until = 0.0
                else:
                    self.report_failure(entry.url)
        except Exception:
            self.report_failure(entry.url)
