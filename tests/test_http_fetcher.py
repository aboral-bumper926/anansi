"""Tests for HTTPFetcher."""

from __future__ import annotations

import httpx
import pytest
import respx

from anansi.fetchers.http import HTTPFetcher


@pytest.fixture
def fetcher() -> HTTPFetcher:
    return HTTPFetcher(max_retries=2, timeout=5.0)


async def test_successful_fetch(fetcher: HTTPFetcher) -> None:
    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="<html><body>hello</body></html>")
        )
        result = await fetcher.fetch("https://example.com/")

    assert result.status == 200
    assert result.ok is True
    assert "hello" in result.html
    assert result.via_browser is False


async def test_404_not_retried(fetcher: HTTPFetcher) -> None:
    call_count = 0

    with respx.mock:
        def handler(request):
            nonlocal call_count
            call_count += 1
            return httpx.Response(404, text="Not found")

        respx.get("https://example.com/missing").mock(side_effect=handler)
        result = await fetcher.fetch("https://example.com/missing")

    assert result.status == 404
    assert call_count == 1  # no retries for 404


async def test_503_is_retried(fetcher: HTTPFetcher) -> None:
    """503 should be retried; returns 200 on second attempt."""
    responses = [
        httpx.Response(503, text="Service Unavailable"),
        httpx.Response(200, text="<html>ok</html>"),
    ]

    with respx.mock:
        respx.get("https://example.com/retry").mock(side_effect=responses)
        result = await fetcher.fetch("https://example.com/retry")

    assert result.status == 200


async def test_proxy_kwarg_accepted(fetcher: HTTPFetcher) -> None:
    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="ok")
        )
        # Should not raise even when proxy is passed
        result = await fetcher.fetch("https://example.com/", proxy="http://proxy:8080")

    assert result.status == 200


async def test_fetch_result_includes_headers(fetcher: HTTPFetcher) -> None:
    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(
                200,
                text="ok",
                headers={"etag": '"abc123"', "content-type": "text/html"},
            )
        )
        result = await fetcher.fetch("https://example.com/")

    assert result.headers.get("etag") == '"abc123"'
