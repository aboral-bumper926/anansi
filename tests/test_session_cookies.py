"""Tests for HTTPFetcher session cookie persistence across requests."""

from __future__ import annotations

import httpx
import pytest
import respx

from anansi.fetchers.http import HTTPFetcher


async def test_set_cookie_persisted_to_next_request() -> None:
    """Cookie from Set-Cookie response header should be sent on the next request."""
    received_cookies: list[str] = []

    with respx.mock:
        # First request sets a session cookie
        respx.get("https://example.com/login").mock(
            return_value=httpx.Response(
                200,
                text="logged in",
                headers={"Set-Cookie": "session=abc123; Path=/"},
            )
        )

        # Second request — capture whatever cookie header is sent
        def capture(request: httpx.Request) -> httpx.Response:
            received_cookies.append(request.headers.get("cookie", ""))
            return httpx.Response(200, text="profile")

        respx.get("https://example.com/profile").mock(side_effect=capture)

        async with HTTPFetcher() as fetcher:
            await fetcher.fetch("https://example.com/login")
            await fetcher.fetch("https://example.com/profile")

    assert received_cookies, "Second request was never made"
    assert "session=abc123" in received_cookies[0], (
        f"Session cookie not sent on second request; got: {received_cookies[0]!r}"
    )


async def test_constructor_cookies_sent_on_first_request() -> None:
    """Cookies passed to HTTPFetcher() constructor must be sent from the first request."""
    received_cookies: list[str] = []

    with respx.mock:
        def capture(request: httpx.Request) -> httpx.Response:
            received_cookies.append(request.headers.get("cookie", ""))
            return httpx.Response(200, text="ok")

        respx.get("https://example.com/").mock(side_effect=capture)

        async with HTTPFetcher(cookies={"auth": "token123"}) as fetcher:
            await fetcher.fetch("https://example.com/")

    assert "auth=token123" in received_cookies[0]


async def test_proxy_request_does_not_corrupt_session_jar() -> None:
    """Cookies set via a proxy request should accumulate in session_cookies but not
    overwrite the persistent client's jar in a harmful way for non-proxy requests."""
    with respx.mock:
        respx.get("https://example.com/data").mock(
            return_value=httpx.Response(
                200,
                text="ok",
                headers={"Set-Cookie": "x=1; Path=/"},
            )
        )

        async with HTTPFetcher() as fetcher:
            # Proxy request — should not raise
            result = await fetcher.fetch("https://example.com/data", proxy="http://proxy:8080")

        assert result.status == 200
        # session_cookies should have accumulated the cookie
        assert fetcher._session_cookies.get("x") == "1"


async def test_multiple_set_cookies_all_accumulated() -> None:
    with respx.mock:
        respx.get("https://example.com/a").mock(
            return_value=httpx.Response(
                200, text="ok",
                headers={"Set-Cookie": "k1=v1; Path=/"},
            )
        )
        respx.get("https://example.com/b").mock(
            return_value=httpx.Response(
                200, text="ok",
                headers={"Set-Cookie": "k2=v2; Path=/"},
            )
        )

        async with HTTPFetcher() as fetcher:
            await fetcher.fetch("https://example.com/a")
            await fetcher.fetch("https://example.com/b")

        assert fetcher._session_cookies["k1"] == "v1"
        assert fetcher._session_cookies["k2"] == "v2"
