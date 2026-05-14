"""
Arachne — The spider that learns.

Adaptive web scraping framework with self-healing selectors,
anti-bot bypass, concurrent crawling, and MCP server integration.
"""

from anansi.core import Crawler, Spider, Request, Response, Item
from anansi.fetchers.http import HTTPFetcher
from anansi.fetchers.browser import BrowserFetcher
from anansi.fetchers.smart import needs_browser
from anansi.parser.adaptive import AdaptiveParser
from anansi.proxy.manager import ProxyManager

__version__ = "0.1.0"
__all__ = [
    "Crawler",
    "Spider",
    "Request",
    "Response",
    "Item",
    "HTTPFetcher",
    "BrowserFetcher",
    "needs_browser",
    "AdaptiveParser",
    "ProxyManager",
]
