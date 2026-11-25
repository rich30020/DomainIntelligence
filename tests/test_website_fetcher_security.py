"""test website fetcher security.

This file contains test helpers or manual checks for the Domain Intelligence
application. It is kept separate from the production application startup.
"""

import pytest

from modules.website_fetcher import WebsiteFetcher


def test_website_fetcher_rejects_url_instead_of_domain():
    """Verify expected behavior for website fetcher rejects url instead of domain.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    fetcher = WebsiteFetcher()
    with pytest.raises(ValueError):
        fetcher.fetch("https://example.com/path")


def test_website_fetcher_rejects_private_dns(monkeypatch):
    """Verify expected behavior for website fetcher rejects private dns.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    monkeypatch.setattr(
        "modules.website_fetcher.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("127.0.0.1", 443))
        ],
    )
    with pytest.raises(ValueError, match="non pubblico"):
        WebsiteFetcher.validate_public_dns("example.test")
