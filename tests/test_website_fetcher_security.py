import pytest

from modules.website_fetcher import WebsiteFetcher


def test_website_fetcher_rejects_url_instead_of_domain():
    fetcher = WebsiteFetcher()
    with pytest.raises(ValueError):
        fetcher.fetch("https://example.com/path")


def test_website_fetcher_rejects_private_dns(monkeypatch):
    monkeypatch.setattr(
        "modules.website_fetcher.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("127.0.0.1", 443))
        ],
    )
    with pytest.raises(ValueError, match="non pubblico"):
        WebsiteFetcher.validate_public_dns("example.test")
