"""test website clone.

This file contains test helpers or manual checks for the Domain Intelligence
application. It is kept separate from the production application startup.
"""

from threading import Event
from unittest.mock import Mock

import pytest

from core import ScanContext, ScanScope, ScanMode
from modules.website_parser import WebsiteParser
from modules.website_similarity import WebsiteSimilarity
from modules.website_clone_analyzer import WebsiteCloneAnalyzer


HTML_A = """
<html>
<head>
    <title>Example Company</title>
    <meta name="description" content="Official company website">
    <meta property="og:site_name" content="Example Company">
    <link rel="icon" href="/favicon.ico">
</head>
<body>
    <img src="/logo.png" alt="Company Logo">
    <h1>Welcome</h1>
</body>
</html>
"""

HTML_B = """
<html>
<head>
    <title>Example Company</title>
    <meta name="description" content="Official company website">
    <meta property="og:site_name" content="Example Company">
    <link rel="icon" href="/favicon.ico">
</head>
<body>
    <img src="/logo.png" alt="Company Logo">
    <h1>Welcome</h1>
</body>
</html>
"""


def test_website_parser_extracts_metadata():
    """Verify expected behavior for website parser extracts metadata.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    parser = WebsiteParser()

    result = parser.parse(
        HTML_A,
        "https://example.com/",
    )

    assert result["title"] == "Example Company"
    assert result["description"] == "Official company website"
    assert result["site_name"] == "Example Company"
    assert result["favicon"] == "https://example.com/favicon.ico"
    assert "https://example.com/logo.png" in result["logo_candidates"]


def test_website_parser_ignores_unsafe_image_reference():
    """Verify expected behavior for website parser ignores unsafe image reference.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    parser = WebsiteParser()

    html = """
    <html>
        <body>
            <img src="javascript:alert(1)" alt="Company Logo">
        </body>
    </html>
    """

    result = parser.parse(html, "https://example.com/")

    assert result["logo_candidates"] == []


def test_website_similarity_identical_pages():
    """Verify expected behavior for website similarity identical pages.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    parser = WebsiteParser()
    similarity = WebsiteSimilarity()

    first = parser.parse(HTML_A, "https://example.com/")
    second = parser.parse(HTML_B, "https://example.net/")

    result = similarity.compare(first, second)

    assert result["score"] == 100
    assert result["level"] == "very_high"


def test_website_similarity_missing_fields():
    """Verify expected behavior for website similarity missing fields.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    similarity = WebsiteSimilarity()

    result = similarity.compare(
        {"title": "Example"},
        {"title": "Example"},
    )

    assert result["score"] == 100
    assert result["available_fields"] == 1


def test_analyzer_requires_authorized_mode():
    """Verify expected behavior for analyzer requires authorized mode.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    analyzer = WebsiteCloneAnalyzer(fetcher=Mock())

    context = ScanContext(
        scan_id="test-id",
        domain="example.com",
        scope=ScanScope(
            root_domain="example.com",
            mode=ScanMode.PASSIVE,
        ),
        started_at="test",
    )

    with pytest.raises(PermissionError):
        analyzer.run(context, Event())


def test_analyzer_requires_both_domains_authorized():
    """Verify expected behavior for analyzer requires both domains authorized.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    fetcher = Mock()
    analyzer = WebsiteCloneAnalyzer(fetcher=fetcher)

    context = ScanContext(
        scan_id="test-id",
        domain="example.com",
        scope=ScanScope(
            root_domain="example.com",
            mode=ScanMode.AUTHORIZED,
            authorized_domains=["example.com"],
        ),
        started_at="test",
        metadata={"comparison_domain": "example.net"},
    )

    with pytest.raises(PermissionError):
        analyzer.run(context, Event())

    fetcher.fetch.assert_not_called()


def test_analyzer_compares_two_authorized_domains():
    """Verify expected behavior for analyzer compares two authorized domains.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    fetcher = Mock()
    fetcher.fetch.side_effect = [
        {
            "domain": "example.com",
            "url": "https://example.com/",
            "html": HTML_A,
        },
        {
            "domain": "example.net",
            "url": "https://example.net/",
            "html": HTML_B,
        },
    ]

    analyzer = WebsiteCloneAnalyzer(fetcher=fetcher)

    context = ScanContext(
        scan_id="test-id",
        domain="example.com",
        scope=ScanScope(
            root_domain="example.com",
            mode=ScanMode.AUTHORIZED,
            authorized_domains=[
                "example.com",
                "example.net",
            ],
        ),
        started_at="test",
        metadata={"comparison_domain": "example.net"},
    )

    result = analyzer.run(context, Event())

    assert result["original_domain"] == "example.com"
    assert result["comparison_domain"] == "example.net"
    assert result["similarity"]["score"] == 100
    assert fetcher.fetch.call_count == 2