"""test similar domains.

This file contains test helpers or manual checks for the Domain Intelligence
application. It is kept separate from the production application startup.
"""

from threading import Event
from unittest.mock import Mock

from core import ScanContext, ScanScope, ScanMode
from modules.similar_domain_generator import SimilarDomainGenerator
from modules.domain_similarity import DomainSimilarity
from modules.similar_domain_analyzer import SimilarDomainAnalyzer


def test_generator_creates_candidates():
    """Verify expected behavior for generator creates candidates.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    generator = SimilarDomainGenerator()
    results = generator.generate("example.com")

    assert len(results) > 0
    assert all(item["domain"] != "example.com" for item in results)


def test_generator_respects_limit():
    """Verify expected behavior for generator respects limit.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    generator = SimilarDomainGenerator(max_candidates=5)
    results = generator.generate("example.com")

    assert len(results) <= 5


def test_generator_removes_duplicates():
    """Verify expected behavior for generator removes duplicates.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    generator = SimilarDomainGenerator()
    results = generator.generate("example.com")

    domains = [item["domain"] for item in results]
    assert len(domains) == len(set(domains))


def test_similarity_score():
    """Verify expected behavior for similarity score.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    score = DomainSimilarity.calculate(
        "example.com",
        "examp1e.com",
    )

    assert 0 <= score <= 100
    assert score > 50


def test_similarity_classification():
    """Verify expected behavior for similarity classification.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    assert DomainSimilarity.classify(95) == "very_high"
    assert DomainSimilarity.classify(80) == "high"
    assert DomainSimilarity.classify(60) == "medium"
    assert DomainSimilarity.classify(30) == "low"


def test_analyzer_passive_scan():
    """Verify expected behavior for analyzer passive scan.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    rdap = Mock()
    rdap.get_domain.return_value = {
        "success": True,
        "data": {"name": "candidate.example"},
    }

    analyzer = SimilarDomainAnalyzer(
        max_candidates=5,
        max_rdap_lookups=2,
        rdap_service=rdap,
    )

    context = ScanContext(
        scan_id="test-id",
        domain="example.com",
        scope=ScanScope(
            root_domain="example.com",
            mode=ScanMode.PASSIVE,
        ),
        started_at="test",
    )

    result = analyzer.run(context, Event())

    assert result["original_domain"] == "example.com"
    assert result["total_generated"] > 0
    assert result["total_analyzed"] > 0
    assert len(result["results"]) == result["total_analyzed"]
    assert rdap.get_domain.call_count <= 2


def test_analyzer_rejects_authorized_mode():
    """Verify expected behavior for analyzer rejects authorized mode.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    analyzer = SimilarDomainAnalyzer(
        rdap_service=Mock(),
    )

    context = ScanContext(
        scan_id="test-id",
        domain="example.com",
        scope=ScanScope(
            root_domain="example.com",
            mode=ScanMode.AUTHORIZED,
            authorized_domains=["example.com"],
        ),
        started_at="test",
    )

    try:
        analyzer.run(context, Event())
        assert False, "Era attesa una PermissionError."
    except PermissionError:
        pass


def test_analyzer_handles_rdap_failure():
    """Verify expected behavior for analyzer handles rdap failure.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    rdap = Mock()
    rdap.get_domain.side_effect = Exception("Servizio non disponibile")

    analyzer = SimilarDomainAnalyzer(
        max_candidates=3,
        max_rdap_lookups=2,
        rdap_service=rdap,
    )

    context = ScanContext(
        scan_id="test-id",
        domain="example.com",
        scope=ScanScope(
            root_domain="example.com",
            mode=ScanMode.PASSIVE,
        ),
        started_at="test",
    )

    result = analyzer.run(context, Event())

    assert result["total_analyzed"] > 0
    assert all(
        item["rdap_status"] == "unknown"
        for item in result["results"]
        if item["rdap_status"] != "not_checked"
    )