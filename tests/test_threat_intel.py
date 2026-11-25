"""test threat intel.

This file contains test helpers or manual checks for the Domain Intelligence
application. It is kept separate from the production application startup.
"""

from threading import Event

from core import ScanContext, ScanScope, ScanMode
from services.threat_intel_store import ThreatIntelStore
from modules.threat_intel_analyzer import ThreatIntelAnalyzer


def create_test_feed(tmp_path):
    csv_path = tmp_path / "test_iocs.csv"

    csv_path.write_text(
        "indicator,type,source,confidence,first_seen,last_seen,description\n"
        "bad-example.test,domain,TestFeed,95,2026-01-01,2026-02-01,Test IOC\n"
        "suspicious-example.test,domain,TestFeed,70,,,Second IOC\n",
        encoding="utf-8",
    )

    return csv_path


def test_import_csv(tmp_path):
    """Verify expected behavior for import csv.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    store = ThreatIntelStore()
    csv_path = create_test_feed(tmp_path)

    result = store.import_csv(str(csv_path))

    assert result["imported"] == 2
    assert result["rejected"] == 0
    assert result["total"] == 2


def test_reject_invalid_domain(tmp_path):
    """Verify expected behavior for reject invalid domain.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    csv_path = tmp_path / "invalid.csv"

    csv_path.write_text(
        "indicator,type,source,confidence\n"
        "bad domain,domain,TestFeed,90\n",
        encoding="utf-8",
    )

    store = ThreatIntelStore()
    result = store.import_csv(str(csv_path))

    assert result["imported"] == 0
    assert result["rejected"] == 1


def test_exact_domain_match(tmp_path):
    """Verify expected behavior for exact domain match.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    store = ThreatIntelStore()
    store.import_csv(str(create_test_feed(tmp_path)))

    analyzer = ThreatIntelAnalyzer(store)

    result = analyzer.analyze_domain("bad-example.test")

    assert result["matched"] is True
    assert result["threat_score"] == 95
    assert result["threat_level"] == "critical"
    assert result["matches"][0]["match_type"] == "exact"


def test_subdomain_match(tmp_path):
    """Verify expected behavior for subdomain match.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    store = ThreatIntelStore()
    store.import_csv(str(create_test_feed(tmp_path)))

    analyzer = ThreatIntelAnalyzer(store)

    result = analyzer.analyze_domain(
        "login.bad-example.test"
    )

    assert result["matched"] is True
    assert result["matches"][0]["match_type"] == "subdomain"


def test_domain_boundary_protection(tmp_path):
    """Verify expected behavior for domain boundary protection.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    store = ThreatIntelStore()
    store.import_csv(str(create_test_feed(tmp_path)))

    analyzer = ThreatIntelAnalyzer(store)

    result = analyzer.analyze_domain(
        "notbad-example.test"
    )

    assert result["matched"] is False
    assert result["threat_score"] == 0


def test_analyzer_run(tmp_path):
    """Verify expected behavior for analyzer run.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    store = ThreatIntelStore()
    store.import_csv(str(create_test_feed(tmp_path)))

    analyzer = ThreatIntelAnalyzer(store)

    context = ScanContext(
        scan_id="test-id",
        domain="bad-example.test",
        scope=ScanScope(
            root_domain="bad-example.test",
            mode=ScanMode.PASSIVE,
        ),
        started_at="test",
    )

    result = analyzer.run(context, Event())

    assert result["total_analyzed"] == 1
    assert result["total_matches"] == 1
    assert result["results"][0]["matched"] is True