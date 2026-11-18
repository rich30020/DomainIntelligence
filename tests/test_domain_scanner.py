
from threading import Event
from unittest.mock import Mock

from core import (
    ScannerEngine,
    ScanRequest,
    ScanScope,
    ScanMode,
)

from modules.domain_scanner import DomainScanner


def create_scanner():

    scanner = DomainScanner()

    scanner.rdap_service.get_domain_info = Mock(
        return_value={
            "success": True,
            "status": "found"
        }
    )

    scanner.dns_analyzer.analyze = Mock(
        return_value={
            "domain": "example.com",
            "records": {
                "A": ["192.0.2.1"]
            }
        }
    )

    return scanner


def test_domain_scanner():

    engine = ScannerEngine()

    scanner = create_scanner()

    engine.register_module(scanner)

    scope = ScanScope(
        root_domain="example.com",
        mode=ScanMode.PASSIVE
    )

    request = ScanRequest(
        domain="example.com",
        scope=scope
    )

    result = engine.run_scan(request)

    assert result.status == "completed"
    assert len(result.results) == 1

    data = result.results[0].data

    assert data["validation"]["success"] is True
    assert data["rdap"]["success"] is True
    assert data["dns"]["domain"] == "example.com"
    assert data["certificate"]["status"] == "skipped"


def test_domain_normalization():

    scanner = DomainScanner()

    result = scanner.normalize_domain(
        " EXAMPLE.COM. "
    )

    assert result == "example.com"


def test_invalid_domain():

    scanner = DomainScanner()

    assert scanner.validate_domain(
        "invalid_domain"
    ) is False


def test_cancelled_scan():

    scanner = create_scanner()

    event = Event()
    event.set()

    from core.scanner_engine import ScanContext

    context = ScanContext(
        scan_id="test-id",
        domain="example.com",
        scope=ScanScope(
            root_domain="example.com",
            mode=ScanMode.PASSIVE
        ),
        started_at="test"
    )

    result = scanner.run(context, event)

    assert result["rdap"] == {}
    assert result["dns"] == {}
