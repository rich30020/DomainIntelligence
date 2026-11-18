from types import SimpleNamespace

import pytest

from services.database_service import DatabaseService


def create_fake_scan():
    subdomain_data = {
        "root_domain": "example.test",
        "total_discovered": 2,
        "subdomains": [
            {
                "hostname": "www.example.test",
                "sources": ["crtsh"],
                "ip_addresses": ["192.0.2.10"],
                "status": "resolved",
            },
            {
                "hostname": "mail.example.test",
                "sources": ["otx"],
                "ip_addresses": [],
                "status": "unresolved",
            },
        ],
    }

    threat_data = {
        "total_analyzed": 1,
        "total_matches": 1,
        "results": [
            {
                "domain": "bad-example.test",
                "matched": True,
                "threat_score": 95,
                "threat_level": "critical",
                "matches": [
                    {
                        "source": "TestFeed",
                        "confidence": 95,
                    }
                ],
            }
        ],
    }

    module_results = [
        SimpleNamespace(
            module_name="subdomain_finder",
            success=True,
            error=None,
            completed_at="2026-11-18T12:00:00",
            data=subdomain_data,
        ),
        SimpleNamespace(
            module_name="threat_intel_analyzer",
            success=True,
            error=None,
            completed_at="2026-11-18T12:01:00",
            data=threat_data,
        ),
    ]

    return SimpleNamespace(
        scan_id="test-scan-001",
        domain="example.test",
        status="completed",
        started_at="2026-11-18T11:59:00",
        completed_at="2026-11-18T12:02:00",
        results=module_results,
    )


def test_database_creation(tmp_path):
    db_path = tmp_path / "test.db"

    service = DatabaseService(db_path)

    assert db_path.exists()

    service.close()


def test_save_scan_result(tmp_path):
    service = DatabaseService(
        tmp_path / "test.db"
    )

    result = service.save_scan_result(
        create_fake_scan()
    )

    assert result["success"] is True
    assert result["scan_id"] == "test-scan-001"
    assert result["modules_saved"] == 2

    service.close()


def test_scan_history(tmp_path):
    service = DatabaseService(
        tmp_path / "test.db"
    )

    service.save_scan_result(
        create_fake_scan()
    )

    history = service.get_scan_history()

    assert len(history) == 1
    assert history[0]["domain"] == "example.test"
    assert history[0]["status"] == "completed"

    service.close()


def test_scan_details(tmp_path):
    service = DatabaseService(
        tmp_path / "test.db"
    )

    service.save_scan_result(
        create_fake_scan()
    )

    details = service.get_scan_details(
        "test-scan-001"
    )

    assert details is not None
    assert details["domain"] == "example.test"
    assert len(details["modules"]) == 2

    service.close()


def test_subdomains_are_saved_as_findings(tmp_path):
    service = DatabaseService(
        tmp_path / "test.db"
    )

    service.save_scan_result(
        create_fake_scan()
    )

    details = service.get_scan_details(
        "test-scan-001"
    )

    subdomains = [
        item
        for item in details["findings"]
        if item["finding_type"] == "subdomain"
    ]

    assert len(subdomains) == 2

    service.close()


def test_threat_intel_matches_are_saved(tmp_path):
    service = DatabaseService(
        tmp_path / "test.db"
    )

    service.save_scan_result(
        create_fake_scan()
    )

    details = service.get_scan_details(
        "test-scan-001"
    )

    matches = [
        item
        for item in details["findings"]
        if item["finding_type"] == "threat_intel_match"
    ]

    assert len(matches) == 1
    assert matches[0]["indicator"] == "bad-example.test"
    assert matches[0]["score"] == 95

    service.close()


def test_duplicate_scan_is_rejected(tmp_path):
    service = DatabaseService(
        tmp_path / "test.db"
    )

    scan = create_fake_scan()

    service.save_scan_result(scan)

    with pytest.raises(ValueError):
        service.save_scan_result(scan)

    service.close()


def test_missing_scan_returns_none(tmp_path):
    service = DatabaseService(
        tmp_path / "test.db"
    )

    result = service.get_scan_details(
        "scan-does-not-exist"
    )

    assert result is None

    service.close()