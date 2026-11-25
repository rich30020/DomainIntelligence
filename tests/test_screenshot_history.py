"""Automated tests for test screenshot history.

These tests protect expected behavior and help detect regressions in the
Domain Intelligence implementation.
"""

from datetime import datetime, timezone

from services.database_service import DatabaseService


def test_save_and_read_screenshot_history(tmp_path):
    """Verify expected behavior for save and read screenshot history.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    service = DatabaseService(tmp_path / "screens.db")
    capture = {
        "hostname": "example.com",
        "url": "https://example.com",
        "screenshot_path": str(tmp_path / "example.png"),
        "title": "Example Domain",
        "description": "Example description",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "page_width": 1440,
        "page_height": 1200,
    }
    saved = service.save_screenshot_record(capture)
    assert saved["domain"] == "example.com"
    assert saved["page_width"] == 1440
    history = service.get_screenshot_history()
    assert len(history) == 1
    assert history[0]["url"] == "https://example.com"
    service.close()


def test_save_screenshot_comparison_metadata(tmp_path):
    """Verify expected behavior for save screenshot comparison metadata.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    service = DatabaseService(tmp_path / "screens.db")
    capture = {
        "hostname": "example.org",
        "url": "https://example.org",
        "screenshot_path": str(tmp_path / "candidate.png"),
        "title": "Example",
    }
    saved = service.save_screenshot_record(
        capture,
        comparison={
            "reference_path": str(tmp_path / "reference.png"),
            "similarity_percent": 96.5,
            "assessment": "somiglianza_visiva_molto_alta",
        },
    )
    assert saved["similarity_percent"] == 96.5
    assert saved["assessment"] == "somiglianza_visiva_molto_alta"
    service.close()


def test_reject_incomplete_screenshot_record(tmp_path):
    """Verify expected behavior for reject incomplete screenshot record.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    service = DatabaseService(tmp_path / "screens.db")
    try:
        service.save_screenshot_record({"hostname": "example.com"})
    except ValueError:
        pass
    else:
        raise AssertionError("Expected incomplete screenshot data to be rejected")
    service.close()
