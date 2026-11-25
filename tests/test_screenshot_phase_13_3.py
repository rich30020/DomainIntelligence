"""test screenshot phase 13 3.

This file contains test helpers or manual checks for the Domain Intelligence
application. It is kept separate from the production application startup.
"""

from services.database_service import DatabaseService


class FakeCapture:
    hostname = "owned.example"
    url = "https://owned.example/"
    screenshot_path = "screenshots/test.png"
    title = "Test page"
    description = "Authorized test"
    captured_at = None
    page_width = 1280
    page_height = 720


def test_comparison_updates_existing_record_without_duplicate(tmp_path):
    """Verify expected behavior for comparison updates existing record without duplicate.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    db = DatabaseService(tmp_path / "test.db")
    try:
        saved = db.save_screenshot_record(FakeCapture())
        updated = db.update_screenshot_comparison(
            saved["id"],
            {
                "reference_path": "screenshots/reference.png",
                "similarity_percent": 91.25,
                "phash_distance": 7,
                "assessment": "somiglianza_visiva_alta",
            },
        )
        history = db.get_screenshot_history()
        assert len(history) == 1
        assert updated["id"] == saved["id"]
        assert updated["similarity_percent"] == 91.25
        assert updated["phash_distance"] == 7
        assert updated["comparison_reference"].endswith("reference.png")
    finally:
        db.close()


def test_get_screenshot_record_returns_detail(tmp_path):
    """Verify expected behavior for get screenshot record returns detail.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    db = DatabaseService(tmp_path / "test.db")
    try:
        saved = db.save_screenshot_record(FakeCapture())
        detail = db.get_screenshot_record(saved["id"])
        assert detail["domain"] == "owned.example"
        assert detail["url"] == "https://owned.example/"
    finally:
        db.close()


def test_update_missing_screenshot_raises(tmp_path):
    """Verify expected behavior for update missing screenshot raises.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    db = DatabaseService(tmp_path / "test.db")
    try:
        try:
            db.update_screenshot_comparison(999, {"similarity_percent": 90})
        except ValueError as exc:
            assert "non trovato" in str(exc)
        else:
            raise AssertionError("Era atteso ValueError.")
    finally:
        db.close()
