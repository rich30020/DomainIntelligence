"""Automated tests for test screenshot gui 13 3.

These tests protect expected behavior and help detect regressions in the
Domain Intelligence implementation.
"""

from gui.main_window import MainWindow


def test_screenshot_tab_is_available():
    """Verify expected behavior for screenshot tab is available.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    window = MainWindow()
    try:
        assert window.results_tabs.count() > 0
        assert window.screenshot_history_table.columnCount() == 7
        assert hasattr(window, "open_screenshot_history_record")
    finally:
        window.close()
