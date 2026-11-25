"""Automated tests for test screenshot gui.

These tests protect expected behavior and help detect regressions in the
Domain Intelligence implementation.
"""

from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow


def test_screenshot_tab_is_available():
    """Verify expected behavior for screenshot tab is available.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    labels = [
        window.results_tabs.tabText(i)
        for i in range(window.results_tabs.count())
    ]
    assert "Screenshot e confronto" in labels
    assert window.capture_screenshot_button.isEnabled()
    window.close()
