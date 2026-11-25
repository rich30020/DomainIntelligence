"""Automated tests for test gui shutdown.

These tests protect the documented behavior of the Domain Intelligence application
and help detect regressions when implementation details are changed.
"""

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow


def test_window_has_deferred_close_support():
    """Verify expected behavior for window has deferred close support.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        assert hasattr(window, "closeEvent")
        assert hasattr(window, "_complete_deferred_close")
        assert window._close_requested is False
    finally:
        window.close()
        app.processEvents()
