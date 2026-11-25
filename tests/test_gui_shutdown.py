from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow


def test_window_has_deferred_close_support():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        assert hasattr(window, "closeEvent")
        assert hasattr(window, "_complete_deferred_close")
        assert window._close_requested is False
    finally:
        window.close()
        app.processEvents()
