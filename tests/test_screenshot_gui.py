from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow


def test_screenshot_tab_is_available():
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    labels = [
        window.results_tabs.tabText(i)
        for i in range(window.results_tabs.count())
    ]
    assert "Screenshot e confronto" in labels
    assert window.capture_screenshot_button.isEnabled()
    window.close()
