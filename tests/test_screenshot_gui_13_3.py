from gui.main_window import MainWindow


def test_screenshot_tab_is_available():
    window = MainWindow()
    try:
        assert window.results_tabs.count() > 0
        assert window.screenshot_history_table.columnCount() == 7
        assert hasattr(window, "open_screenshot_history_record")
    finally:
        window.close()
