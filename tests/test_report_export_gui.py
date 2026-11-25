"""Automated tests for test report export gui.

These tests protect the documented behavior of the Domain Intelligence application
and help detect regressions when implementation details are changed.
"""

from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow


def test_report_export_buttons_exist_and_start_disabled():
    """Verify expected behavior for report export buttons exist and start disabled.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    # QWidget requires an active QApplication before MainWindow can be instantiated.
    app = QApplication.instance()
    owns_app = app is None
    if owns_app:
        app = QApplication([])

    window = MainWindow()
    try:
        assert window.export_pdf_button.text() == "Esporta PDF"
        assert window.export_csv_button.text() == "Esporta CSV"
        assert not window.export_pdf_button.isEnabled()
        assert not window.export_csv_button.isEnabled()
    finally:
        window.close()
        window.deleteLater()
        app.processEvents()
        if owns_app:
            app.quit()
