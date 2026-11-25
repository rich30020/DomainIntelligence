from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow


def test_report_export_buttons_exist_and_start_disabled():
    # QWidget richiede un QApplication esplicito prima di creare MainWindow.
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
