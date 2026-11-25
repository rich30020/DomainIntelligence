"""Application entry point wiring the GUI, modules, and shared services."""

import sys
from pathlib import Path

from app_paths import resource_path
from PySide6.QtWidgets import QApplication

from gui.main_window import MainWindow
from core import ScannerEngine

from modules import (
    DomainScanner,
    SubdomainFinder,
    SimilarDomainAnalyzer,
    WebsiteCloneAnalyzer,
    ThreatIntelAnalyzer,
    ImageHashAnalyzer,
    ImageSimilarityAnalyzer,
    LogoDetector,
)

from services import DatabaseService
from services.threat_intel_store import ThreatIntelStore
from services.scheduled_scan_manager import ScheduledScanManager


def create_scanner_engine(threat_intel_store):
    """Create the scanner and register the modules exposed by the GUI."""
    engine = ScannerEngine()

    engine.register_module(DomainScanner())
    engine.register_module(SubdomainFinder())
    engine.register_module(SimilarDomainAnalyzer())
    engine.register_module(WebsiteCloneAnalyzer())
    engine.register_module(
        ThreatIntelAnalyzer(store=threat_intel_store)
    )
    engine.register_module(ImageHashAnalyzer())
    engine.register_module(ImageSimilarityAnalyzer())
    engine.register_module(LogoDetector())

    return engine


def main():
    """Initialize the desktop application and coordinate service shutdown."""
    app = QApplication(sys.argv)
    app.setApplicationName("Domain Intelligence")

    # Load the bundled sample feed when available. A missing local feed should
    # not prevent the desktop application from starting.
    threat_intel_store = ThreatIntelStore()
    feed_path = resource_path(Path("data") / "threat_intel" / "sample_iocs.csv")

    if feed_path.exists():
        import_result = threat_intel_store.import_csv(str(feed_path))
        print("Threat Intelligence:", import_result)
    else:
        print("Feed IOC non trovato:", feed_path)

    scanner_engine = create_scanner_engine(threat_intel_store)
    database_service = DatabaseService()

    # Manual and scheduled scans share the same engine and database service,
    # keeping module registration and persistence behavior consistent.
    scheduled_scan_manager = ScheduledScanManager(
        scanner_engine=scanner_engine,
        database_service=database_service,
        check_interval_ms=15000,
    )

    window = MainWindow(
        scanner_engine=scanner_engine,
        database_service=database_service,
        scheduled_scan_manager=scheduled_scan_manager,
    )

    # Stop the scheduler before closing SQLite. The manager stops its timer
    # and waits for an active scheduled scan before the database is closed.
    app.aboutToQuit.connect(scheduled_scan_manager.shutdown)
    app.aboutToQuit.connect(database_service.close)

    scheduled_scan_manager.start()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
