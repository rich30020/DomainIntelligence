
import sys
from pathlib import Path

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


def create_scanner_engine(threat_intel_store):
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
    app = QApplication(sys.argv)
    app.setApplicationName("Domain Intelligence")

    threat_intel_store = ThreatIntelStore()

    feed_path = (
        Path(__file__).resolve().parent
        / "data"
        / "threat_intel"
        / "sample_iocs.csv"
    )

    if feed_path.exists():
        import_result = threat_intel_store.import_csv(
            str(feed_path)
        )
        print("Threat Intelligence:", import_result)
    else:
        print("Feed IOC non trovato:", feed_path)

    scanner_engine = create_scanner_engine(
        threat_intel_store
    )

    database_service = DatabaseService()

    window = MainWindow(
        scanner_engine=scanner_engine,
        database_service=database_service,
    )

    window.show()

    exit_code = app.exec()

    database_service.close()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
