from threading import Event

from core import ScanMode, ScanRequest, ScanScope, ScannerEngine
from services.database_service import DatabaseService
from services.report_export_service import ReportExportService


class SuccessfulModule:
    name = "integration_success"

    def run(self, context, cancellation_event):
        return {
            "domain": context.domain,
            "scan_id": context.scan_id,
            "evidence": ["passive-test-evidence"],
        }


class FailingModule:
    name = "integration_failure"

    def run(self, context, cancellation_event):
        raise RuntimeError("errore simulato della fonte")


class CancellingModule:
    name = "integration_cancel"

    def run(self, context, cancellation_event):
        cancellation_event.set()
        return {"started": True}


def make_request(domain="example.com", modules=None):
    return ScanRequest(
        domain=domain,
        scope=ScanScope(root_domain=domain, mode=ScanMode.PASSIVE),
        selected_modules=modules or [],
    )


def test_module_error_does_not_stop_following_modules():
    engine = ScannerEngine()
    engine.register_module(FailingModule())
    engine.register_module(SuccessfulModule())

    result = engine.run_scan(
        make_request(modules=["integration_failure", "integration_success"])
    )

    assert result.status == "completed"
    assert len(result.results) == 2
    assert result.results[0].success is False
    assert "errore simulato" in result.results[0].error
    assert result.results[1].success is True
    assert result.results[1].data["domain"] == "example.com"


def test_unknown_module_is_recorded_without_crashing_scan():
    engine = ScannerEngine()
    result = engine.run_scan(make_request(modules=["modulo_inesistente"]))

    assert result.status == "completed"
    assert len(result.results) == 1
    assert result.results[0].success is False
    assert result.results[0].error == "Modulo non registrato."


def test_cancellation_stops_before_next_module():
    engine = ScannerEngine()
    engine.register_module(CancellingModule())
    engine.register_module(SuccessfulModule())
    result = engine.run_scan(
        make_request(modules=["integration_cancel", "integration_success"])
    )

    assert result.status == "cancelled"
    assert result.results == []


def test_completed_scan_can_be_saved_and_exported(tmp_path):
    engine = ScannerEngine()
    engine.register_module(SuccessfulModule())
    scan = engine.run_scan(make_request(modules=["integration_success"]))

    database = DatabaseService(tmp_path / "integration.db")
    try:
        saved = database.save_scan_result(scan)
        history = database.get_scan_history()
        assert saved["success"] is True
        assert len(history) == 1
        assert history[0]["scan_id"] == scan.scan_id
    finally:
        database.close()

    csv_path = ReportExportService().export_csv(scan, tmp_path / "scan.csv")
    assert csv_path.exists()
    assert csv_path.read_bytes().startswith(b"\xef\xbb\xbf")

    pdf_path = ReportExportService().export_pdf(scan, tmp_path / "scan.pdf")
    assert pdf_path.read_bytes().startswith(b"%PDF")


def test_invalid_domain_fails_before_running_modules():
    engine = ScannerEngine()
    engine.register_module(SuccessfulModule())
    result = engine.run_scan(make_request(domain="not_a_domain"))

    assert result.status == "failed"
    assert result.results == []


def test_pre_cancelled_scan_does_not_run_modules():
    engine = ScannerEngine()
    engine.register_module(SuccessfulModule())
    cancellation = Event()
    cancellation.set()
    result = engine.run_scan(
        make_request(modules=["integration_success"]),
        cancellation_event=cancellation,
    )

    assert result.status == "cancelled"
    assert result.results == []
