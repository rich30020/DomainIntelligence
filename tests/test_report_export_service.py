"""Automated tests for test report export service.

These tests protect the documented behavior of the Domain Intelligence application
and help detect regressions when implementation details are changed.
"""

import csv
from pathlib import Path

from services.report_export_service import ReportExportService


class Obj:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def sample_result():
    return Obj(
        domain="example.com",
        status="completed",
        scan_id="scan-test-001",
        results=[
            Obj(
                module_name="domain_scanner",
                success=True,
                error=None,
                data={"dns": {"A": ["192.0.2.10"]}, "note": "test"},
            ),
            Obj(
                module_name="threat_intel_analyzer",
                success=False,
                error="Fonte non disponibile",
                data=None,
            ),
        ],
    )


def test_export_csv_creates_rows_for_modules(tmp_path):
    """Verify expected behavior for export csv creates rows for modules.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    target = tmp_path / "report.csv"
    ReportExportService().export_csv(sample_result(), target)
    assert target.exists()
    with target.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter=";"))
    assert len(rows) == 2
    assert rows[0]["dominio"] == "example.com"
    assert rows[0]["modulo"] == "domain_scanner"
    assert "192.0.2.10" in rows[0]["dati_json"]


def test_export_pdf_creates_valid_pdf(tmp_path):
    """Verify expected behavior for export pdf creates valid pdf.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    target = tmp_path / "report.pdf"
    ReportExportService().export_pdf(sample_result(), target)
    assert target.exists()
    assert target.read_bytes().startswith(b"%PDF")


def test_export_csv_supports_dict_results(tmp_path):
    """Verify expected behavior for export csv supports dict results.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    target = tmp_path / "dict.csv"
    result = {
        "domain": "example.org",
        "status": "completed",
        "scan_id": "dict-1",
        "results": [{"module_name": "dns", "success": True, "data": {"A": []}}],
    }
    ReportExportService().export_csv(result, target)
    assert "example.org" in target.read_text(encoding="utf-8-sig")
