import csv

from services.report_export_service import ReportExportService


class Obj:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def test_csv_neutralises_formula_like_cells(tmp_path):
    result = Obj(
        domain='=HYPERLINK("https://bad.example")',
        status="completed",
        scan_id="scan-1",
        results=[
            Obj(
                module_name="+cmd",
                success=True,
                error="@SUM(1,1)",
                data={"note": "-1+1"},
            )
        ],
    )
    target = tmp_path / "safe.csv"
    ReportExportService().export_csv(result, target)
    with target.open(encoding="utf-8-sig", newline="") as handle:
        row = next(csv.DictReader(handle, delimiter=";"))
    assert row["dominio"].startswith("'=")
    assert row["modulo"].startswith("'+")
    assert row["errore"].startswith("'@")
    # JSON object begins with '{', so Excel does not interpret the cell as a formula.
    assert row["dati_json"].startswith("{")
    assert "-1+1" in row["dati_json"]


def test_csv_keeps_normal_cells_unchanged():
    assert ReportExportService._safe_csv_cell("example.com") == "example.com"
    assert ReportExportService._safe_csv_cell(None) == ""
