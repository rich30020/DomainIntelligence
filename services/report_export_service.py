import csv
import json
from xml.sax.saxutils import escape
from pathlib import Path


class ReportExportService:
    """Esporta i risultati di una scansione in PDF e CSV."""

    @staticmethod
    def _read(value, key, default=None):
        if isinstance(value, dict):
            return value.get(key, default)
        return getattr(value, key, default)

    @classmethod
    def _report_data(cls, result):
        modules = []
        for item in cls._read(result, "results", []) or []:
            data = cls._read(item, "data")
            modules.append({
                "module_name": cls._read(item, "module_name", "modulo"),
                "success": bool(cls._read(item, "success", False)),
                "error": cls._read(item, "error"),
                "data": data,
            })
        return {
            "domain": cls._read(result, "domain", "non disponibile"),
            "status": cls._read(result, "status", "non disponibile"),
            "scan_id": cls._read(result, "scan_id", "non disponibile"),
            "modules": modules,
        }

    @staticmethod
    def _safe_csv_cell(value):
        """Neutralizza celle che Excel/Calc potrebbe interpretare come formule."""
        text = "" if value is None else str(value)
        probe = text.lstrip(" \\t\\r\\n")
        if probe.startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    def export_csv(self, result, destination):
        data = self._report_data(result)
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.writer(handle, delimiter=";")
            writer.writerow([
                "dominio", "scan_id", "stato", "modulo",
                "successo", "errore", "dati_json"
            ])
            for module in data["modules"] or [{
                "module_name": "nessun_modulo", "success": False,
                "error": "Nessun risultato modulo", "data": None
            }]:
                writer.writerow([
                    self._safe_csv_cell(data["domain"]),
                    self._safe_csv_cell(data["scan_id"]),
                    self._safe_csv_cell(data["status"]),
                    self._safe_csv_cell(module["module_name"]),
                    self._safe_csv_cell(module["success"]),
                    self._safe_csv_cell(module["error"] or ""),
                    self._safe_csv_cell(
                        json.dumps(module["data"], ensure_ascii=False, default=str)
                        if module["data"] is not None else ""
                    ),
                ])
        return path

    def export_pdf(self, result, destination):
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                KeepTogether
            )
        except ImportError as exc:
            raise RuntimeError(
                "ReportLab non è installato. Esegui: pip install reportlab"
            ) from exc

        data = self._report_data(result)
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            str(path), pagesize=A4,
            rightMargin=18*mm, leftMargin=18*mm,
            topMargin=18*mm, bottomMargin=18*mm,
            title=f"Domain Intelligence - {data['domain']}",
            author="Domain Intelligence",
        )
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="ReportSubtitle", parent=styles["Normal"],
            textColor=colors.HexColor("#526579"), alignment=TA_CENTER,
            spaceAfter=12
        ))
        story = [
            Paragraph("DOMAIN INTELLIGENCE", styles["Title"]),
            Paragraph("Report dei risultati della scansione", styles["ReportSubtitle"]),
            Spacer(1, 5*mm),
        ]
        summary = [
            ["Dominio", str(data["domain"])],
            ["ID scansione", str(data["scan_id"])],
            ["Stato", str(data["status"])],
            ["Moduli eseguiti", str(len(data["modules"]))],
        ]
        table = Table(summary, colWidths=[42*mm, 125*mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#EAF1F5")),
            ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#C9D5DE")),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("PADDING", (0,0), (-1,-1), 7),
        ]))
        story.extend([table, Spacer(1, 7*mm), Paragraph("Dettaglio moduli", styles["Heading2"])])
        for module in data["modules"]:
            outcome = "Completato" if module["success"] else "Non completato"
            parts = [
                Paragraph(
                    f"<b>{escape(str(module['module_name']))}</b> — {outcome}",
                    styles["Heading3"]
                )
            ]
            if module["error"]:
                parts.append(Paragraph(
                    f"Errore: {escape(str(module['error']))}",
                    styles["BodyText"]
                ))
            if module["data"] is not None:
                payload = json.dumps(module["data"], ensure_ascii=False, indent=2, default=str)
                # ReportLab Paragraph is not a safe container for arbitrary JSON markup.
                from reportlab.platypus import Preformatted
                parts.append(Preformatted(payload[:12000], styles["Code"]))
            story.extend([KeepTogether(parts), Spacer(1, 3*mm)])
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph(
            "Nota: i risultati sono evidenze tecniche e dipendono dalle fonti consultate. "
            "Una mancata corrispondenza IOC o una somiglianza visiva non dimostrano, da sole, "
            "che un dominio sia sicuro o malevolo.",
            styles["Italic"]
        ))
        doc.build(story)
        return path
