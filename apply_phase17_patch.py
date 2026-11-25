"""Apply idempotent source updates required by the Windows packaging workflow."""

"""Applica in modo verificato le modifiche minime per la build PyInstaller.
Eseguire dalla cartella principale del progetto: python apply_phase17_patch.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def replace_once(file_path: str, old: str, new: str) -> None:
    path = ROOT / file_path
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count == 0:
        if new in text:
            print(f"OK già aggiornato: {file_path}")
            return
        raise SystemExit(f"ERRORE: blocco da aggiornare non trovato in {file_path}. Nessuna modifica a questo file.")
    if count != 1:
        raise SystemExit(f"ERRORE: trovato {count} volte in {file_path}; interrompo per evitare modifiche ambigue.")
    path.write_text(text.replace(old, new), encoding="utf-8")
    print(f"Aggiornato: {file_path}")


replace_once(
    "main.py",
    "from pathlib import Path\n\nfrom PySide6.QtWidgets import QApplication",
    "from pathlib import Path\n\nfrom app_paths import resource_path\nfrom PySide6.QtWidgets import QApplication",
)
replace_once(
    "main.py",
    "    feed_path = (\n        Path(__file__).resolve().parent\n        / \"data\"\n        / \"threat_intel\"\n        / \"sample_iocs.csv\"\n    )",
    "    feed_path = resource_path(Path(\"data\") / \"threat_intel\" / \"sample_iocs.csv\")",
)
replace_once(
    "services/database_service.py",
    "from sqlalchemy.orm import sessionmaker\n\nfrom models.db_models import (",
    "from sqlalchemy.orm import sessionmaker\n\nfrom app_paths import get_writable_dir\nfrom models.db_models import (",
)
replace_once(
    "services/database_service.py",
    "            project_root = Path(__file__).resolve().parent.parent\n            database_path = (\n                project_root\n                / \"data\"\n                / \"domain_intelligence.db\"\n            )",
    "            database_path = (\n                get_writable_dir(\"data\")\n                / \"domain_intelligence.db\"\n            )",
)
replace_once(
    "gui/main_window.py",
    "from pathlib import Path\n",
    "from pathlib import Path\n\nfrom app_paths import get_writable_dir\n",
)
replace_once(
    "gui/main_window.py",
    "        project_root = Path(__file__).resolve().parent.parent\n        output_dir = project_root / \"screenshots\"",
    "        output_dir = get_writable_dir(\"screenshots\")",
)
print("Patch Fase 17 applicata/verificata.")
