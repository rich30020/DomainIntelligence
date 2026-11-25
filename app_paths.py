"""Resolve runtime resources and persistent writable application directories."""

"""Percorsi compatibili con avvio da sorgente e build PyInstaller."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "DomainIntelligence"


def resource_path(relative_path: str | Path) -> Path:
    """Percorso di una risorsa inclusa nell'applicazione (sola lettura)."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / relative_path


def get_app_data_dir() -> Path:
    """Cartella scrivibile: progetto in sviluppo, LocalAppData in versione EXE."""
    if getattr(sys, "frozen", False):
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        path = base / APP_NAME
    else:
        path = Path(__file__).resolve().parent
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_writable_dir(name: str) -> Path:
    """Restituisce e crea una sottocartella dati scrivibile."""
    path = get_app_data_dir() / name
    path.mkdir(parents=True, exist_ok=True)
    return path
