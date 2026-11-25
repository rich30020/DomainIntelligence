$ErrorActionPreference = "Stop"

Write-Host "=== Domain Intelligence - build Windows EXE ===" -ForegroundColor Cyan

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    throw "Virtual environment non trovato. Crea prima .venv nella cartella del progetto."
}

$Python = ".\.venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt
& $Python -m pip install "pyinstaller>=6.10,<7"

# Playwright resta opzionale per le schermate. Se installato, viene incluso il
# pacchetto Python; il browser Chromium va installato separatamente sul PC.
& $Python -m pip install playwright

& $Python .\apply_phase17_patch.py
& $Python -m py_compile .\app_paths.py .\main.py .\gui\main_window.py .\services\database_service.py

& $Python -m PyInstaller --clean --noconfirm .\DomainIntelligence.spec

Write-Host "Build completata. Avvio di prova:" -ForegroundColor Green
Write-Host ".\dist\DomainIntelligence\DomainIntelligence.exe"
