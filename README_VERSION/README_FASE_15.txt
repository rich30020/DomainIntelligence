FASE 15 — Esportazione report PDF e CSV

File da sostituire:
- gui/main_window.py

Nuovo file:
- services/report_export_service.py

Nuovi test:
- tests/test_report_export_service.py
- tests/test_report_export_gui.py

Funzioni:
- Esporta PDF riepilogativo con dominio, ID scansione, stato e dettagli dei moduli.
- Esporta CSV con una riga per modulo, usando separatore punto e virgola e UTF-8 con BOM per Excel.
- I pulsanti sono disabilitati finché non è disponibile una scansione completata.
- Nessuna scansione o richiesta di rete viene avviata dall'esportazione.

Dipendenza:
ReportLab è già previsto nel requirements.txt del progetto. Verificare con:
python -c "import reportlab; print(reportlab.Version)"
Se manca:
pip install "reportlab>=4.2"

Installazione:
1. Chiudere l'app.
2. Sostituire gui/main_window.py.
3. Copiare services/report_export_service.py in services.
4. Copiare i due test in tests.

Test:
python -m py_compile gui/main_window.py services/report_export_service.py
pytest -v tests/test_report_export_service.py tests/test_report_export_gui.py
pytest -v

Nota interpretativa: report e punteggi riassumono evidenze, non certificano da soli sicurezza o malevolenza.
