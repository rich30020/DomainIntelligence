FASE 13.2 – INTEGRAZIONE SCREENSHOT NELLA GUI E NEL DATABASE

SOSTITUIRE con i file inclusi:
- gui/main_window.py
- models/db_models.py
- services/database_service.py

Aggiungere:
- tests/test_screenshot_history.py
- tests/test_screenshot_gui.py

Funzioni aggiunte:
- scheda "Screenshot e confronto" nella GUI;
- URL HTTPS e hostname autorizzato devono coincidere esattamente;
- checkbox di conferma dell'autorizzazione esplicita;
- acquisizione in QThread per non bloccare l'interfaccia;
- anteprima screenshot;
- selezione immagine di riferimento e confronto pHash;
- salvataggio dei metadati nello storico SQLite.

IMPORTANTE
- Usa esclusivamente domini che controlli o per cui hai autorizzazione esplicita.
- La conferma UI non sostituisce l'autorizzazione reale.
- La funzione screenshot resta separata dalle scansioni passive automatiche.
- Gli screenshot sono salvati localmente in ./screenshots.
- L'aggiornamento del modello aggiunge la tabella screenshot_records; non elimina
  le tabelle esistenti. SQLite create_all aggiunge la nuova tabella.
- Playwright e Chromium devono essere installati nella stessa venv.

TEST
python -m py_compile gui/main_window.py services/database_service.py models/db_models.py
pytest -v tests/test_screenshot_history.py tests/test_screenshot_gui.py
pytest -v

Nota: la prova live richiede un dominio HTTPS di tua proprietà/autorizzato.
