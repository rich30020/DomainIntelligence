FASE 13.3 — Miglioramento confronto visivo e storico

File inclusi (sostituire integralmente):
- gui/main_window.py
- services/database_service.py
- models/db_models.py

Nuovi test da aggiungere:
- tests/test_screenshot_phase_13_3.py
- tests/test_screenshot_gui_13_3.py

Miglioramenti:
1. Il confronto aggiorna il record screenshot già salvato: non crea una seconda acquisizione nello storico.
2. L'archivio conserva anche la distanza pHash.
3. Anteprime affiancate per riferimento e screenshot acquisito.
4. Tabella storico arricchita con URL e valutazione.
5. Doppio clic su una riga per visualizzare i dettagli e le immagini associate.

Database:
- Aggiunta la colonna nullable phash_distance a screenshot_records.
- SQLite non aggiunge automaticamente nuove colonne con create_all su tabelle già esistenti.
- Per questo pacchetto, eseguire una migrazione SQL una sola volta (vedi istruzioni sotto) PRIMA di avviare l'app:
  ALTER TABLE screenshot_records ADD COLUMN phash_distance INTEGER;

Se la tabella screenshot_records non esiste ancora, avviare una volta l'app con i nuovi modelli: la tabella verrà creata con la colonna. In tal caso NON eseguire ALTER TABLE.

Test:
python -m py_compile gui/main_window.py services/database_service.py models/db_models.py
pytest -v tests/test_screenshot_phase_13_3.py tests/test_screenshot_gui_13_3.py
pytest -v

Nota: la somiglianza visiva è un indicatore tecnico e non prova di clonazione, phishing o frode.
Le acquisizioni restano limitate a siti posseduti o esplicitamente autorizzati.
