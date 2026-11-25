DOMAIN INTELLIGENCE - FASE 12.1
Fondamenta database per monitoraggio pianificato

FILE DA COPIARE NEL PROGETTO
1) models/db_models.py       -> sostituire il file esistente
2) services/database_service.py -> sostituire il file esistente
3) tests/test_scheduled_scans.py -> aggiungere questo nuovo file

Non modificare main.py, gui/main_window.py o gui/scan_worker.py in questa fase.
Non modificare o cancellare data/domain_intelligence.db: create_all aggiunge la nuova
 tabella scheduled_scan_records senza eliminare le tabelle esistenti.

La fase aggiunge solo persistenza e CRUD delle pianificazioni. Non avvia ancora
scansioni automatiche e non crea thread o timer in background.

API aggiunte a DatabaseService:
- create_schedule(domain, selected_modules, interval_minutes, next_run_at=None, name=None, enabled=True)
- get_schedules(include_disabled=True)
- get_schedule(schedule_id)
- update_schedule(schedule_id, **changes)
- set_schedule_enabled(schedule_id, enabled)
- delete_schedule(schedule_id)
- get_due_schedules(now=None)
- mark_schedule_run(schedule_id, ran_at=None, next_run_at=None, scan_id=None, error=None)

Intervallo consentito: da 15 a 43200 minuti (30 giorni).
Gli orari sono normalizzati in UTC; SQLite può restituire datetime senza timezone,
ma i dizionari restituiti espongono timestamp ISO 8601 con offset UTC.

TEST
Dalla cartella principale DomainIntelligence, con .venv attivo:
python -m py_compile models/db_models.py services/database_service.py
pytest -v tests/test_scheduled_scans.py
pytest -v
