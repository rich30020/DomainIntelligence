FASE 12.3 – GESTIONE DELLE PIANIFICAZIONI DALLA GUI

Questa fase aggiunge la scheda "Monitoraggio programmato" alla GUI esistente.

FUNZIONI
- Creazione di una pianificazione indicando dominio, frequenza e moduli.
- Moduli ammessi: Domain Scanner, Subdomain Finder, Similar Domain Finder,
  Threat Intelligence. I moduli immagine locali sono esclusi perché dipendono
  da percorsi di file sul PC.
- Visualizzazione di stato, prossima/ultima esecuzione, numero esecuzioni ed errori.
- Attivazione/disattivazione della pianificazione selezionata.
- Eliminazione con conferma.
- Aggiornamento dopo il completamento/fallimento di una scansione programmata.
- Coordinamento con il motore della Fase 12.2: una scansione manuale mette
  in pausa l'avvio di nuove scansioni pianificate.

IMPORTANTE
- Gli orari sono mostrati in UTC.
- L'applicazione deve restare aperta perché le pianificazioni vengano eseguite.
- Le scansioni sono passive.
- Prima di applicare questa fase, devono essere già installate le Fasi 12.1 e 12.2.
- Sostituisci gui/main_window.py con il file incluso nello ZIP.
- Aggiungi tests/test_schedule_gui.py.

TEST
python -m py_compile gui/main_window.py
pytest -v tests/test_schedule_gui.py
pytest -v

Se i test Qt non si avviano in un ambiente senza display, eseguili su Windows
dentro la normale sessione desktop, con l'ambiente virtuale attivo.
