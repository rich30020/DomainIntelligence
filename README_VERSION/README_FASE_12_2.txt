FASE 12.2 – MOTORE DI ESECUZIONE AUTOMATICA

OBIETTIVO
- Controllare ogni 15 secondi le pianificazioni scadute.
- Eseguire una scansione pianificata alla volta in un QThread.
- Salvare il risultato nello storico già esistente.
- Aggiornare ultima esecuzione, prossima esecuzione e contatori.
- Non bloccare l'interfaccia: puoi cambiare scheda o usare altre finestre.
- Alla chiusura completa, fermare il timer e attendere la scansione attiva
  prima di chiudere il database.

FILE
1) services/scheduled_scan_manager.py – NUOVO
2) main.py – SOSTITUIRE
3) gui/main_window.py – SOSTITUIRE con la versione inclusa nello ZIP
4) tests/test_scheduled_scan_manager.py – NUOVO

SOSTITUZIONE GUI
La versione inclusa di gui/main_window.py è stata ricavata dal file che hai
caricato, mantenendo struttura e stile. Sostituisci il file esistente con
quello incluso nello ZIP: gestisce il coordinamento tra scansione manuale
e pianificata, evitando che i due worker usino contemporaneamente il motore.

IMPORTANTE
- Non cambiare gui/scan_worker.py.
- Non usare immagini nelle scansioni pianificate: i moduli immagine richiedono
  percorsi di file locali, che non sono persistenti nella pianificazione.
- Le scansioni restano passive.
- Le scansioni pianificate vengono eseguite solo mentre l'app è aperta.
- La X chiude completamente l'app: non è previsto un servizio Windows.
- Una scansione già avviata viene lasciata terminare prima della chiusura
  completa, per evitare di chiudere SQLite mentre il worker sta salvando.
- Il timer controlla ogni 15 secondi, quindi una scansione può partire fino
  a circa 15 secondi dopo l'orario previsto.

INSTALLAZIONE
Copia services/scheduled_scan_manager.py nella cartella services.
Sostituisci main.py.
Applica le modifiche A-G a gui/main_window.py.

TEST
    python -m py_compile main.py services/scheduled_scan_manager.py gui/main_window.py
    pytest -v tests/test_scheduled_scan_manager.py
    pytest -v

Prima di creare una pianificazione reale nella GUI (che arriverà nella
Fase 12.3), i test useranno un database temporaneo e un motore simulato.
