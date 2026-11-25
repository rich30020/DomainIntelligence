from datetime import datetime, timezone

from PySide6.QtCore import QCoreApplication, QObject, QThread, QTimer, Signal, Slot

from gui.scan_worker import ScanWorker


class ScheduledScanManager(QObject):
    """
    Esegue una pianificazione alla volta senza bloccare il thread della GUI.

    Il timer vive nel thread principale Qt; la scansione vera e propria viene
    eseguita da ScanWorker in un QThread separato.
    """

    status_changed = Signal(str)
    schedule_completed = Signal(dict)
    schedule_failed = Signal(dict)

    def __init__(
        self,
        scanner_engine,
        database_service,
        check_interval_ms=15000,
        parent=None,
    ):
        super().__init__(parent)
        self.scanner_engine = scanner_engine
        self.database_service = database_service
        self.timer = QTimer(self)
        self.timer.setInterval(max(1000, int(check_interval_ms)))
        self.timer.timeout.connect(self.check_due_schedules)

        self.thread = None
        self.worker = None
        self.active_schedule = None
        self._paused = False
        self._stopping = False
        self._shutdown_complete = False

    @property
    def is_busy(self):
        return self.thread is not None and self.thread.isRunning()

    def start(self):
        if self._stopping:
            return
        self._paused = False
        if not self.timer.isActive():
            self.timer.start()
        self.check_due_schedules()

    def pause(self):
        """Sospende nuove scansioni pianificate; non interrompe quella attiva."""
        self._paused = True
        self.timer.stop()

    def resume(self):
        if self._stopping:
            return
        self._paused = False
        if not self.timer.isActive():
            self.timer.start()
        self.check_due_schedules()

    @Slot()
    def check_due_schedules(self):
        if self._stopping or self._paused or self.is_busy:
            return

        try:
            due_items = self.database_service.get_due_schedules()
        except Exception as exc:
            self.status_changed.emit(
                f"Errore lettura pianificazioni: {exc}"
            )
            return

        if not due_items:
            return

        # Una sola scansione pianificata alla volta: le altre restano in coda
        # nel database e verranno recuperate al successivo controllo.
        schedule = due_items[0]
        self._start_schedule(schedule)

    def _start_schedule(self, schedule):
        self.active_schedule = schedule
        self.status_changed.emit(
            f"Monitoraggio in esecuzione: {schedule['domain']}"
        )

        self.thread = QThread(self)
        self.worker = ScanWorker(
            self.scanner_engine,
            schedule["domain"],
            schedule["selected_modules"],
        )
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.completed.connect(self._on_scan_completed)
        self.worker.failed.connect(self._on_scan_failed)
        self.worker.completed.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._on_thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(object)
    def _on_scan_completed(self, result):
        schedule = self.active_schedule or {}
        error = None
        try:
            self.database_service.save_scan_result(result)
        except Exception as exc:
            error = f"Salvataggio risultati non riuscito: {exc}"

        try:
            self.database_service.mark_schedule_run(
                schedule["id"],
                ran_at=datetime.now(timezone.utc),
                scan_id=getattr(result, "scan_id", None),
                error=error,
            )
        except Exception as exc:
            error = (
                f"{error}; " if error else ""
            ) + f"Aggiornamento pianificazione non riuscito: {exc}"

        payload = {
            "schedule_id": schedule.get("id"),
            "domain": schedule.get("domain"),
            "scan_id": getattr(result, "scan_id", None),
            "error": error,
        }

        if error:
            self.schedule_failed.emit(payload)
            self.status_changed.emit(
                f"Scansione {schedule.get('domain', '')} terminata con errore"
            )
        else:
            self.schedule_completed.emit(payload)
            self.status_changed.emit(
                f"Scansione pianificata completata: {schedule.get('domain', '')}"
            )

    @Slot(str)
    def _on_scan_failed(self, error_message):
        schedule = self.active_schedule or {}
        error = str(error_message)

        try:
            self.database_service.mark_schedule_run(
                schedule["id"],
                ran_at=datetime.now(timezone.utc),
                error=error,
            )
        except Exception as exc:
            error += f"; aggiornamento pianificazione non riuscito: {exc}"

        payload = {
            "schedule_id": schedule.get("id"),
            "domain": schedule.get("domain"),
            "scan_id": None,
            "error": error,
        }
        self.schedule_failed.emit(payload)
        self.status_changed.emit(
            f"Scansione pianificata fallita: {schedule.get('domain', '')}"
        )

    @Slot()
    def _on_thread_finished(self):
        self.thread = None
        self.worker = None
        self.active_schedule = None

        if not self._stopping and not self._paused:
            # Lascia terminare le notifiche Qt correnti prima di avviare
            # un'eventuale pianificazione successiva.
            QTimer.singleShot(250, self.check_due_schedules)

    def shutdown(self):
        """
        Ferma il timer e attende la scansione attiva prima della chiusura
        completa, così il database non viene chiuso mentre il worker lo usa.
        """
        self._stopping = True
        self._paused = True
        self.timer.stop()

        if self.thread is not None and self.thread.isRunning():
            self.thread.quit()
            # Attesa limitata: evitare un blocco infinito della chiusura.
            # Se il worker non termina, non dichiarare shutdown completato.
            if not self.thread.wait(30000):
                self.status_changed.emit(
                    "Chiusura in attesa: la scansione pianificata non è ancora terminata."
                )
                raise TimeoutError(
                    "La scansione pianificata è ancora attiva dopo 30 secondi. "
                    "Il database non deve essere chiuso mentre il worker è in esecuzione."
                )
            # Consegna i segnali queued (salvataggio risultato e aggiornamento
            # pianificazione) prima che main.py chiuda il database.
            QCoreApplication.processEvents()

        self.thread = None
        self.worker = None
        self.active_schedule = None
        self._shutdown_complete = True
