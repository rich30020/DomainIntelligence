"""Coordinate recurring scans while keeping the GUI and database lifecycle safe."""

from datetime import datetime, timezone

from PySide6.QtCore import QCoreApplication, QObject, QThread, QTimer, Signal, Slot

from gui.scan_worker import ScanWorker


class ScheduledScanManager(QObject):
    """Schedule due scans and serialize their execution through a Qt worker.

    Only one scheduled scan is active at a time. The manager pauses cleanly
    during manual GUI scans and stops its timer before application shutdown.
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
        """Initialize the scheduler timer, service references, and worker state."""
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
        """Start the polling timer used to detect due schedule records."""
        if self._stopping:
            return
        self._paused = False
        if not self.timer.isActive():
            self.timer.start()
        self.check_due_schedules()

    def pause(self):
        """Temporarily suspend dispatch of scheduled scans."""
        self._paused = True
        self.timer.stop()

    def resume(self):
        """Resume schedule polling after a manual scan has finished."""
        if self._stopping:
            return
        self._paused = False
        if not self.timer.isActive():
            self.timer.start()
        self.check_due_schedules()

    @Slot()
    def check_due_schedules(self):
        """Poll the database and dispatch the earliest due schedule if idle."""
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

        # Run only one scheduled scan at a time. Other due schedules remain in
        # the database and are picked up by a later polling cycle.
        schedule = due_items[0]
        self._start_schedule(schedule)

    def _start_schedule(self, schedule):
        """Create and start a QThread worker for one selected schedule record."""
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
        """Persist a completed run and update its recurring-schedule metadata."""
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
        """Record a failed scheduled run and expose the error through a signal."""
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
        """Release worker references and resume polling when shutdown is not active."""
        self.thread = None
        self.worker = None
        self.active_schedule = None

        if not self._stopping and not self._paused:
            # Let queued Qt notifications finish before dispatching another
            # scheduled item.
            QTimer.singleShot(250, self.check_due_schedules)

    def shutdown(self):
        """Stop scheduling and wait for any active worker before teardown."""
        self._stopping = True
        self._paused = True
        self.timer.stop()

        if self.thread is not None and self.thread.isRunning():
            self.thread.quit()
            # Use a bounded wait so application shutdown cannot block indefinitely.
            # Do not mark shutdown as complete while a worker is still running.
            if not self.thread.wait(30000):
                self.status_changed.emit(
                    "Chiusura in attesa: la scansione pianificata non è ancora terminata."
                )
                raise TimeoutError(
                    "La scansione pianificata è ancora attiva dopo 30 secondi. "
                    "Il database non deve essere chiuso mentre il worker è in esecuzione."
                )
            # Process queued signals (result persistence and schedule updates) before
            # main.py closes the database connection.
            QCoreApplication.processEvents()

        self.thread = None
        self.worker = None
        self.active_schedule = None
        self._shutdown_complete = True
