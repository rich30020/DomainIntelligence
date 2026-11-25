from threading import Event

from PySide6.QtCore import QObject, Signal, Slot

from core import ScanRequest, ScanScope, ScanMode


class ScanWorker(QObject):
    completed = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        scanner_engine,
        domain,
        selected_modules,
        image_path=None,
        comparison_image_path=None,
        cancellation_event=None,
    ):
        super().__init__()
        self.scanner_engine = scanner_engine
        self.domain = domain
        self.selected_modules = list(selected_modules or [])
        self.image_path = image_path
        self.comparison_image_path = comparison_image_path
        self.cancellation_event = cancellation_event or Event()

    @Slot()
    def run(self):
        try:
            if self.cancellation_event.is_set():
                raise RuntimeError("Scansione annullata prima dell'avvio.")

            scope = ScanScope(
                root_domain=self.domain,
                mode=ScanMode.PASSIVE,
            )
            metadata = {}
            if self.image_path:
                metadata["image_path"] = self.image_path
            if self.comparison_image_path:
                metadata["comparison_image_path"] = self.comparison_image_path

            request = ScanRequest(
                domain=self.domain,
                scope=scope,
                selected_modules=self.selected_modules,
                metadata=metadata,
            )
            result = self.scanner_engine.run_scan(
                request,
                cancellation_event=self.cancellation_event,
            )
            self.completed.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            self.finished.emit()
