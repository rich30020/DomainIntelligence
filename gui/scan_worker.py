"""Qt worker that runs a scan without blocking the GUI event loop."""

from threading import Event

from PySide6.QtCore import QObject, Signal, Slot

from core import ScanRequest, ScanScope, ScanMode


class ScanWorker(QObject):
    """Run one scan in a QThread and report its outcome through Qt signals.

    The worker contains no widget logic. Keeping scan execution separate from
    the main thread allows the interface to remain responsive during analysis.
    """
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
        """Store scan inputs and create a cooperative cancellation token."""
        super().__init__()
        self.scanner_engine = scanner_engine
        self.domain = domain
        self.selected_modules = list(selected_modules or [])
        self.image_path = image_path
        self.comparison_image_path = comparison_image_path
        self.cancellation_event = cancellation_event or Event()

    @Slot()
    def run(self):
        """Build a passive request, execute it, and always emit ``finished``.

        The final signal lets the owning window release worker/thread references
        even when request construction or scan execution raises an exception.
        """
        try:
            if self.cancellation_event.is_set():
                raise RuntimeError("Scansione annullata prima dell'avvio.")

            # GUI-triggered scans use passive scope by default. Modules that
            # require active checks are therefore rejected by the engine.
            scope = ScanScope(
                root_domain=self.domain,
                mode=ScanMode.PASSIVE,
            )
            # Pass optional image paths as metadata so analysis modules do not
            # need dependencies on GUI widgets or file-picker controls.
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
            # Always notify the QThread owner, on both success and failure.
            self.finished.emit()
