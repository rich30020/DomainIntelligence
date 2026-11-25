from threading import Event

from gui.scan_worker import ScanWorker


class FakeEngine:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.received_event = None

    def run_scan(self, request, cancellation_event=None):
        self.received_event = cancellation_event
        if self.error:
            raise self.error
        return self.result


def test_worker_emits_result_and_finished():
    result = object()
    engine = FakeEngine(result=result)
    worker = ScanWorker(engine, "example.com", ["domain_scanner"])
    completed, finished = [], []
    worker.completed.connect(completed.append)
    worker.finished.connect(lambda: finished.append(True))
    worker.run()
    assert completed == [result]
    assert finished == [True]
    assert engine.received_event is not None


def test_worker_emits_readable_error_and_finished():
    engine = FakeEngine(error=ValueError("errore simulato"))
    worker = ScanWorker(engine, "example.com", ["domain_scanner"])
    failed, finished = [], []
    worker.failed.connect(failed.append)
    worker.finished.connect(lambda: finished.append(True))
    worker.run()
    assert failed and "ValueError" in failed[0]
    assert "errore simulato" in failed[0]
    assert finished == [True]


def test_worker_respects_pre_cancelled_event():
    event = Event()
    event.set()
    engine = FakeEngine(result=object())
    worker = ScanWorker(
        engine, "example.com", ["domain_scanner"],
        cancellation_event=event,
    )
    failed = []
    worker.failed.connect(failed.append)
    worker.run()
    assert failed
    assert "annullata" in failed[0]
    assert engine.received_event is None
