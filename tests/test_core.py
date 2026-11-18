
from core import (
    ScannerEngine,
    ScanRequest,
    ScanScope,
    ScanMode,
    TaskManager,
)


class TestModule:

    name = "test_module"

    def run(self, context, cancellation_event):

        return {
            "domain": context.domain,
            "message": "Modulo eseguito correttamente",
            "scan_id": context.scan_id,
        }


def test_scanner_engine():

    engine = ScannerEngine()

    engine.register_module(TestModule())

    scope = ScanScope(
        root_domain="example.com",
        mode=ScanMode.PASSIVE
    )

    request = ScanRequest(
        domain="example.com",
        scope=scope
    )

    result = engine.run_scan(request)

    assert result.status == "completed"
    assert len(result.results) == 1
    assert result.results[0].success is True


def test_invalid_domain():

    engine = ScannerEngine()

    scope = ScanScope(
        root_domain="invalid_domain",
        mode=ScanMode.PASSIVE
    )

    request = ScanRequest(
        domain="invalid_domain",
        scope=scope
    )

    result = engine.run_scan(request)

    assert result.status == "failed"


def test_task_manager():

    manager = TaskManager(max_workers=2)

    try:

        task_id, future, cancellation = manager.submit(
            lambda cancellation_event: "Task OK"
        )

        assert future.result(timeout=5) == "Task OK"
        assert manager.get_task(task_id) is not None

    finally:
        manager.shutdown()
