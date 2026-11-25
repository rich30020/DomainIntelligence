from datetime import datetime, timedelta, timezone

import pytest
from PySide6.QtCore import QCoreApplication

from services.scheduled_scan_manager import ScheduledScanManager


class FakeDatabase:
    def __init__(self, schedules):
        self.schedules = schedules
        self.saved = []
        self.marked = []

    def get_due_schedules(self):
        return list(self.schedules)

    def save_scan_result(self, result):
        self.saved.append(result)

    def mark_schedule_run(self, schedule_id, **kwargs):
        self.marked.append((schedule_id, kwargs))


class FakeEngine:
    pass


@pytest.fixture
def app():
    instance = QCoreApplication.instance()
    if instance is None:
        instance = QCoreApplication([])
    return instance


def test_manager_starts_and_timer_uses_configured_interval(app):
    db = FakeDatabase([])
    manager = ScheduledScanManager(FakeEngine(), db, check_interval_ms=5000)
    manager.start()
    assert manager.timer.isActive()
    assert manager.timer.interval() == 5000
    manager.shutdown()


def test_manager_pause_and_resume(app):
    manager = ScheduledScanManager(FakeEngine(), FakeDatabase([]))
    manager.start()
    manager.pause()
    assert not manager.timer.isActive()
    manager.resume()
    assert manager.timer.isActive()
    manager.shutdown()


def test_manager_does_not_start_when_paused(app):
    db = FakeDatabase([{
        "id": 1, "domain": "example.com",
        "selected_modules": ["domain_scanner"],
    }])
    manager = ScheduledScanManager(FakeEngine(), db)
    manager.pause()
    manager.check_due_schedules()
    assert manager.thread is None
    manager.shutdown()


def test_manager_ignores_when_no_due_schedules(app):
    db = FakeDatabase([])
    manager = ScheduledScanManager(FakeEngine(), db)
    manager.check_due_schedules()
    assert manager.thread is None
    manager.shutdown()
