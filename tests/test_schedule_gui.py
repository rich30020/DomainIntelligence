"""Automated tests for test schedule gui.

These tests protect expected behavior and help detect regressions in the
Domain Intelligence implementation.
"""


from datetime import datetime, timezone
from PySide6.QtWidgets import QApplication
import pytest

from gui.main_window import MainWindow


class FakeDatabase:
    def __init__(self):
        self.items = []
        self.next_id = 1

    def create_schedule(self, domain, selected_modules, interval_minutes):
        item = {
            "id": self.next_id, "name": f"Monitoraggio {domain}",
            "domain": domain, "selected_modules": selected_modules,
            "interval_minutes": interval_minutes, "enabled": True,
            "next_run_at": datetime.now(timezone.utc).isoformat(),
            "last_run_at": None, "run_count": 0, "failure_count": 0,
        }
        self.items.append(item)
        self.next_id += 1
        return item

    def get_schedules(self, include_disabled=True):
        return list(self.items)

    def get_schedule(self, schedule_id):
        return next((x for x in self.items if x["id"] == schedule_id), None)

    def set_schedule_enabled(self, schedule_id, enabled):
        item = self.get_schedule(schedule_id)
        item["enabled"] = enabled
        return item

    def delete_schedule(self, schedule_id):
        self.items = [x for x in self.items if x["id"] != schedule_id]
        return True


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    yield instance


def test_schedule_interval_labels():
    """Verify expected behavior for schedule interval labels.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    assert MainWindow._format_schedule_interval(15) == "Ogni 15 min"
    assert MainWindow._format_schedule_interval(60) == "Ogni 1 h"
    assert MainWindow._format_schedule_interval(1440) == "Ogni 1 g"


def test_schedule_table_loads(app):
    """Verify expected behavior for schedule table loads.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    db = FakeDatabase()
    db.create_schedule("example.com", ["domain_scanner"], 60)
    window = MainWindow(database_service=db)
    assert window.schedules_table.rowCount() == 1
    assert window.schedules_table.item(0, 2).text() == "example.com"
    window.close()


def test_create_schedule_from_ui(app):
    """Verify expected behavior for create schedule from ui.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    db = FakeDatabase()
    window = MainWindow(database_service=db)
    window.schedule_domain_input.setText("example.org")
    window.create_schedule()
    assert len(db.items) == 1
    assert db.items[0]["domain"] == "example.org"
    assert "domain_scanner" in db.items[0]["selected_modules"]
    window.close()


def test_toggle_and_delete_schedule(app):
    """Verify expected behavior for toggle and delete schedule.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    db = FakeDatabase()
    db.create_schedule("example.net", ["domain_scanner"], 30)
    window = MainWindow(database_service=db)
    window.schedules_table.selectRow(0)
    window.toggle_selected_schedule()
    assert db.items[0]["enabled"] is False
    # Call the delete path with an automated confirmation not suitable for UI tests;
    # verify the database-backed action directly.
    assert db.delete_schedule(1) is True
    window.load_schedules()
    assert window.schedules_table.rowCount() == 0
    window.close()
