from datetime import datetime, timedelta, timezone

import pytest

from services.database_service import DatabaseService


@pytest.fixture
def db(tmp_path):
    service = DatabaseService(tmp_path / "test.db")
    yield service
    service.close()


def create_one(db, **kwargs):
    values = {
        "domain": "example.com",
        "selected_modules": ["domain_scanner", "subdomain_finder"],
        "interval_minutes": 60,
    }
    values.update(kwargs)
    return db.create_schedule(**values)


def test_create_and_get_schedule(db):
    item = create_one(db, name="Test periodico")
    assert item["id"] > 0
    assert item["domain"] == "example.com"
    assert item["selected_modules"] == ["domain_scanner", "subdomain_finder"]
    assert item["interval_minutes"] == 60
    assert item["enabled"] is True
    assert db.get_schedule(item["id"])["name"] == "Test periodico"


def test_schedule_persists_after_service_reopen(tmp_path):
    path = tmp_path / "persistent.db"
    first = DatabaseService(path)
    item = create_one(first)
    first.close()

    second = DatabaseService(path)
    assert second.get_schedule(item["id"])["domain"] == "example.com"
    second.close()


def test_validation_rejects_bad_domain(db):
    with pytest.raises(ValueError, match="Dominio non valido"):
        create_one(db, domain="https://example.com/path")


def test_validation_rejects_empty_modules(db):
    with pytest.raises(ValueError, match="almeno un modulo"):
        create_one(db, selected_modules=[])


@pytest.mark.parametrize("interval", [0, 14, 43201, "abc"])
def test_validation_rejects_bad_interval(db, interval):
    with pytest.raises(ValueError):
        create_one(db, interval_minutes=interval)


def test_update_schedule_fields(db):
    item = create_one(db)
    updated = db.update_schedule(
        item["id"],
        name="Nuovo nome",
        domain="example.org",
        selected_modules=["threat_intel_analyzer"],
        interval_minutes=120,
    )
    assert updated["name"] == "Nuovo nome"
    assert updated["domain"] == "example.org"
    assert updated["selected_modules"] == ["threat_intel_analyzer"]
    assert updated["interval_minutes"] == 120


def test_enable_disable_and_filter(db):
    item = create_one(db)
    assert len(db.get_schedules(include_disabled=False)) == 1
    db.set_schedule_enabled(item["id"], False)
    assert db.get_schedule(item["id"])["enabled"] is False
    assert db.get_schedules(include_disabled=False) == []


def test_due_schedules_only_returns_enabled_overdue(db):
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    due = create_one(db, next_run_at=now - timedelta(minutes=1))
    create_one(db, next_run_at=now + timedelta(minutes=1))
    disabled = create_one(db, next_run_at=now - timedelta(minutes=2))
    db.set_schedule_enabled(disabled["id"], False)

    results = db.get_due_schedules(now)
    assert [item["id"] for item in results] == [due["id"]]


def test_mark_schedule_run_updates_counters_and_timestamps(db):
    item = create_one(db)
    ran = datetime(2026, 2, 1, 10, 0, tzinfo=timezone.utc)
    next_run = ran + timedelta(minutes=60)
    updated = db.mark_schedule_run(
        item["id"], ran_at=ran, next_run_at=next_run,
        scan_id="scan-123", error="fonte non disponibile",
    )
    assert updated["run_count"] == 1
    assert updated["failure_count"] == 1
    assert updated["last_scan_id"] == "scan-123"
    assert updated["last_error"] == "fonte non disponibile"
    assert updated["next_run_at"].startswith("2026-02-01T11:00:00")

    updated = db.mark_schedule_run(item["id"], ran_at=next_run)
    assert updated["run_count"] == 2
    assert updated["failure_count"] == 0
    assert updated["last_error"] is None


def test_delete_schedule(db):
    item = create_one(db)
    assert db.delete_schedule(item["id"]) is True
    assert db.get_schedule(item["id"]) is None
    assert db.delete_schedule(item["id"]) is False


def test_unknown_update_field_is_rejected(db):
    item = create_one(db)
    with pytest.raises(ValueError, match="non modificabili"):
        db.update_schedule(item["id"], run_count=999)
