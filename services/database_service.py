import json
import re

from datetime import datetime, timezone, timedelta
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app_paths import get_writable_dir
from models.db_models import (
    Base,
    ScanRecord,
    ModuleRecord,
    FindingRecord,
    ScheduledScanRecord,
    ScreenshotRecord,
)


class DatabaseService:

    def __init__(self, database_path=None):
        if database_path is None:
            database_path = (
                get_writable_dir("data")
                / "domain_intelligence.db"
            )

        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        database_url = (
            "sqlite:///"
            + self.database_path.resolve().as_posix()
        )

        self.engine = create_engine(
            database_url,
            connect_args={"check_same_thread": False},
        )

        self.Session = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
        )

        Base.metadata.create_all(self.engine)

    @staticmethod
    def _json_safe(value):
        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, datetime):
            return value.isoformat()

        if isinstance(value, Path):
            return str(value)

        if hasattr(value, "value"):
            return DatabaseService._json_safe(value.value)

        if hasattr(value, "__dataclass_fields__"):
            return {
                key: DatabaseService._json_safe(item)
                for key, item in vars(value).items()
            }

        if isinstance(value, dict):
            return {
                str(key): DatabaseService._json_safe(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [
                DatabaseService._json_safe(item)
                for item in value
            ]

        return str(value)

    @staticmethod
    def _get(value, field, default=None):
        if isinstance(value, dict):
            return value.get(field, default)

        return getattr(value, field, default)

    @staticmethod
    def _parse_datetime(value):
        if value is None:
            return None

        if isinstance(value, datetime):
            return value

        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return None

        return None

    def _extract_findings(self, scan_id, module_name, data):
        if not isinstance(data, dict):
            return []

        findings = []

        def add(
            finding_type,
            indicator,
            score=None,
            level=None,
            source=None,
            details=None,
        ):
            if not indicator:
                return

            findings.append(
                FindingRecord(
                    scan_id=scan_id,
                    finding_type=finding_type,
                    indicator=str(indicator),
                    score=score,
                    level=level,
                    source=source,
                    details=self._json_safe(details),
                )
            )

        # Sottodomini scoperti
        if module_name == "subdomain_finder":
            for item in data.get("subdomains", []):
                add(
                    finding_type="subdomain",
                    indicator=item.get("hostname"),
                    level=item.get("status"),
                    source=", ".join(item.get("sources", [])),
                    details=item,
                )

        # Domini simili
        elif module_name == "similar_domain_analyzer":
            for item in data.get("results", []):
                add(
                    finding_type="similar_domain",
                    indicator=item.get("domain"),
                    score=item.get("similarity_score"),
                    level=item.get("similarity_level"),
                    source=item.get("reason"),
                    details=item,
                )

        # Corrispondenze Threat Intelligence
        elif module_name == "threat_intel_analyzer":
            for item in data.get("results", []):
                if item.get("matched"):
                    sources = sorted({
                        match.get("source", "")
                        for match in item.get("matches", [])
                        if match.get("source")
                    })

                    add(
                        finding_type="threat_intel_match",
                        indicator=item.get("domain"),
                        score=item.get("threat_score"),
                        level=item.get("threat_level"),
                        source=", ".join(sources),
                        details=item,
                    )

        # Confronto tra siti
        elif module_name == "website_clone_analyzer":
            similarity = data.get("similarity", {})

            add(
                finding_type="website_comparison",
                indicator=data.get("comparison_domain"),
                score=similarity.get("score"),
                level=similarity.get("level"),
                source=data.get("original_domain"),
                details=data,
            )

        return findings

    def save_scan_result(self, scan_result):
        scan_id = self._get(scan_result, "scan_id")

        if not scan_id:
            raise ValueError("Scan ID mancante.")

        domain = self._get(scan_result, "domain")

        if not domain:
            raise ValueError("Dominio della scansione mancante.")

        started_at = self._parse_datetime(
            self._get(scan_result, "started_at")
        ) or datetime.now(timezone.utc)

        completed_at = self._parse_datetime(
            self._get(scan_result, "completed_at")
        )

        results = self._get(scan_result, "results", []) or []

        with self.Session() as session:
            existing = session.scalar(
                select(ScanRecord).where(
                    ScanRecord.scan_id == scan_id
                )
            )

            if existing:
                raise ValueError(
                    f"La scansione {scan_id} è già presente."
                )

            record = ScanRecord(
                scan_id=scan_id,
                domain=domain,
                status=self._get(
                    scan_result,
                    "status",
                    "unknown",
                ),
                started_at=started_at,
                completed_at=completed_at,
            )

            session.add(record)
            session.flush()

            for module_result in results:
                module_name = self._get(
                    module_result,
                    "module_name",
                    "unknown",
                )

                data = self._json_safe(
                    self._get(module_result, "data")
                )

                module_record = ModuleRecord(
                    scan_id=scan_id,
                    module_name=module_name,
                    success=bool(
                        self._get(module_result, "success", False)
                    ),
                    error=self._get(module_result, "error"),
                    completed_at=str(
                        self._get(module_result, "completed_at")
                        or ""
                    ) or None,
                    data=data,
                )

                session.add(module_record)

                findings = self._extract_findings(
                    scan_id,
                    module_name,
                    data,
                )

                session.add_all(findings)

            session.commit()

        return {
            "success": True,
            "scan_id": scan_id,
            "modules_saved": len(results),
        }

    def get_scan_history(self, limit=100):
        limit = max(1, min(int(limit), 1000))

        with self.Session() as session:
            records = session.scalars(
                select(ScanRecord)
                .order_by(ScanRecord.id.desc())
                .limit(limit)
            ).all()

            return [
                {
                    "scan_id": item.scan_id,
                    "domain": item.domain,
                    "status": item.status,
                    "started_at": (
                        item.started_at.isoformat()
                        if item.started_at else None
                    ),
                    "completed_at": (
                        item.completed_at.isoformat()
                        if item.completed_at else None
                    ),
                    "modules_count": len(item.modules),
                    "findings_count": len(item.findings),
                }
                for item in records
            ]

    def get_scan_details(self, scan_id):
        with self.Session() as session:
            record = session.scalar(
                select(ScanRecord).where(
                    ScanRecord.scan_id == scan_id
                )
            )

            if record is None:
                return None

            return {
                "scan_id": record.scan_id,
                "domain": record.domain,
                "status": record.status,
                "started_at": (
                    record.started_at.isoformat()
                    if record.started_at else None
                ),
                "completed_at": (
                    record.completed_at.isoformat()
                    if record.completed_at else None
                ),
                "modules": [
                    {
                        "module_name": item.module_name,
                        "success": item.success,
                        "error": item.error,
                        "data": item.data,
                    }
                    for item in record.modules
                ],
                "findings": [
                    {
                        "finding_type": item.finding_type,
                        "indicator": item.indicator,
                        "score": item.score,
                        "level": item.level,
                        "source": item.source,
                        "details": item.details,
                    }
                    for item in record.findings
                ],
            }


    @staticmethod
    def _normalize_utc(value):
        """Converte un datetime in UTC naive per compatibilità SQLite."""
        if not isinstance(value, datetime):
            raise ValueError("La data deve essere un oggetto datetime.")
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    @staticmethod
    def _schedule_to_dict(item):
        def iso(value):
            if value is None:
                return None
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).isoformat()

        return {
            "id": item.id,
            "name": item.name,
            "domain": item.domain,
            "selected_modules": list(item.selected_modules or []),
            "interval_minutes": item.interval_minutes,
            "enabled": item.enabled,
            "created_at": iso(item.created_at),
            "next_run_at": iso(item.next_run_at),
            "last_run_at": iso(item.last_run_at),
            "last_scan_id": item.last_scan_id,
            "last_error": item.last_error,
            "run_count": item.run_count,
            "failure_count": item.failure_count,
        }

    @staticmethod
    def _validate_schedule(domain, selected_modules, interval_minutes):
        domain = str(domain or "").strip().lower().rstrip(".")
        pattern = (
            r"(?=.{1,253}$)"
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z]{2,63}"
        )
        if not re.fullmatch(pattern, domain):
            raise ValueError("Dominio non valido per la pianificazione.")

        if isinstance(selected_modules, str):
            raise ValueError("selected_modules deve essere una lista di moduli.")
        modules = sorted({str(value).strip() for value in (selected_modules or []) if str(value).strip()})
        if not modules:
            raise ValueError("Seleziona almeno un modulo.")
        if any(len(value) > 100 for value in modules):
            raise ValueError("Nome modulo troppo lungo.")

        try:
            interval = int(interval_minutes)
        except (TypeError, ValueError):
            raise ValueError("Intervallo non valido.") from None
        if interval < 15 or interval > 43200:
            raise ValueError("L'intervallo deve essere compreso tra 15 e 43200 minuti.")
        return domain, modules, interval

    def create_schedule(
        self, domain, selected_modules, interval_minutes,
        next_run_at=None, name=None, enabled=True,
    ):
        domain, modules, interval = self._validate_schedule(
            domain, selected_modules, interval_minutes
        )
        now = datetime.now(timezone.utc)
        next_run = self._normalize_utc(next_run_at or (now + timedelta(minutes=interval)))
        clean_name = str(name or f"Monitoraggio {domain}").strip()
        if not clean_name or len(clean_name) > 120:
            raise ValueError("Il nome deve contenere da 1 a 120 caratteri.")

        with self.Session() as session:
            record = ScheduledScanRecord(
                name=clean_name,
                domain=domain,
                selected_modules=modules,
                interval_minutes=interval,
                enabled=bool(enabled),
                next_run_at=next_run,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return self._schedule_to_dict(record)

    def get_schedules(self, include_disabled=True):
        with self.Session() as session:
            statement = select(ScheduledScanRecord).order_by(ScheduledScanRecord.id.desc())
            if not include_disabled:
                statement = statement.where(ScheduledScanRecord.enabled.is_(True))
            return [self._schedule_to_dict(item) for item in session.scalars(statement).all()]

    def get_schedule(self, schedule_id):
        with self.Session() as session:
            item = session.get(ScheduledScanRecord, int(schedule_id))
            return self._schedule_to_dict(item) if item else None

    def update_schedule(self, schedule_id, **changes):
        allowed = {"name", "domain", "selected_modules", "interval_minutes", "enabled", "next_run_at"}
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"Campi non modificabili: {', '.join(sorted(unknown))}")

        with self.Session() as session:
            item = session.get(ScheduledScanRecord, int(schedule_id))
            if item is None:
                return None

            domain = changes.get("domain", item.domain)
            modules = changes.get("selected_modules", item.selected_modules)
            interval = changes.get("interval_minutes", item.interval_minutes)
            domain, modules, interval = self._validate_schedule(domain, modules, interval)
            item.domain = domain
            item.selected_modules = modules
            item.interval_minutes = interval

            if "name" in changes:
                name = str(changes["name"] or "").strip()
                if not name or len(name) > 120:
                    raise ValueError("Il nome deve contenere da 1 a 120 caratteri.")
                item.name = name
            if "enabled" in changes:
                item.enabled = bool(changes["enabled"])
            if "next_run_at" in changes:
                item.next_run_at = self._normalize_utc(changes["next_run_at"])

            session.commit()
            session.refresh(item)
            return self._schedule_to_dict(item)

    def set_schedule_enabled(self, schedule_id, enabled):
        return self.update_schedule(schedule_id, enabled=enabled)

    def delete_schedule(self, schedule_id):
        with self.Session() as session:
            item = session.get(ScheduledScanRecord, int(schedule_id))
            if item is None:
                return False
            session.delete(item)
            session.commit()
            return True

    def get_due_schedules(self, now=None):
        reference = self._normalize_utc(now or datetime.now(timezone.utc))
        with self.Session() as session:
            statement = (
                select(ScheduledScanRecord)
                .where(
                    ScheduledScanRecord.enabled.is_(True),
                    ScheduledScanRecord.next_run_at <= reference,
                )
                .order_by(ScheduledScanRecord.next_run_at.asc())
            )
            return [self._schedule_to_dict(item) for item in session.scalars(statement).all()]

    def mark_schedule_run(
        self, schedule_id, ran_at=None, next_run_at=None,
        scan_id=None, error=None,
    ):
        ran = self._normalize_utc(ran_at or datetime.now(timezone.utc))
        with self.Session() as session:
            item = session.get(ScheduledScanRecord, int(schedule_id))
            if item is None:
                return None
            item.last_run_at = ran
            item.next_run_at = self._normalize_utc(
                next_run_at or (ran + timedelta(minutes=item.interval_minutes))
            )
            item.last_scan_id = str(scan_id) if scan_id else None
            item.last_error = str(error)[:4000] if error else None
            item.run_count += 1
            item.failure_count = item.failure_count + 1 if error else 0
            session.commit()
            session.refresh(item)
            return self._schedule_to_dict(item)


    def save_screenshot_record(self, capture_result, comparison=None):
        """Salva metadati e percorso locale di uno screenshot acquisito."""
        def get_value(name, default=None):
            if isinstance(capture_result, dict):
                return capture_result.get(name, default)
            return getattr(capture_result, name, default)

        captured_at = self._parse_datetime(get_value("captured_at")) or datetime.now(timezone.utc)
        comparison = comparison or {}
        if not isinstance(comparison, dict):
            comparison = self._json_safe(comparison)
        record = ScreenshotRecord(
            domain=str(get_value("hostname", "")).strip().lower(),
            url=str(get_value("url", "")),
            screenshot_path=str(get_value("screenshot_path", "")),
            page_title=str(get_value("title", ""))[:500] or None,
            description=str(get_value("description", "")) or None,
            captured_at=captured_at,
            page_width=get_value("page_width"),
            page_height=get_value("page_height"),
            comparison_reference=comparison.get("reference_path"),
            similarity_percent=comparison.get("similarity_percent"),
            assessment=comparison.get("assessment"),
        )
        if not record.domain or not record.url or not record.screenshot_path:
            raise ValueError("Dati screenshot incompleti.")
        with self.Session() as session:
            session.add(record)
            session.commit()
            session.refresh(record)
            return self._screenshot_to_dict(record)


    def update_screenshot_comparison(self, record_id, comparison):
        """Aggiorna il confronto sul record acquisizione esistente, senza duplicarlo."""
        if not isinstance(comparison, dict):
            raise TypeError("comparison deve essere un dizionario.")
        with self.Session() as session:
            item = session.get(ScreenshotRecord, int(record_id))
            if item is None:
                raise ValueError(f"Screenshot con ID {record_id} non trovato.")
            item.comparison_reference = comparison.get("reference_path")
            item.similarity_percent = comparison.get("similarity_percent")
            item.phash_distance = comparison.get("phash_distance")
            item.assessment = comparison.get("assessment")
            session.commit()
            session.refresh(item)
            return self._screenshot_to_dict(item)

    def get_screenshot_record(self, record_id):
        """Restituisce il dettaglio di una singola acquisizione."""
        with self.Session() as session:
            item = session.get(ScreenshotRecord, int(record_id))
            return self._screenshot_to_dict(item) if item is not None else None

    @staticmethod
    def _screenshot_to_dict(item):
        return {
            "id": item.id,
            "domain": item.domain,
            "url": item.url,
            "screenshot_path": item.screenshot_path,
            "page_title": item.page_title,
            "description": item.description,
            "captured_at": item.captured_at.isoformat() if item.captured_at else None,
            "page_width": item.page_width,
            "page_height": item.page_height,
            "comparison_reference": item.comparison_reference,
            "similarity_percent": item.similarity_percent,
            "phash_distance": item.phash_distance,
            "assessment": item.assessment,
        }

    def get_screenshot_history(self, limit=100):
        limit = max(1, min(int(limit), 1000))
        with self.Session() as session:
            items = session.scalars(
                select(ScreenshotRecord)
                .order_by(ScreenshotRecord.id.desc())
                .limit(limit)
            ).all()
            return [self._screenshot_to_dict(item) for item in items]

    def close(self):
        self.engine.dispose()