import json

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from models.db_models import (
    Base,
    ScanRecord,
    ModuleRecord,
    FindingRecord,
)


class DatabaseService:

    def __init__(self, database_path=None):
        if database_path is None:
            project_root = Path(__file__).resolve().parent.parent
            database_path = (
                project_root
                / "data"
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

    def close(self):
        self.engine.dispose()