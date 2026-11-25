"""Import, validate, normalize, and deduplicate local IOC feed records."""

import csv
import ipaddress

from pathlib import Path

from models.ioc import IOC


class ThreatIntelStore:
    """Hold validated IOC records loaded from local CSV feeds.

    This service performs no network lookups. Feed provenance is preserved on
    each IOC so later matching and risk scoring can identify independent sources.
    """

    REQUIRED_COLUMNS = {
        "indicator",
        "type",
        "source",
        "confidence",
    }

    def __init__(self):
        self.indicators = []

    @staticmethod
    def normalize_domain(domain: str) -> str | None:
        """Normalize a hostname to lowercase IDNA ASCII or return ``None``."""
        if not isinstance(domain, str):
            return None

        domain = domain.strip().lower().rstrip(".")

        if not domain or "/" in domain or ":" in domain:
            return None

        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return None

        if len(domain) > 253:
            return None

        labels = domain.split(".")

        if len(labels) < 2:
            return None

        for label in labels:
            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
            ):
                return None

            if not all(
                char.isalnum() or char == "-"
                for char in label
            ):
                return None

        return domain

    @staticmethod
    def validate_indicator(indicator: str, indicator_type: str):
        """Validate and normalize a domain, IP, hash, or HTTP(S) URL IOC."""
        if indicator_type == "domain":
            normalized = ThreatIntelStore.normalize_domain(
                indicator
            )

            if not normalized:
                raise ValueError(
                    f"Dominio IOC non valido: {indicator}"
                )

            return normalized

        if indicator_type == "ip":
            return str(ipaddress.ip_address(indicator.strip()))

        if indicator_type == "hash":
            value = indicator.strip().lower()

            if len(value) not in (32, 40, 64):
                raise ValueError("Hash non valido.")

            if not all(
                char in "0123456789abcdef"
                for char in value
            ):
                raise ValueError("Hash non valido.")

            return value

        if indicator_type == "url":
            value = indicator.strip()

            if not value.startswith(("http://", "https://")):
                raise ValueError("URL IOC non valido.")

            return value

        raise ValueError("Tipo IOC non supportato.")

    def import_csv(self, csv_path: str) -> dict:
        """Import valid CSV rows and report rejected rows without aborting the feed.

        Required columns are checked before parsing. Individual row errors are
        collected with line numbers so one malformed indicator does not prevent
        other valid records from being loaded.
        """
        path = Path(csv_path)

        if not path.exists():
            raise FileNotFoundError(csv_path)

        imported = 0
        rejected = 0
        errors = []

        with path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as file:

            reader = csv.DictReader(file)

            if not reader.fieldnames:
                raise ValueError("CSV senza intestazione.")

            missing = self.REQUIRED_COLUMNS - set(reader.fieldnames)

            if missing:
                raise ValueError(
                    f"Colonne mancanti nel CSV: {sorted(missing)}"
                )

            for line_number, row in enumerate(reader, start=2):
                try:
                    indicator_type = row["type"].strip().lower()

                    indicator = self.validate_indicator(
                        row["indicator"],
                        indicator_type,
                    )

                    ioc = IOC(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        source=row["source"],
                        confidence=int(row["confidence"]),
                        first_seen=row.get("first_seen") or None,
                        last_seen=row.get("last_seen") or None,
                        description=row.get("description") or None,
                    )

                    # The same indicator may legitimately appear in multiple
                    # feeds; deduplicate only when type and source also match.
                    key = (
                        ioc.indicator,
                        ioc.indicator_type,
                        ioc.source,
                    )

                    existing = {
                        (
                            item.indicator,
                            item.indicator_type,
                            item.source,
                        )
                        for item in self.indicators
                    }

                    if key not in existing:
                        self.indicators.append(ioc)
                        imported += 1

                except (ValueError, TypeError, AttributeError) as exc:
                    rejected += 1
                    errors.append({
                        "line": line_number,
                        "error": str(exc),
                    })

        return {
            "imported": imported,
            "rejected": rejected,
            "total": len(self.indicators),
            "errors": errors,
        }

    def get_domain_indicators(self) -> list[IOC]:
        """Return only domain-type indicators for domain/subdomain matching."""
        return [
            item
            for item in self.indicators
            if item.indicator_type == "domain"
        ]