from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class IOC:
    indicator: str
    indicator_type: str
    source: str
    confidence: int = 50
    first_seen: str | None = None
    last_seen: str | None = None
    description: str | None = None

    def __post_init__(self):
        self.indicator = self.indicator.strip().lower()
        self.indicator_type = self.indicator_type.strip().lower()
        self.source = self.source.strip()

        if not self.indicator:
            raise ValueError("Indicatore vuoto.")

        if self.indicator_type not in {
            "domain", "url", "ip", "hash"
        }:
            raise ValueError("Tipo IOC non supportato.")

        if not 0 <= self.confidence <= 100:
            raise ValueError(
                "La confidence deve essere compresa tra 0 e 100."
            )

        if not self.source:
            raise ValueError("La fonte dell'IOC è obbligatoria.")

    @staticmethod
    def current_timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()