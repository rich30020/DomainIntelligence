
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Domain:

    name: str
    normalized_name: str

    tld: str = ""
    is_valid: bool = False

    rdap_info: dict[str, Any] = field(
        default_factory=dict
    )

    dns_info: dict[str, Any] = field(
        default_factory=dict
    )

    certificate_info: dict[str, Any] = field(
        default_factory=dict
    )

    created_at: str = field(
        default_factory=lambda:
        datetime.now(timezone.utc).isoformat()
    )
