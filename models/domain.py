
"""Typed representation of a domain and its collected public metadata."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Domain:
    """Hold a domain identity and optional RDAP, DNS, and certificate metadata.

    Each enrichment field is separate because the sources have different
    schemas and individual lookups can fail independently.
    """

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
