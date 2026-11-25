
"""Represent and validate the authorized scope of a domain assessment."""

from enum import Enum
from dataclasses import dataclass, field


class ScanMode(Enum):
    """Distinguish public-data collection from explicitly authorized checks."""
    PASSIVE = "passive"
    AUTHORIZED = "authorized"


@dataclass
class ScanScope:
    """Declare the root domain, scan mode, and domains approved for active checks."""

    root_domain: str
    mode: ScanMode = ScanMode.PASSIVE

    authorized_domains: set[str] = field(
        default_factory=set
    )

    def __post_init__(self):
        self.root_domain = self.root_domain.lower().strip().rstrip(".")

        self.authorized_domains = {
            domain.lower().strip().rstrip(".")
            for domain in self.authorized_domains
        }


class ScopeManager:
    """Apply the scope rules used by the scanner before a module is run.

    Passive analysis may use public information. Active analysis is permitted
    only in ``AUTHORIZED`` mode and only for exact hostnames listed in
    ``authorized_domains``; authorization is never inferred from similarity.
    """

    def is_passive_allowed(self, scope: ScanScope) -> bool:
        """Check whether passive analysis is permitted for this scope."""
        return scope.mode in (
            ScanMode.PASSIVE,
            ScanMode.AUTHORIZED
        )

    def is_active_allowed(
        self,
        domain: str,
        scope: ScanScope
    ) -> bool:
        """Allow an active check only for an exact authorized hostname."""

        domain = domain.lower().strip().rstrip(".")

        if scope.mode != ScanMode.AUTHORIZED:
            return False

        if domain in scope.authorized_domains:
            return True

        return False

    def validate_scope(self, scope: ScanScope) -> bool:
        """Validate that the scope contains a root domain and is internally consistent."""

        if not scope.root_domain:
            return False

        # Authorized mode must explicitly include the root domain so the
        # scope cannot silently broaden the target set.
        if scope.mode == ScanMode.AUTHORIZED:
            return scope.root_domain in scope.authorized_domains

        return True
