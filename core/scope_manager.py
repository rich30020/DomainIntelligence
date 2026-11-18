
from enum import Enum
from dataclasses import dataclass, field


class ScanMode(Enum):
    PASSIVE = "passive"
    AUTHORIZED = "authorized"


@dataclass
class ScanScope:

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
    """
    Controlla l'ambito consentito delle analisi.
    """

    def is_passive_allowed(self, scope: ScanScope) -> bool:
        return scope.mode in (
            ScanMode.PASSIVE,
            ScanMode.AUTHORIZED
        )

    def is_active_allowed(
        self,
        domain: str,
        scope: ScanScope
    ) -> bool:

        domain = domain.lower().strip().rstrip(".")

        if scope.mode != ScanMode.AUTHORIZED:
            return False

        if domain in scope.authorized_domains:
            return True

        return False

    def validate_scope(self, scope: ScanScope) -> bool:

        if not scope.root_domain:
            return False

        if scope.mode == ScanMode.AUTHORIZED:
            return scope.root_domain in scope.authorized_domains

        return True
