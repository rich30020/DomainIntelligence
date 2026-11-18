
import re

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Event
from typing import Any
from uuid import uuid4

from core.event_manager import EventManager
from core.scope_manager import (
    ScanScope,
    ScopeManager,
)


@dataclass
class ScanRequest:

    domain: str
    scope: ScanScope

    selected_modules: list[str] = field(
        default_factory=list
    )
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanContext:

    scan_id: str
    domain: str
    scope: ScanScope

    started_at: str

    metadata: dict = field(
        default_factory=dict
    )
    


@dataclass
class ModuleResult:

    module_name: str
    success: bool

    data: dict = field(
        default_factory=dict
    )

    error: str | None = None

    completed_at: str = field(
        default_factory=lambda:
        datetime.now(timezone.utc).isoformat()
    )


@dataclass
class ScanResult:

    scan_id: str
    domain: str

    status: str

    results: list[ModuleResult] = field(
        default_factory=list
    )

    started_at: str | None = None
    completed_at: str | None = None


class ScannerEngine:
    """
    Motore centrale di Domain Intelligence.
    """

    def __init__(self, event_manager=None):

        self.events = event_manager or EventManager()

        self.scope_manager = ScopeManager()

        self.modules = {}

    def register_module(self, module):

        if not hasattr(module, "name"):
            raise ValueError(
                "Il modulo deve avere un attributo name."
            )

        if not callable(getattr(module, "run", None)):
            raise ValueError(
                "Il modulo deve implementare run()."
            )

        self.modules[module.name] = module

    @staticmethod
    def validate_domain(domain: str) -> bool:

        if not isinstance(domain, str):
            return False

        domain = domain.strip().lower().rstrip(".")

        if not domain or len(domain) > 253:
            return False

        pattern = (
            r"^(?=.{1,253}$)"
            r"(?:[a-z0-9]"
            r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z]{2,63}$"
        )

        return bool(re.fullmatch(pattern, domain))

    def run_scan(
        self,
        request: ScanRequest,
        cancellation_event: Event | None = None
    ) -> ScanResult:

        cancellation_event = (
            cancellation_event or Event()
        )

        scan_id = str(uuid4())

        started_at = datetime.now(
            timezone.utc
        ).isoformat()

        result = ScanResult(
            scan_id=scan_id,
            domain=request.domain,
            status="running",
            started_at=started_at
        )

        try:

            domain = (
                request.domain.strip()
                .lower()
                .rstrip(".")
            )

            if not self.validate_domain(domain):
                raise ValueError(
                    "Il dominio inserito non è valido."
                )

            if not self.scope_manager.validate_scope(
                request.scope
            ):
                if request.scope.root_domain != domain:
                    raise PermissionError(
                        "Il dominio richiesto non corrisponde "
                        "al dominio autorizzato."
                )
                
                raise PermissionError(
                    "Ambito di analisi non valido."
                )

            context = ScanContext(
                scan_id=scan_id,
                domain=domain,
                scope=request.scope,
                started_at=started_at,
                metadata=request.metadata,
            )

            self.events.emit(
                "scan_started",
                {
                    "scan_id": scan_id,
                    "domain": domain
                }
            )

            selected_modules = (
                request.selected_modules
                or list(self.modules.keys())
            )

            for module_name in selected_modules:

                if cancellation_event.is_set():
                    result.status = "cancelled"
                    break

                module = self.modules.get(module_name)

                if module is None:

                    result.results.append(
                        ModuleResult(
                            module_name=module_name,
                            success=False,
                            error="Modulo non registrato."
                        )
                    )

                    continue

                self.events.emit(
                    "module_started",
                    {
                        "scan_id": scan_id,
                        "module": module_name
                    }
                )

                requires_active = getattr(
                    module,
                    "requires_active",
                    False
                )

                if requires_active and not self.scope_manager.is_active_allowed(
                    domain,
                    request.scope
                ):
                    result.results.append(
                        ModuleResult(
                            module_name=module_name,
                            success=False,
                            error="Verifica attiva non autorizzata."
                        )
                    )
                    continue

                try:

                    module_data = module.run(
                        context,
                        cancellation_event
                    )

                    if cancellation_event.is_set():
                        result.status = "cancelled"
                        break

                    module_result = ModuleResult(
                        module_name=module_name,
                        success=True,
                        data=module_data or {}
                    )

                except Exception as exc:

                    module_result = ModuleResult(
                        module_name=module_name,
                        success=False,
                        error=str(exc)
                    )

                result.results.append(module_result)

                self.events.emit(
                    "module_completed",
                    {
                        "scan_id": scan_id,
                        "module": module_name,
                        "success": module_result.success
                    }
                )

            else:
                result.status = "completed"

            self.events.emit(
                "scan_completed",
                {
                    "scan_id": scan_id,
                    "status": result.status
                }
            )

        except Exception as exc:

            result.status = "failed"

            self.events.emit(
                "scan_error",
                {
                    "scan_id": scan_id,
                    "error": str(exc)
                }
            )

        finally:

            result.completed_at = datetime.now(
                timezone.utc
            ).isoformat()

        return result
