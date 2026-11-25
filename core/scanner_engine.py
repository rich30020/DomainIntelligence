"""Core orchestration engine for Domain Intelligence.

This module defines the request, execution context, per-module result, and final
scan result data structures. It also provides the engine that validates a scan's
scope, runs the selected analysis modules, isolates module failures, supports
cooperative cancellation, and emits lifecycle events for the graphical interface.
"""


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
    """Describe one scan, including its authorization scope and selected modules."""

    domain: str
    scope: ScanScope

    selected_modules: list[str] = field(
        default_factory=list
    )
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanContext:
    """Share scan identity and caller-provided metadata with analysis modules."""

    scan_id: str
    domain: str
    scope: ScanScope

    started_at: str

    metadata: dict = field(
        default_factory=dict
    )
    


@dataclass
class ModuleResult:
    """Capture one module execution outcome without failing the whole scan."""

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
    """Aggregate scan status, timestamps, and ordered module results."""

    scan_id: str
    domain: str

    status: str

    results: list[ModuleResult] = field(
        default_factory=list
    )

    started_at: str | None = None
    completed_at: str | None = None


class ScannerEngine:
    """Coordinate validation, scope enforcement, module execution, and events.

    Modules are registered by name and invoked independently. A module-level
    exception is recorded in its result so later modules can still run. Modules
    that require active checks are skipped unless the domain is explicitly
    included in the authorization scope.
    """

    def __init__(self, event_manager=None):

        self.events = event_manager or EventManager()

        self.scope_manager = ScopeManager()

        self.modules = {}

    def register_module(self, module):
        """Register a module exposing a unique ``name`` and callable ``run``."""

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
        """Return whether the value has a syntactically valid DNS hostname format."""

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
        """Execute requested modules and return the complete scan outcome.

        Cancellation is cooperative: the engine checks the event between
        modules, while each long-running module should also check it internally.
        """

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

            # Canonicalize once so validation, scope checks, and modules all use
            # the same lowercase hostname without a trailing root dot.
            domain = (
                request.domain.strip()
                .lower()
                .rstrip(".")
            )

            if not self.validate_domain(domain):
                raise ValueError(
                    "Il dominio inserito non è valido."
                )

            # Enforce the declared scope before building context or invoking
            # modules. This is the central authorization gate for each scan.
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

            # An empty selection means all registered modules; otherwise keep
            # the user's requested order for predictable output and progress.
            selected_modules = (
                request.selected_modules
                or list(self.modules.keys())
            )

            for module_name in selected_modules:

                # Do not start another module after a cancellation request.
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

                # Passive checks are the default. Active modules must declare
                # this requirement and pass the explicit authorization check.
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

                # Isolate failures per module: a failed source or parser should
                # be recorded without discarding successful results from others.
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
