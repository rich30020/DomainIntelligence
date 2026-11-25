# Domain Intelligence — Code Architecture

This guide complements the inline comments and docstrings in the Python source. It explains how the main application layers cooperate and clarifies the security boundaries that are easy to miss when reading individual functions.

## 1. Application startup

`main.py` is the composition root:

1. Qt creates the application object.
2. The local threat-intelligence store is initialized and the bundled sample IOC CSV is imported when it exists.
3. `create_scanner_engine()` creates the central `ScannerEngine` and registers the analysis modules.
4. A shared `DatabaseService` is created for scan history and scheduled-scan persistence.
5. `ScheduledScanManager` is connected to the same scanner and database services.
6. `MainWindow` receives these services and builds the user interface.
7. On application shutdown, scheduled work is stopped before the database engine is closed.

The GUI, manual scans, and scheduled scans therefore use the same module registry and persistence layer.

## 2. Scan request and execution lifecycle

The core scan data flow is:

`ScanRequest → ScannerEngine.run_scan() → ScanContext → Analysis modules → ModuleResult[] → ScanResult`

- **ScanRequest** carries the target domain, the declared `ScanScope`, the selected module names, and optional metadata.
- **ScanScope** states whether the run is passive or explicitly authorized and records the exact hostnames approved for active checks.
- **ScanContext** gives every module the same scan identifier, normalized domain, scope, start time, and metadata.
- **ModuleResult** records one module's success, returned data, error, and completion time.
- **ScanResult** aggregates all module outcomes and the overall scan status.

The engine normalizes and validates the domain before executing modules. It validates the scope before constructing the shared context. A missing module is recorded as an unsuccessful module result. Exceptions raised by one module are isolated and recorded so later modules can continue.

Cancellation is cooperative. The engine checks the cancellation event between modules and after a module returns. A long-running module should also inspect the same event during its own work.

## 3. Scope and authorization boundary

`ScopeManager` provides the central scope checks:

- Passive collection is the default mode for public-data sources.
- A module that declares `requires_active = True` is not run unless the scan scope is in authorized mode and the exact target hostname appears in `authorized_domains`.
- Authorization is exact-host based. Similarity to an authorized brand or domain does not grant authorization to another hostname.

The scope check is an application control. Operators must still ensure that their use of the application complies with applicable law, contracts, and the permissions granted by the asset owner.

## 4. Analysis modules and source adapters

The `modules/` package contains focused analyzers rather than one monolithic scanner:

- **DomainScanner** collects registration, DNS, and certificate metadata.
- **SubdomainFinder** combines Certificate Transparency, HackerTarget, and OTX observations, then normalizes, deduplicates, and verifies DNS records.
- **SimilarDomainAnalyzer** generates lookalike candidates and enriches a bounded set using public RDAP information.
- **ThreatIntelAnalyzer** compares domain indicators against the locally loaded IOC store.
- **WebsiteCloneAnalyzer** fetches and compares website metadata for explicitly authorized targets.
- **ImageHashAnalyzer** and **ImageSimilarityAnalyzer** calculate and compare perceptual hashes for local image files.
- **LogoDetector** is a filename-keyword heuristic; it does not perform visual logo recognition.
- **ScreenshotVisualAnalyzer** compares local screenshots using perceptual image fingerprints.

The `modules/sources/` package contains adapters for external public-data providers. Provider errors and rate limits should be treated as source-availability limitations, not as proof that a domain is benign or malicious.

## 5. Threat intelligence and risk indicator

`ThreatIntelStore` imports CSV records, validates supported indicator types, normalizes values, and retains source provenance. Duplicate rows are collapsed only when indicator, type, and source all match.

`ThreatIntelAnalyzer` performs local comparisons and reports matches with their source and confidence values. It does not visit target websites or issue network requests.

`RiskScoringService` uses only IOC matches returned by the Threat Intelligence module. It uses the highest reported IOC confidence as the base and adds a small bounded bonus for additional distinct sources.

Important interpretation rules:

- No IOC match means **not evaluable**, not safe.
- A score is a source-confidence indicator, not a probability of maliciousness.
- Similar-domain scores, DNS presence, registration data, valid TLS, and source errors are not treated as proof of malicious activity.

## 6. Website and screenshot safety controls

The website analysis path is guarded by explicit authorization and network restrictions.

- Website fetching uses HTTPS and validates DNS answers as globally routable addresses.
- The HTTPS connection is pinned to a validated IP while retaining hostname SNI and certificate verification.
- Redirects are rejected and response bodies are capped.
- Screenshot capture requires HTTPS, an exact hostname allowlist, and public IP resolution.
- Chromium requests are restricted to approved hosts and pinned to validated addresses.
- The screenshot service does not submit credentials, fill forms, or interact with page controls.

These controls reduce common request-forgery and DNS-rebinding risks. They do not constitute a complete security certification or replace a review of the runtime environment.

## 7. GUI threading and scheduled work

`MainWindow` owns the widgets and translates user actions into service calls. Long-running scan operations are handled by `ScanWorker` in a `QThread`, so network lookups and analysis do not block the Qt event loop.

Signals carry scan completion and failure back to the GUI thread. The worker always emits its `finished` signal so the window can release thread references and restore controls.

`ScheduledScanManager` polls for due schedule records with a Qt timer and runs at most one scheduled scan at a time. Manual scans can pause scheduled dispatch. During shutdown, the timer is stopped and the active worker is given an opportunity to finish before the database is closed.

## 8. Persistence and reporting

`DatabaseService` stores scan records, per-module output, normalized findings, scheduled-scan configuration, and screenshot metadata. Each operation uses its own SQLAlchemy session so transaction boundaries remain explicit.

`ReportExportService` converts the structured scan result to CSV or PDF:

- CSV values are neutralized when they could be interpreted as spreadsheet formulas.
- PDF text is escaped before it is passed to ReportLab markup.
- Structured module output is included as data, not interpreted as markup.

## 9. Suggested reading order

For a developer new to the codebase, this sequence follows the primary execution path:

1. `main.py`
2. `core/scanner_engine.py`
3. `core/scope_manager.py`
4. `gui/main_window.py` and `gui/scan_worker.py`
5. `modules/subdomain_finder.py` and `modules/threat_intel_analyzer.py`
6. `services/database_service.py`
7. `services/risk_scoring_service.py`
8. `services/screenshot_service.py` and `services/report_export_service.py`
