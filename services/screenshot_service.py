"""Screenshot sicuri di siti esplicitamente autorizzati.

Richiede Playwright e Chromium:
    pip install playwright
    python -m playwright install chromium

Il servizio applica una allowlist esatta di hostname, accetta solo HTTPS,
blocca IP non pubblici e ripete i controlli per ogni richiesta/redirect.
Non invia credenziali, non compila form e non interagisce con la pagina.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from datetime import datetime, timezone
import re


class ScreenshotSecurityError(ValueError):
    """Richiesta di acquisizione non consentita."""


@dataclass
class ScreenshotResult:
    url: str
    hostname: str
    screenshot_path: str
    title: str
    description: str
    captured_at: str
    page_width: int
    page_height: int


def _normalise_host(host: str) -> str:
    return host.rstrip(".").encode("idna").decode("ascii").lower()


def _resolve_public_host(hostname: str) -> list[str]:
    """Restituisce IP pubblici verificati; rifiuta risposte miste o non pubbliche."""
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScreenshotSecurityError(f"Impossibile risolvere il dominio: {hostname}") from exc
    addresses = {record[4][0] for record in records}
    if not addresses:
        raise ScreenshotSecurityError("Il dominio non ha indirizzi IP risolvibili.")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not ip.is_global:
            raise ScreenshotSecurityError(
                f"Indirizzo non pubblico bloccato per {hostname}: {ip}"
            )
    return sorted(addresses)


def _build_host_resolver_rules(hosts: set[str]) -> str:
    """Crea regole Chromium che fissano gli host autorizzati agli IP verificati."""
    rules = []
    for raw_host in sorted(hosts):
        host = _normalise_host(raw_host)
        addresses = _resolve_public_host(host)
        # Una singola destinazione validata evita che Chromium ripeta una
        # risoluzione DNS indipendente dopo il controllo applicativo.
        rules.append(f"MAP {host} {addresses[0]}")
    rules.append("EXCLUDE localhost")
    return ",".join(rules)


def validate_capture_url(url: str, authorised_hosts: set[str]) -> str:
    """Valida URL HTTPS e hostname esattamente presente nella allowlist."""
    if not isinstance(url, str) or not url.strip():
        raise ScreenshotSecurityError("Inserisci un URL valido.")
    parsed = urlsplit(url.strip())
    if parsed.scheme.lower() != "https":
        raise ScreenshotSecurityError("Sono consentiti esclusivamente URL HTTPS.")
    if not parsed.hostname:
        raise ScreenshotSecurityError("URL senza hostname.")
    if parsed.username or parsed.password:
        raise ScreenshotSecurityError("Gli URL con credenziali incorporate sono vietati.")
    if parsed.port not in (None, 443):
        raise ScreenshotSecurityError("Sono consentite solo connessioni HTTPS sulla porta 443.")
    host = _normalise_host(parsed.hostname)
    allowed = {_normalise_host(item) for item in authorised_hosts}
    if host not in allowed:
        raise ScreenshotSecurityError(
            f"Host {host} non presente nella lista dei domini autorizzati."
        )
    _resolve_public_host(host)
    return host


def capture_authorised_site(
    url: str,
    authorised_hosts: set[str],
    output_dir: str | Path,
    *,
    timeout_ms: int = 20000,
    viewport: tuple[int, int] = (1440, 1000),
) -> ScreenshotResult:
    """Acquisisce una schermata completa senza interazioni con il sito."""
    hostname = validate_capture_url(url, authorised_hosts)

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except ImportError as exc:
        raise RuntimeError(
            "Playwright non è installato. Esegui: pip install playwright"
        ) from exc

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9.-]", "_", hostname)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    screenshot_path = destination / f"{safe_name}_{stamp}.png"

    def guard_request(route):
        request_url = route.request.url
        parsed = urlsplit(request_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            route.abort("blockedbyclient")
            return
        if parsed.username or parsed.password:
            route.abort("blockedbyclient")
            return
        try:
            if parsed.port not in (None, 443):
                route.abort("blockedbyclient")
                return
        except ValueError:
            route.abort("blockedbyclient")
            return
        request_host = _normalise_host(parsed.hostname)
        # Strict same-host policy prevents third-party tracking and unreviewed
        # redirects/resources. Add another explicitly authorised hostname only
        # when the operator has permission for that host too.
        if request_host not in {_normalise_host(x) for x in authorised_hosts}:
            route.abort("blockedbyclient")
            return
        route.continue_()

    normalised_authorised_hosts = {_normalise_host(item) for item in authorised_hosts}
    resolver_rules = _build_host_resolver_rules(normalised_authorised_hosts)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=[f"--host-resolver-rules={resolver_rules}"],
        )
        context = browser.new_context(
            viewport={"width": int(viewport[0]), "height": int(viewport[1])},
            ignore_https_errors=False,
            java_script_enabled=True,
        )
        page = context.new_page()
        page.route("**/*", guard_request)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            # Brief bounded wait for layout/fonts; do not wait indefinitely for analytics.
            page.wait_for_timeout(800)
            title = page.title()[:500]
            description = page.locator('meta[name="description"]').get_attribute("content") or ""
            description = description[:1000]
            dimensions = page.evaluate(
                "() => ({width: document.documentElement.scrollWidth, "
                "height: document.documentElement.scrollHeight})"
            )
            page.screenshot(path=str(screenshot_path), full_page=True, animations="disabled")
        except PlaywrightTimeoutError as exc:
            raise TimeoutError(f"Timeout durante l'acquisizione di {hostname}.") from exc
        finally:
            context.close()
            browser.close()

    return ScreenshotResult(
        url=url,
        hostname=hostname,
        screenshot_path=str(screenshot_path),
        title=title,
        description=description,
        captured_at=datetime.now(timezone.utc).isoformat(),
        page_width=int(dimensions["width"]),
        page_height=int(dimensions["height"]),
    )
