"""Correlate scanned domain names with locally imported IOC records."""

from core.scope_manager import ScanMode
from services.threat_intel_store import ThreatIntelStore


class ThreatIntelAnalyzer:
    """Match the root domain and discovered subdomains against the local IOC store.

    This module performs local comparisons only: it does not visit domains or
    make network requests. Matches retain source and confidence provenance for
    later review and risk-indicator calculation.
    """

    name = "threat_intel_analyzer"
    requires_active = False

    def __init__(self, store=None):
        self.store = store or ThreatIntelStore()

    @staticmethod
    def classify_score(score: int) -> str:
        """Map the module confidence score to its configured qualitative label."""
        if score >= 85:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score > 0:
            return "low"
        return "no_match"

    def analyze_domain(self, domain: str) -> dict:
        """Return local IOC matches for one normalized domain name."""
        normalized = self.store.normalize_domain(domain)

        if not normalized:
            raise ValueError("Dominio da analizzare non valido.")

        matches = []

        for ioc in self.store.get_domain_indicators():
            ioc_domain = ioc.indicator

            if (
                normalized == ioc_domain
                or normalized.endswith("." + ioc_domain)
            ):
                matches.append({
                    "indicator": ioc.indicator,
                    "source": ioc.source,
                    "confidence": ioc.confidence,
                    "first_seen": ioc.first_seen,
                    "last_seen": ioc.last_seen,
                    "description": ioc.description,
                    "match_type": (
                        "exact"
                        if normalized == ioc_domain
                        else "subdomain"
                    ),
                })

        score = max(
            (item["confidence"] for item in matches),
            default=0,
        )

        return {
            "domain": normalized,
            "matched": bool(matches),
            "threat_score": score,
            "threat_level": self.classify_score(score),
            "match_count": len(matches),
            "matches": matches,
            "disclaimer": (
                "Le corrispondenze IOC sono indicatori da verificare "
                "e non costituiscono prova definitiva di attività malevola."
            ),
        }

    def run(self, context, cancellation_event):
        """Analyze the root domain and discovered subdomains against local IOCs."""
        if cancellation_event.is_set():
            return {"cancelled": True, "results": []}

        results = []

        # This module performs local correlation only. It does not visit target
        # websites, resolve candidate hosts, or issue network requests.
        domains = [context.domain]

        metadata = getattr(context, "metadata", {}) or {}

        additional_domains = metadata.get(
            "threat_intel_domains",
            [],
        )

        domains.extend(additional_domains)

        for domain in dict.fromkeys(domains):
            if cancellation_event.is_set():
                break

            results.append(self.analyze_domain(domain))

        return {
            "total_analyzed": len(results),
            "total_matches": sum(
                1 for item in results if item["matched"]
            ),
            "results": results,
            "cancelled": cancellation_event.is_set(),
        }