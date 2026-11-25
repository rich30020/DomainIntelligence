"""Build a conservative, explainable risk indicator from threat-intelligence matches."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class RiskEvidence:
    """A normalized, traceable IOC match used by the scoring service."""

    domain: str
    indicator: str
    indicator_type: str
    source: str
    confidence: int


class RiskScoringService:
    """Convert IOC matches into a traceable score without overstating certainty.

    Only evidence returned by the Threat Intelligence module contributes to
    the score. A missing match is reported as not evaluable, not as evidence
    that a domain is benign. Similarity and infrastructure observations are
    deliberately excluded from this calculation.
    """

    LEVELS = (
        (85, "critico"),
        (70, "alto"),
        (40, "medio"),
        (1, "basso"),
    )

    ADDITIONAL_SOURCE_BONUS = 5

    @staticmethod
    def _get(value: Any, key: str, default=None):
        """Read a field from either a dictionary or an object."""
        if isinstance(value, dict):
            return value.get(key, default)
        return getattr(value, key, default)

    @classmethod
    def _module_results(cls, scan_result: Any) -> Iterable[Any]:
        """Return module results from either supported scan-result format."""
        if isinstance(scan_result, dict):
            return scan_result.get("results", []) or []
        return cls._get(scan_result, "results", []) or []

    @staticmethod
    def _level(score: int) -> str:
        """Map a numeric indicator to the configured qualitative band."""
        for threshold, label in RiskScoringService.LEVELS:
            if score >= threshold:
                return label
        return "non_valutabile"

    def calculate(self, scan_result: Any) -> dict:
        """Return a structured assessment from a ScanResult or compatible mapping.

        Evidence is normalized, deduplicated by domain/indicator/type/source,
        and sorted by confidence. The highest source confidence forms the base
        score; each additional distinct source adds a bounded corroboration
        bonus. The returned method metadata explains this calculation.
        """
        scan_domain = (
            scan_result.get("domain", "")
            if isinstance(scan_result, dict)
            else self._get(scan_result, "domain", "")
        )
        scan_domain = str(scan_domain or "").strip().lower().rstrip(".")

        evidence: list[RiskEvidence] = []
        warnings: list[str] = []
        threat_module_found = False
        threat_module_succeeded = False

        for module_result in self._module_results(scan_result):
            module_name = self._get(module_result, "module_name", "")
            if module_name != "threat_intel_analyzer":
                continue

            threat_module_found = True
            if not bool(self._get(module_result, "success", False)):
                warnings.append(
                    "Il modulo Threat Intelligence non è riuscito: "
                    "l'assenza di corrispondenze non è verificabile."
                )
                continue

            threat_module_succeeded = True
            data = self._get(module_result, "data", {}) or {}
            if not isinstance(data, dict):
                warnings.append(
                    "Il modulo Threat Intelligence ha restituito dati "
                    "in un formato non riconosciuto."
                )
                continue

            for domain_result in data.get("results", []) or []:
                if not isinstance(domain_result, dict):
                    continue

                matched_domain = str(
                    domain_result.get("domain", scan_domain) or scan_domain
                ).strip().lower().rstrip(".")

                for match in domain_result.get("matches", []) or []:
                    if not isinstance(match, dict):
                        continue

                    indicator = str(match.get("indicator", "") or "").strip()
                    indicator_type = str(
                        match.get("type", match.get("indicator_type", "domain"))
                        or "domain"
                    ).strip().lower()
                    source = str(match.get("source", "") or "fonte non specificata").strip()

                    try:
                        confidence = int(match.get("confidence", 0))
                    except (TypeError, ValueError):
                        continue

                    if not indicator or not 0 <= confidence <= 100:
                        continue

                    evidence.append(
                        RiskEvidence(
                            domain=matched_domain,
                            indicator=indicator,
                            indicator_type=indicator_type,
                            source=source,
                            confidence=confidence,
                        )
                    )

        # Collapse duplicate feed rows while retaining the strongest confidence
        # for each domain/indicator/type/source combination.
        unique: dict[tuple[str, str, str, str], RiskEvidence] = {}
        for item in evidence:
            key = (
                item.domain,
                item.indicator.lower(),
                item.indicator_type,
                item.source.lower(),
            )
            previous = unique.get(key)
            if previous is None or item.confidence > previous.confidence:
                unique[key] = item

        evidence = list(unique.values())
        evidence.sort(
            key=lambda item: (item.confidence, item.source, item.indicator),
            reverse=True,
        )

        if not evidence:
            if not threat_module_found:
                status = "modulo_non_eseguito"
                warnings.append(
                    "Threat Intelligence non è stato selezionato o non compare "
                    "nei risultati della scansione."
                )
            elif not threat_module_succeeded:
                status = "verifica_non_riuscita"
            else:
                status = "nessuna_corrispondenza_ioc"

            return {
                "domain": scan_domain,
                "status": status,
                "score": None,
                "level": "non_valutabile",
                "label": "Evidenze IOC insufficienti",
                "evidence_count": 0,
                "independent_sources": 0,
                "evidence": [],
                "explanation": (
                    "Non sono state trovate corrispondenze IOC utilizzabili. "
                    "Questo risultato non dimostra che il dominio sia sicuro."
                ),
                "warnings": warnings,
                "method": {
                    "name": "IOC confidence indicator",
                    "version": "1.0",
                    "formula": (
                        "massima confidenza IOC + 5 punti per ogni fonte "
                        "distinta aggiuntiva, con limite massimo 100"
                    ),
                },
            }

        # Independent sources provide limited corroboration. The cap prevents
        # the score from exceeding the documented 0–100 confidence scale.
        max_confidence = max(item.confidence for item in evidence)
        sources = {item.source.lower() for item in evidence}
        source_bonus = self.ADDITIONAL_SOURCE_BONUS * max(0, len(sources) - 1)
        score = min(100, max_confidence + source_bonus)

        evidence_payload = [asdict(item) for item in evidence]
        return {
            "domain": scan_domain,
            "status": "ioc_match",
            "score": score,
            "level": self._level(score),
            "label": f"Indicatore IOC: {self._level(score)}",
            "evidence_count": len(evidence),
            "independent_sources": len(sources),
            "evidence": evidence_payload,
            "explanation": (
                f"Rilevate {len(evidence)} corrispondenze IOC da "
                f"{len(sources)} fonti distinte. Il punteggio usa la massima "
                f"confidenza dichiarata ({max_confidence}) e un bonus "
                f"prudenziale di {source_bonus} per fonti aggiuntive."
            ),
            "warnings": warnings,
            "method": {
                "name": "IOC confidence indicator",
                "version": "1.0",
                "formula": (
                    "massima confidenza IOC + 5 punti per ogni fonte "
                    "distinta aggiuntiva, con limite massimo 100"
                ),
                "max_confidence": max_confidence,
                "source_bonus": source_bonus,
            },
        }

    def run(self, scan_result: Any) -> dict:
        """Expose ``calculate`` through the module-style ``run`` interface."""
        return self.calculate(scan_result)
