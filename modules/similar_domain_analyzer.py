
"""Enrich generated lookalike candidates using public registration data."""

from core.scope_manager import ScanMode
from modules.similar_domain_generator import SimilarDomainGenerator
from modules.domain_similarity import DomainSimilarity
from services.rdap_service import RDAPService


class SimilarDomainAnalyzer:
    """Generate candidate lookalikes and optionally check their RDAP records.

    This module is passive: RDAP enrichment queries a public registration-data
    service and does not connect to candidate websites or attempt interaction.
    """
    name = "similar_domain_analyzer"
    requires_active = False

    def __init__(
        self,
        max_candidates: int = 60,
        max_rdap_lookups: int = 20,
        rdap_service=None,
    ):
        self.generator = SimilarDomainGenerator(
            max_candidates=max_candidates
        )
        self.max_rdap_lookups = max(0, max_rdap_lookups)
        self.rdap_service = rdap_service or RDAPService()

    def _check_rdap(self, domain: str) -> dict:
        """Retrieve public registration metadata for one candidate domain."""
        try:
            response = self.rdap_service.get_domain_info(domain)

            if not isinstance(response, dict):
                return {
                    "status": "unknown",
                    "details": None,
                    "error": "Risposta RDAP non valida.",
                }

            if response.get("success") is True:
                return {
                    "status": "registered",
                    "details": response,
                    "error": None,
                }

            if response.get("status") == "not_found":
                return {
                    "status": "not_found",
                    "details": None,
                    "error": response.get(
                        "message",
                        "Dominio non trovato nel servizio RDAP.",
                    ),
                }

            return {
                "status": "unknown",
                "details": None,
                "error": response.get(
                    "message",
                    "Informazioni RDAP non disponibili.",
                ),
            }

        except Exception as exc:
            return {
                "status": "unknown",
                "details": None,
                "error": str(exc),
            }

    def run(self, context, cancellation_event):
        """Return bounded lookalike candidates with similarity and RDAP context."""
        if context.scope.mode != ScanMode.PASSIVE:
            raise PermissionError(
                "Il Similar Domain Analyzer utilizza esclusivamente "
                "fonti passive."
            )

        original_domain = context.domain.lower().strip().rstrip(".")
        candidates = self.generator.generate(original_domain)

        results = []

        for index, candidate in enumerate(candidates):
            if cancellation_event.is_set():
                break

            domain = candidate["domain"]

            score = DomainSimilarity.calculate(
                original_domain,
                domain,
            )

            item = {
                "domain": domain,
                "reason": candidate["reason"],
                "similarity_score": score,
                "similarity_level": DomainSimilarity.classify(score),
                "rdap_status": "not_checked",
                "rdap_details": None,
                "rdap_error": None,
            }

            if index < self.max_rdap_lookups:
                if cancellation_event.is_set():
                    break

                rdap_result = self._check_rdap(domain)

                item["rdap_status"] = rdap_result["status"]
                item["rdap_details"] = rdap_result["details"]
                item["rdap_error"] = rdap_result["error"]

            results.append(item)

        results.sort(
            key=lambda item: item["similarity_score"],
            reverse=True,
        )

        return {
            "original_domain": original_domain,
            "total_generated": len(candidates),
            "total_analyzed": len(results),
            "rdap_lookup_limit": self.max_rdap_lookups,
            "results": results,
            "cancelled": cancellation_event.is_set(),
        }
