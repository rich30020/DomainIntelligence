import re

from core.scope_manager import ScanMode
from modules.website_fetcher import WebsiteFetcher
from modules.website_parser import WebsiteParser
from modules.website_similarity import WebsiteSimilarity


class WebsiteCloneAnalyzer:
    name = "website_clone_analyzer"
    requires_active = True

    def __init__(self, fetcher=None):
        self.fetcher = fetcher or WebsiteFetcher()
        self.parser = WebsiteParser()
        self.similarity = WebsiteSimilarity()

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        if not isinstance(domain, str):
            raise ValueError("Dominio non valido.")

        domain = domain.strip().lower().rstrip(".")

        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Dominio IDN non valido.") from exc

        if len(domain) > 253:
            raise ValueError("Dominio troppo lungo.")

        labels = domain.split(".")

        if len(labels) < 2:
            raise ValueError("Dominio non valido.")

        for label in labels:
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label,
                )
            ):
                raise ValueError("Formato dominio non valido.")

        return domain

    def run(self, context, cancellation_event):
        if context.scope.mode != ScanMode.AUTHORIZED:
            raise PermissionError(
                "Il Website Clone Analyzer richiede "
                "uno scope autorizzato."
            )

        metadata = getattr(context, "metadata", {}) or {}
        comparison_domain = metadata.get("comparison_domain")

        if not comparison_domain:
            return {
                "status": "skipped",
                "reason": "Nessun secondo dominio specificato.",
                "results": None,
                "cancelled": False,
            }

        first_domain = self._normalize_domain(context.domain)
        second_domain = self._normalize_domain(comparison_domain)

        if first_domain == second_domain:
            raise ValueError(
                "I due domini da confrontare devono essere diversi."
            )

        authorized = {
            self._normalize_domain(domain)
            for domain in context.scope.authorized_domains
        }

        if first_domain not in authorized:
            raise PermissionError(
                f"{first_domain} non è autorizzato."
            )

        if second_domain not in authorized:
            raise PermissionError(
                f"{second_domain} non è autorizzato."
            )

        if cancellation_event.is_set():
            return {"cancelled": True, "results": None}

        first_page = self.fetcher.fetch(first_domain)

        if cancellation_event.is_set():
            return {"cancelled": True, "results": None}

        second_page = self.fetcher.fetch(second_domain)

        first_data = self.parser.parse(
            first_page["html"],
            first_page["url"],
        )

        second_data = self.parser.parse(
            second_page["html"],
            second_page["url"],
        )

        comparison = self.similarity.compare(
            first_data,
            second_data,
        )

        return {
            "original_domain": first_domain,
            "comparison_domain": second_domain,
            "similarity": comparison,
            "pages": {
                first_domain: first_data,
                second_domain: second_data,
            },
            "cancelled": False,
            "disclaimer": (
                "La somiglianza tecnica non dimostra "
                "un'attività fraudolenta."
            ),
        }