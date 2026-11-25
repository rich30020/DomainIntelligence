
"""Collect public domain registration, DNS, and authorized TLS metadata."""

import re

from core.scope_manager import ScanMode
from models.domain import Domain
from services.rdap_service import RDAPService

from modules.dns_analyzer import DNSAnalyzer
from modules.certificate_analyzer import CertificateAnalyzer


class DomainScanner:
    """Orchestrate domain validation and independent RDAP, DNS, and TLS checks.

    RDAP and DNS use publicly available information. The direct TLS check is
    gated by the authorization scope so it is not treated as a passive lookup.
    """

    name = "domain_scanner"

    # DNS and RDAP are public-data lookups. Direct TLS inspection is a separate
    # operation because the scanner requires explicit authorization for it.
    requires_active = False

    def __init__(self):

        self.rdap_service = RDAPService()
        self.dns_analyzer = DNSAnalyzer()
        self.certificate_analyzer = CertificateAnalyzer()

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize a hostname, including Unicode labels, to IDNA ASCII."""

        domain = domain.strip().rstrip(".").lower()

        # Convert Unicode domain labels to their ASCII-compatible IDNA form.
        return domain.encode("idna").decode("ascii")

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Return whether the normalized input is a syntactically valid domain."""

        if not domain or len(domain) > 253:
            return False

        pattern = (
            r"^(?=.{1,253}$)"
            r"(?:[a-z0-9]"
            r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z]{2,63}$"
        )

        return bool(re.fullmatch(pattern, domain))

    def run(self, context, cancellation_event):
        """Collect domain metadata and return it in the module result schema."""

        original_domain = context.domain

        domain = self.normalize_domain(
            original_domain
        )

        if not self.validate_domain(domain):
            raise ValueError("Dominio non valido.")

        domain_model = Domain(
            name=original_domain,
            normalized_name=domain,
            tld=domain.rsplit(".", 1)[-1],
            is_valid=True
        )

        results = {
            "domain": domain,
            "validation": {
                "success": True,
                "normalized": domain
            },
            "rdap": {},
            "dns": {},
            "certificate": {
                "status": "not_checked"
            }
        }

        # 1. Retrieve public registration metadata from RDAP.

        if cancellation_event.is_set():
            return results

        try:

            results["rdap"] = (
                self.rdap_service.get_domain_info(domain)
            )

        except Exception as exc:

            results["rdap"] = {
                "success": False,
                "status": "error",
                "message": str(exc)
            }

        # 2. Collect public DNS records.

        if cancellation_event.is_set():
            return results

        try:

            results["dns"] = (
                self.dns_analyzer.analyze(domain)
            )

        except Exception as exc:

            results["dns"] = {
                "success": False,
                "status": "error",
                "message": str(exc)
            }

        # 3. Inspect TLS only when the declared scope authorizes active checks.

        if cancellation_event.is_set():
            return results

        authorized = (
            context.scope.mode == ScanMode.AUTHORIZED
            and context.scope.root_domain == domain
            and domain in context.scope.authorized_domains
        )

        if authorized:

            results["certificate"] = (
                self.certificate_analyzer.analyze(domain)
            )

        else:

            results["certificate"] = {
                "success": False,
                "status": "skipped",
                "message": (
                    "Verifica TLS diretta non eseguita: "
                    "autorizzazione esplicita non disponibile."
                )
            }

        # 4. Complete the normalized domain model.

        domain_model.rdap_info = results["rdap"]
        domain_model.dns_info = results["dns"]
        domain_model.certificate_info = results["certificate"]

        results["domain_model"] = {
            "name": domain_model.name,
            "normalized_name": domain_model.normalized_name,
            "tld": domain_model.tld,
            "is_valid": domain_model.is_valid
        }

        return results
