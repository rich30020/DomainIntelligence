
import re

from core.scope_manager import ScanMode
from models.domain import Domain
from services.rdap_service import RDAPService

from modules.dns_analyzer import DNSAnalyzer
from modules.certificate_analyzer import CertificateAnalyzer


class DomainScanner:

    name = "domain_scanner"

    # Il modulo esegue DNS e RDAP pubblici.
    # TLS diretto viene verificato separatamente.
    requires_active = False

    def __init__(self):

        self.rdap_service = RDAPService()
        self.dns_analyzer = DNSAnalyzer()
        self.certificate_analyzer = CertificateAnalyzer()

    @staticmethod
    def normalize_domain(domain: str) -> str:

        domain = domain.strip().rstrip(".").lower()

        # Converte i domini Unicode in formato IDNA.
        return domain.encode("idna").decode("ascii")

    @staticmethod
    def validate_domain(domain: str) -> bool:

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

        # 1. RDAP

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

        # 2. DNS

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

        # 3. TLS diretto, solo con autorizzazione.

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

        # 4. Costruzione del modello.

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
