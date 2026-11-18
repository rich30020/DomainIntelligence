
from core.scope_manager import ScanMode

from modules.subdomain_normalizer import SubdomainNormalizer
from modules.subdomain_verifier import SubdomainVerifier

from modules.sources.crtsh_source import CRTSHSource
from modules.sources.hackertarget_source import HackerTargetSource
from modules.sources.otx_source import OTXSource


class SubdomainFinder:

    name = "subdomain_finder"

    requires_active = False

    def __init__(self):

        self.sources = [
            CRTSHSource(),
            HackerTargetSource(),
            OTXSource()
        ]

        self.normalizer = SubdomainNormalizer()
        self.verifier = SubdomainVerifier()

    def run(self, context, cancellation_event):

        domain = context.domain

        if context.scope.mode != ScanMode.PASSIVE:
            raise PermissionError(
                "Il Subdomain Finder è configurato "
                "per la raccolta passiva."
            )

        raw_records = []
        source_results = []

        # 1. Raccolta dalle fonti pubbliche.

        for source in self.sources:

            if cancellation_event.is_set():
                break

            try:

                response = source.search(domain)

                source_results.append({
                    "source": source.name,
                    "success": response["success"],
                    "count": response.get("count", 0),
                    "error": response.get("error")
                })

                if not response["success"]:
                    continue

                # Certificate Transparency.
                if source.name == "crtsh":

                    for hostname in response.get(
                        "subdomains", []
                    ):

                        raw_records.append({
                            "hostname": hostname,
                            "source": source.name
                        })

                # HackerTarget e OTX.
                else:

                    for record in response.get(
                        "results", []
                    ):

                        raw_records.append({
                            "hostname": record.get("hostname"),
                            "source": source.name,
                            "ip": record.get("ip"),
                            "first_seen": record.get("first_seen"),
                            "last_seen": record.get("last_seen")
                        })

            except Exception as exc:

                source_results.append({
                    "source": source.name,
                    "success": False,
                    "count": 0,
                    "error": str(exc)
                })

        # 2. Normalizzazione e deduplicazione.

        subdomains = self.normalizer.process(
            domain,
            raw_records
        )

        # 3. Verifica DNS.

        for subdomain in subdomains:

            if cancellation_event.is_set():
                break

            verification = self.verifier.verify(
                subdomain["hostname"]
            )

            subdomain["status"] = verification["status"]

            for address in verification["addresses"]:

                if address not in subdomain["ip_addresses"]:
                    subdomain["ip_addresses"].append(address)

        # 4. Risultati finali.

        return {
            "root_domain": domain,
            "total_discovered": len(subdomains),
            "sources": source_results,
            "subdomains": subdomains,
            "cancelled": cancellation_event.is_set()
        }
