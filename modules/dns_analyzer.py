
"""Query selected public DNS record types and normalize resolver responses."""

import dns.resolver
import dns.exception


class DNSAnalyzer:
    """Analyze public DNS records for a domain using bounded resolver timeouts."""

    RECORD_TYPES = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
        "SOA"
    ]

    def __init__(self, timeout: float = 3.0):

        self.timeout = timeout

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def get_record(self, domain: str, record_type: str):
        """Query one DNS record type and return normalized answers or an error."""

        try:

            answers = self.resolver.resolve(
                domain,
                record_type
            )

            return [
                str(answer)
                for answer in answers
            ]

        except dns.resolver.NXDOMAIN:
            return []

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout
        ):
            return []

        except Exception:
            return []

    def analyze(self, domain: str) -> dict:
        """Collect the configured record types into one structured DNS report."""

        results = {}

        for record_type in self.RECORD_TYPES:

            results[record_type] = self.get_record(
                domain,
                record_type
            )

        return {
            "domain": domain,
            "records": results
        }
