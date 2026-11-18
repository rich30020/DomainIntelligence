
import dns.resolver
import dns.exception


class DNSAnalyzer:
    """
    Analizza i record DNS pubblici di un dominio.
    """

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
