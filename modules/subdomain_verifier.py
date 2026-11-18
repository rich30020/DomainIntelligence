
import dns.resolver
import dns.exception


class SubdomainVerifier:
    """
    Verifica la risoluzione DNS dei sottodomini.
    """

    def __init__(self, timeout: float = 3.0):

        self.resolver = dns.resolver.Resolver()

        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def verify(self, hostname: str) -> dict:

        addresses = []

        try:

            for record_type in ("A", "AAAA"):

                try:

                    answers = self.resolver.resolve(
                        hostname,
                        record_type
                    )

                    addresses.extend(
                        str(answer)
                        for answer in answers
                    )

                except (
                    dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN
                ):
                    continue

                except (
                    dns.resolver.NoNameservers,
                    dns.exception.Timeout
                ):
                    return {
                        "hostname": hostname,
                        "status": "unknown",
                        "addresses": []
                    }

            if addresses:

                return {
                    "hostname": hostname,
                    "status": "resolved",
                    "addresses": sorted(set(addresses))
                }

            return {
                "hostname": hostname,
                "status": "unresolved",
                "addresses": []
            }

        except Exception:

            return {
                "hostname": hostname,
                "status": "unknown",
                "addresses": []
            }
    