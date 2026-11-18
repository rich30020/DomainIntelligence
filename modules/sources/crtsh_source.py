
import httpx


class CRTSHSource:
    """
    Recupera nomi DNS dai certificati pubblici
    presenti in Certificate Transparency.
    """

    name = "crtsh"

    URL = "https://crt.sh/"

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    def search(self, domain: str) -> dict:

        try:

            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                headers={
                    "User-Agent": "DomainIntelligence/1.0"
                }
            ) as client:

                response = client.get(
                    self.URL,
                    params={
                        "q": f"%.{domain}",
                        "output": "json"
                    }
                )

                response.raise_for_status()

                records = response.json()

                if not isinstance(records, list):
                    raise ValueError(
                        "Formato risposta CT non valido."
                    )

                subdomains = set()

                for record in records:

                    names = record.get(
                        "name_value", ""
                    )

                    for name in names.splitlines():

                        name = name.strip().lower().rstrip(".")

                        if name.startswith("*."):
                            name = name[2:]

                        if name and name != domain:
                            subdomains.add(name)

                return {
                    "success": True,
                    "source": self.name,
                    "subdomains": sorted(subdomains),
                    "count": len(subdomains)
                }

        except (
            httpx.HTTPError,
            ValueError,
            TypeError
        ) as exc:

            return {
                "success": False,
                "source": self.name,
                "subdomains": [],
                "count": 0,
                "error": str(exc)
            }
