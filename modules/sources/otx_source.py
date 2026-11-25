
"""Query AlienVault OTX public Passive DNS indicator data."""

import httpx


class OTXSource:
    """Retrieve Passive DNS observations from AlienVault OTX."""

    name = "otx"

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain/"

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 20.0
    ):

        self.api_key = api_key
        self.timeout = timeout

    def search(self, domain: str) -> dict:
        """Fetch OTX observations using the optional API key when configured."""

        url = f"{self.BASE_URL}{domain}/passive_dns"

        headers = {
            "Accept": "application/json",
            "User-Agent": "DomainIntelligence/1.0"
        }

        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        try:

            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                headers=headers
            ) as client:

                response = client.get(url)

                response.raise_for_status()

                data = response.json()

                records = data.get("passive_dns", [])

                if not isinstance(records, list):
                    raise ValueError(
                        "Formato risposta OTX non valido."
                    )

                results = []

                for record in records:

                    hostname = record.get("hostname")

                    if not hostname:
                        continue

                    results.append({
                        "hostname": hostname.lower().rstrip("."),
                        "ip": record.get("address"),
                        "record_type": record.get("record_type"),
                        "first_seen": record.get("first"),
                        "last_seen": record.get("last")
                    })

                return {
                    "success": True,
                    "source": self.name,
                    "results": results,
                    "count": len(results)
                }

        except (
            httpx.HTTPError,
            ValueError,
            TypeError
        ) as exc:

            return {
                "success": False,
                "source": self.name,
                "results": [],
                "count": 0,
                "error": str(exc)
            }
