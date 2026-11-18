
import httpx


class HackerTargetSource:
    """
    Recupera hostname da HackerTarget Hostsearch.
    """

    name = "hackertarget"

    URL = "https://api.hackertarget.com/hostsearch/"

    def __init__(self, timeout: float = 15.0):
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
                    params={"q": domain}
                )

                response.raise_for_status()

                content = response.text.strip()

                if content.startswith("error") or content.startswith("API count"):
                    raise ValueError(content)

                results = []

                for line in content.splitlines():

                    parts = line.split(",", 1)

                    if len(parts) != 2:
                        continue

                    hostname, address = parts

                    results.append({
                        "hostname": hostname.strip().lower(),
                        "ip": address.strip()
                    })

                return {
                    "success": True,
                    "source": self.name,
                    "results": results,
                    "count": len(results)
                }

        except (
            httpx.HTTPError,
            ValueError
        ) as exc:

            return {
                "success": False,
                "source": self.name,
                "results": [],
                "count": 0,
                "error": str(exc)
            }
