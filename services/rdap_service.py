
"""Retrieve public registration metadata through the RDAP protocol."""

import httpx


class RDAPService:
    """Fetch public domain registration data without attempting account access."""

    BASE_URL = "https://rdap.org/domain/"

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    def get_domain_info(self, domain: str) -> dict:
        """Query the RDAP bootstrap service and normalize common response fields.

        Network, timeout, and not-found conditions are returned as structured
        statuses so callers can distinguish unavailable data from a positive
        registration lookup.
        """

        url = f"{self.BASE_URL}{domain}"

        try:

            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=5,
                headers={
                    "User-Agent": "DomainIntelligence/1.0"
                }
            ) as client:

                response = client.get(url)

                if response.status_code == 404:
                    return {
                        "success": False,
                        "status": "not_found",
                        "message": "Dominio non trovato nel servizio RDAP."
                    }

                response.raise_for_status()

                data = response.json()

                # Registrar information is represented by an entity whose
                # RDAP role includes 'registrar'; retain its vCard payload.
                registrar = None

                for entity in data.get("entities", []):

                    if "registrar" in entity.get(
                        "roles", []
                    ):

                        registrar = entity.get(
                            "vcardArray"
                        )

                        break

                return {
                    "success": True,
                    "status": "found",
                    "domain": data.get("ldhName"),
                    "handle": data.get("handle"),
                    "registrar": registrar,
                    "status_codes": data.get("status", []),
                    "events": data.get("events", []),
                    "nameservers": [
                        item.get("ldhName")
                        for item in data.get(
                            "nameservers", []
                        )
                    ],
                    "entities": data.get("entities", [])
                }

        except httpx.TimeoutException:
            return {
                "success": False,
                "status": "timeout",
                "message": "Timeout durante la richiesta RDAP."
            }

        except httpx.HTTPStatusError as exc:
            return {
                "success": False,
                "status": "http_error",
                "message": str(exc)
            }

        except (httpx.HTTPError, ValueError) as exc:
            return {
                "success": False,
                "status": "error",
                "message": str(exc)
            }
