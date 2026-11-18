import ipaddress
import socket

import httpx


class WebsiteFetcher:
    MAX_HTML_BYTES = 1_000_000

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    @staticmethod
    def validate_public_dns(domain: str) -> list[str]:
        try:
            answers = socket.getaddrinfo(
                domain,
                443,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ValueError(
                f"Impossibile risolvere il dominio: {exc}"
            ) from exc

        addresses = sorted({
            item[4][0]
            for item in answers
        })

        if not addresses:
            raise ValueError("Il dominio non ha indirizzi IP.")

        for address in addresses:
            ip = ipaddress.ip_address(address)

            if not ip.is_global:
                raise ValueError(
                    f"Indirizzo IP non pubblico rifiutato: {address}"
                )

        return addresses

    def fetch(self, domain: str) -> dict:
        domain = domain.strip().lower().rstrip(".")

        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Nome dominio non valido.") from exc

        if not domain or "/" in domain or ":" in domain:
            raise ValueError("Inserire un nome dominio, non un URL.")

        # Verifica preventiva degli indirizzi DNS.
        addresses = self.validate_public_dns(domain)

        url = f"https://{domain}/"

        with httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": "DomainIntelligence/1.0",
                "Accept": "text/html",
            },
        ) as client:
            with client.stream("GET", url) as response:
                if response.is_redirect:
                    raise ValueError(
                        "Redirect non seguito per motivi di sicurezza."
                    )

                response.raise_for_status()

                content_type = response.headers.get(
                    "content-type", ""
                ).lower()

                if "text/html" not in content_type:
                    raise ValueError(
                        "La risorsa non è una pagina HTML."
                    )

                chunks = []
                total_bytes = 0

                for chunk in response.iter_bytes():
                    total_bytes += len(chunk)

                    if total_bytes > self.MAX_HTML_BYTES:
                        raise ValueError(
                            "La pagina supera il limite di 1 MB."
                        )

                    chunks.append(chunk)

                html = b"".join(chunks).decode(
                    response.encoding or "utf-8",
                    errors="replace",
                )

                return {
                    "domain": domain,
                    "url": url,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "html": html,
                    "resolved_ips": addresses,
                }