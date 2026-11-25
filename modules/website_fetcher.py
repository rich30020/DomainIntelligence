import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection che connette all'IP validato mantenendo SNI e verifica TLS sul dominio."""

    def __init__(self, hostname, address, timeout):
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())
        self._pinned_address = address

    def connect(self):
        raw_socket = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
        )
        self.sock = self._context.wrap_socket(
            raw_socket,
            server_hostname=self.host,
        )


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

        addresses = sorted({item[4][0] for item in answers})
        if not addresses:
            raise ValueError("Il dominio non ha indirizzi IP.")

        for address in addresses:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
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

        if (
            not domain
            or "/" in domain
            or ":" in domain
            or "@" in domain
            or any(ch.isspace() for ch in domain)
        ):
            raise ValueError("Inserire un nome dominio valido, non un URL.")

        # Il socket si connette direttamente a uno degli IP già validati:
        # non viene effettuata una seconda risoluzione DNS durante la connessione.
        addresses = self.validate_public_dns(domain)
        last_error = None

        for address in addresses:
            connection = _PinnedHTTPSConnection(domain, address, self.timeout)
            try:
                connection.request(
                    "GET",
                    "/",
                    headers={
                        "Host": domain,
                        "User-Agent": "DomainIntelligence/1.0",
                        "Accept": "text/html",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()

                if response.status in (301, 302, 303, 307, 308):
                    raise ValueError(
                        "Redirect non seguito per motivi di sicurezza."
                    )
                if response.status < 200 or response.status >= 300:
                    raise ValueError(f"Risposta HTTP non valida: {response.status}")

                content_type = response.getheader("Content-Type", "").lower()
                if "text/html" not in content_type:
                    raise ValueError("La risorsa non è una pagina HTML.")

                content_length = response.getheader("Content-Length")
                if content_length:
                    try:
                        if int(content_length) > self.MAX_HTML_BYTES:
                            raise ValueError("La pagina supera il limite di 1 MB.")
                    except ValueError as exc:
                        if "supera il limite" in str(exc):
                            raise
                        # Content-Length malformato: si applica comunque il limite streaming.

                body = response.read(self.MAX_HTML_BYTES + 1)
                if len(body) > self.MAX_HTML_BYTES:
                    raise ValueError("La pagina supera il limite di 1 MB.")

                html = body.decode("utf-8", errors="replace")
                return {
                    "domain": domain,
                    "url": f"https://{domain}/",
                    "status_code": response.status,
                    "content_type": content_type,
                    "html": html,
                    "resolved_ips": addresses,
                    "connected_ip": address,
                }
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                last_error = exc
            finally:
                connection.close()

        raise ValueError(
            f"Impossibile collegarsi agli IP pubblici verificati per {domain}: {last_error}"
        ) from last_error
