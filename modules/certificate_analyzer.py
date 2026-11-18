
import socket
import ssl
import ipaddress


class CertificateAnalyzer:
    """
    Analizza il certificato TLS di un dominio autorizzato.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def analyze(self, domain: str) -> dict:

        try:

            addresses = socket.getaddrinfo(
                domain,
                443,
                type=socket.SOCK_STREAM
            )

            public_addresses = []

            for address in addresses:

                ip = ipaddress.ip_address(
                    address[4][0]
                )

                if not ip.is_global:
                    return {
                        "success": False,
                        "status": "blocked_address",
                        "message": (
                            "Destinazione non pubblica: "
                            "connessione bloccata."
                        )
                    }

                public_addresses.append(str(ip))

            if not public_addresses:
                return {
                    "success": False,
                    "status": "no_address"
                }

            context = ssl.create_default_context()

            with socket.create_connection(
                (domain, 443),
                timeout=self.timeout
            ) as connection:

                with context.wrap_socket(
                    connection,
                    server_hostname=domain
                ) as secure_connection:

                    certificate = secure_connection.getpeercert()

                    return {
                        "success": True,
                        "status": "retrieved",
                        "subject": certificate.get(
                            "subject", []
                        ),
                        "issuer": certificate.get(
                            "issuer", []
                        ),
                        "not_before": certificate.get(
                            "notBefore"
                        ),
                        "not_after": certificate.get(
                            "notAfter"
                        ),
                        "subject_alt_names": certificate.get(
                            "subjectAltName", []
                        ),
                        "tls_version": secure_connection.version(),
                        "resolved_addresses": sorted(
                            set(public_addresses)
                        )
                    }

        except (
            socket.timeout,
            TimeoutError
        ):
            return {
                "success": False,
                "status": "timeout"
            }

        except ssl.SSLError as exc:
            return {
                "success": False,
                "status": "ssl_error",
                "message": str(exc)
            }

        except OSError as exc:
            return {
                "success": False,
                "status": "connection_error",
                "message": str(exc)
            }
