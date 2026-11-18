
class SubdomainNormalizer:
    """
    Normalizza e deduplica i sottodomini.
    """

    @staticmethod
    def normalize(hostname: str) -> str | None:

        if not isinstance(hostname, str):
            return None

        hostname = hostname.strip().lower().rstrip(".")

        if hostname.startswith("*."):
            hostname = hostname[2:]

        try:
            hostname = hostname.encode(
                "idna"
            ).decode("ascii")
        except UnicodeError:
            return None

        if len(hostname) > 253:
            return None

        labels = hostname.split(".")

        if len(labels) < 2:
            return None

        for label in labels:

            if (
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
            ):
                return None

            if not all(
                char.isalnum() or char == "-"
                for char in label
            ):
                return None

        return hostname

    @staticmethod
    def belongs_to_domain(
        hostname: str,
        root_domain: str
    ) -> bool:

        return (
            hostname != root_domain
            and hostname.endswith("." + root_domain)
        )

    def process(
        self,
        root_domain: str,
        records: list[dict]
    ) -> list[dict]:

        normalized = {}

        for record in records:

            hostname = self.normalize(
                record.get("hostname", "")
            )

            if not hostname:
                continue

            if not self.belongs_to_domain(
                hostname,
                root_domain
            ):
                continue

            if hostname not in normalized:

                normalized[hostname] = {
                    "hostname": hostname,
                    "sources": [],
                    "ip_addresses": [],
                    "first_seen": None,
                    "last_seen": None,
                    "status": "not_verified"
                }

            item = normalized[hostname]

            source = record.get("source")

            if source and source not in item["sources"]:
                item["sources"].append(source)

            ip = record.get("ip")

            if ip and ip not in item["ip_addresses"]:
                item["ip_addresses"].append(ip)

            first_seen = record.get("first_seen")
            last_seen = record.get("last_seen")

            if first_seen:
                item["first_seen"] = (
                    first_seen
                    if not item["first_seen"]
                    else min(item["first_seen"], first_seen)
                )

            if last_seen:
                item["last_seen"] = (
                    last_seen
                    if not item["last_seen"]
                    else max(item["last_seen"], last_seen)
                )

        return sorted(
            normalized.values(),
            key=lambda item: item["hostname"]
        )
