class SimilarDomainGenerator:
    DEFAULT_TLDS = ("com", "net", "org", "info", "biz")

    CONFUSABLES = {
        "0": "o",
        "1": "l",
        "l": "1",
        "o": "0",
        "5": "s",
        "s": "5",
        "8": "b",
        "b": "8",
    }

    def __init__(self, max_candidates: int = 60):
        self.max_candidates = max(1, max_candidates)

    @staticmethod
    def _split_domain(domain: str):
        domain = domain.strip().lower().rstrip(".")
        if "." not in domain:
            raise ValueError("Il dominio deve includere un'estensione.")

        label, tld = domain.rsplit(".", 1)

        if not label or not tld:
            raise ValueError("Dominio non valido.")

        return label, tld

    @staticmethod
    def _valid_label(label: str) -> bool:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        return all(char.isalnum() or char == "-" for char in label)

    def generate(self, domain: str) -> list[dict]:
        label, original_tld = self._split_domain(domain)

        if not self._valid_label(label):
            raise ValueError("Nome dominio non valido.")

        candidates = {}

        def add(candidate_label: str, candidate_tld: str, reason: str):
            if len(candidates) >= self.max_candidates:
                return

            if not self._valid_label(candidate_label):
                return

            candidate = f"{candidate_label}.{candidate_tld}"

            if candidate == domain.lower().rstrip("."):
                return

            if candidate not in candidates:
                candidates[candidate] = {
                    "domain": candidate,
                    "reason": reason,
                }

        # 1. Omissione di un carattere
        for index in range(len(label)):
            variant = label[:index] + label[index + 1:]
            add(variant, original_tld, "character_omission")

        # 2. Duplicazione di un carattere
        for index, char in enumerate(label):
            variant = label[:index] + char + label[index:]
            add(variant, original_tld, "character_duplication")

        # 3. Scambio di due caratteri adiacenti
        for index in range(len(label) - 1):
            if label[index] == label[index + 1]:
                continue

            chars = list(label)
            chars[index], chars[index + 1] = (
                chars[index + 1],
                chars[index],
            )
            add("".join(chars), original_tld, "adjacent_transposition")

        # 4. Sostituzione con caratteri visivamente simili
        for index, char in enumerate(label):
            replacement = self.CONFUSABLES.get(char)
            if replacement:
                variant = label[:index] + replacement + label[index + 1:]
                add(variant, original_tld, "confusable_character")

        # 5. Inserimento di un trattino
        for index in range(1, len(label)):
            variant = label[:index] + "-" + label[index:]
            add(variant, original_tld, "hyphen_insertion")

        # 6. Variazioni dell'estensione
        for tld in self.DEFAULT_TLDS:
            if tld != original_tld:
                add(label, tld, "tld_variation")

        return list(candidates.values())