from difflib import SequenceMatcher


class DomainSimilarity:
    @staticmethod
    def calculate(original: str, candidate: str) -> float:
        original = original.lower().strip().rstrip(".")
        candidate = candidate.lower().strip().rstrip(".")

        original_label = original.rsplit(".", 1)[0]
        candidate_label = candidate.rsplit(".", 1)[0]

        score = SequenceMatcher(
            None,
            original_label,
            candidate_label
        ).ratio()

        return round(score * 100, 2)

    @staticmethod
    def classify(score: float) -> str:
        if score >= 90:
            return "very_high"
        if score >= 75:
            return "high"
        if score >= 55:
            return "medium"
        return "low"