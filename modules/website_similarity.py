"""Compute weighted similarity between normalized website metadata records."""

from difflib import SequenceMatcher
from urllib.parse import urlparse


class WebsiteSimilarity:
    """Compare page metadata using transparent, feature-specific weights.

    Similarity helps prioritize manual review; it is not proof of cloning,
    phishing, or fraudulent intent.
    """

    WEIGHTS = {
        "title": 20,
        "description": 15,
        "site_name": 20,
        "favicon": 15,
        "logo": 20,
        "structure": 10,
    }

    @staticmethod
    def _text_score(first, second) -> float:
        """Return a normalized text similarity score for two non-empty values."""
        if not first or not second:
            return 0.0

        return SequenceMatcher(
            None,
            str(first).lower().strip(),
            str(second).lower().strip(),
        ).ratio() * 100

    @staticmethod
    def _reference_name(reference):
        """Extract a stable comparison token from an asset reference."""
        if not reference:
            return None

        path = urlparse(reference).path.rstrip("/")
        name = path.rsplit("/", 1)[-1]

        return name.lower() if name else None

    def compare(self, first: dict, second: dict) -> dict:
        """Calculate a weighted score and per-feature comparison evidence."""
        comparisons = {}

        for field in ("title", "description", "site_name"):
            value_a = first.get(field)
            value_b = second.get(field)

            if value_a and value_b:
                comparisons[field] = self._text_score(
                    value_a,
                    value_b,
                )

        favicon_a = self._reference_name(first.get("favicon"))
        favicon_b = self._reference_name(second.get("favicon"))

        if favicon_a and favicon_b:
            comparisons["favicon"] = self._text_score(
                favicon_a,
                favicon_b,
            )

        logos_a = first.get("logo_candidates", [])
        logos_b = second.get("logo_candidates", [])

        if logos_a and logos_b:
            comparisons["logo"] = max(
                self._text_score(
                    self._reference_name(logo_a),
                    self._reference_name(logo_b),
                )
                for logo_a in logos_a
                for logo_b in logos_b
            )

        tags_a = first.get("tag_sequence", [])
        tags_b = second.get("tag_sequence", [])

        if tags_a and tags_b:
            comparisons["structure"] = self._text_score(
                " ".join(tags_a),
                " ".join(tags_b),
            )

        total_weight = sum(
            self.WEIGHTS[field]
            for field in comparisons
        )

        if total_weight:
            score = sum(
                comparisons[field] * self.WEIGHTS[field]
                for field in comparisons
            ) / total_weight
        else:
            score = 0.0

        return {
            "score": round(score, 2),
            "level": self.classify(score),
            "compared_fields": comparisons,
            "available_fields": len(comparisons),
        }

    @staticmethod
    def classify(score: float) -> str:
        """Map the numeric similarity score to a descriptive category."""
        if score >= 85:
            return "very_high"
        if score >= 70:
            return "high"
        if score >= 45:
            return "medium"
        return "low"