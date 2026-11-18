
from modules.image_hash_analyzer import ImageHashAnalyzer


class ImageSimilarityAnalyzer:
    name = "image_similarity_analyzer"
    requires_active = False

    def __init__(self):
        self.hash_analyzer = ImageHashAnalyzer()

    def compare(self, first_path: str, second_path: str) -> dict:
        first = self.hash_analyzer.analyze(first_path)
        second = self.hash_analyzer.analyze(second_path)

        phash = self.hash_analyzer.compare_hashes(
            first["phash"],
            second["phash"],
        )

        ahash = self.hash_analyzer.compare_hashes(
            first["ahash"],
            second["ahash"],
        )

        dhash = self.hash_analyzer.compare_hashes(
            first["dhash"],
            second["dhash"],
        )

        score = round(
            (
                phash["similarity"]
                + ahash["similarity"]
                + dhash["similarity"]
            ) / 3,
            2,
        )

        return {
            "first_image": first,
            "second_image": second,
            "phash": phash,
            "ahash": ahash,
            "dhash": dhash,
            "similarity_score": score,
        }

    def run(self, context, cancellation_event):
        if cancellation_event.is_set():
            return {"cancelled": True}

        first_path = context.metadata.get("image_path")
        second_path = context.metadata.get(
            "comparison_image_path"
        )

        if not first_path or not second_path:
            return {
                "skipped": True,
                "message": (
                    "Per confrontare le immagini occorrono "
                    "due file locali."
                ),
            }

        result = self.compare(first_path, second_path)

        if cancellation_event.is_set():
            return {"cancelled": True}

        return {
            "skipped": False,
            "comparison": result,
        }
