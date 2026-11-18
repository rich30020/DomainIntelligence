
from pathlib import Path


class LogoDetector:
    name = "logo_detector"
    requires_active = False

    KEYWORDS = (
        "logo",
        "brand",
        "emblem",
        "symbol",
        "identity",
    )

    def detect(self, image_path: str) -> dict:
        path = Path(image_path)

        if not path.exists() or not path.is_file():
            raise FileNotFoundError(
                f"Immagine non trovata: {image_path}"
            )

        filename = path.stem.lower()

        keyword_matches = [
            keyword
            for keyword in self.KEYWORDS
            if keyword in filename
        ]

        return {
            "filename": path.name,
            "possible_logo": bool(keyword_matches),
            "matched_keywords": keyword_matches,
            "detection_method": "filename_heuristic",
        }

    def run(self, context, cancellation_event):
        if cancellation_event.is_set():
            return {"cancelled": True}

        image_path = context.metadata.get("image_path")

        if not image_path:
            return {
                "skipped": True,
                "message": "Nessuna immagine locale selezionata.",
            }

        result = self.detect(image_path)

        return {
            "skipped": False,
            "logo_analysis": result,
            "disclaimer": (
                "Rilevamento euristico basato sul nome del file, "
                "non sul riconoscimento visivo del logo."
            ),
        }
