"""Confronto visuale tra screenshot locali di riferimento."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class VisualComparison:
    reference_path: str
    candidate_path: str
    similarity_percent: float
    phash_distance: int
    assessment: str
    disclaimer: str = (
        "La somiglianza visiva è un indicatore tecnico, non prova di clonazione, "
        "phishing o intento fraudolento."
    )


class ScreenshotVisualAnalyzer:
    name = "screenshot_visual_analyzer"

    def compare(self, reference_path: str | Path, candidate_path: str | Path) -> VisualComparison:
        reference = Path(reference_path)
        candidate = Path(candidate_path)
        if not reference.is_file() or not candidate.is_file():
            raise FileNotFoundError("Entrambi i file screenshot devono esistere.")

        try:
            from PIL import Image
            import imagehash
        except ImportError as exc:
            raise RuntimeError("Installa Pillow e ImageHash per il confronto visuale.") from exc

        with Image.open(reference) as image:
            reference_hash = imagehash.phash(image.convert("RGB"))
        with Image.open(candidate) as image:
            candidate_hash = imagehash.phash(image.convert("RGB"))

        distance = int(reference_hash - candidate_hash)
        hash_bits = len(reference_hash.hash) ** 2
        similarity = max(0.0, (1.0 - distance / hash_bits) * 100.0)

        if similarity >= 95:
            assessment = "somiglianza_visiva_molto_alta"
        elif similarity >= 85:
            assessment = "somiglianza_visiva_alta"
        elif similarity >= 70:
            assessment = "somiglianza_visiva_parziale"
        else:
            assessment = "somiglianza_visiva_bassa"

        return VisualComparison(
            reference_path=str(reference.resolve()),
            candidate_path=str(candidate.resolve()),
            similarity_percent=round(similarity, 2),
            phash_distance=distance,
            assessment=assessment,
        )
