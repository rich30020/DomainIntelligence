
"""Calculate perceptual fingerprints for local image files."""

from pathlib import Path

from PIL import Image
import imagehash


class ImageHashAnalyzer:
    """Generate perceptual hashes that tolerate small visual transformations.

    These are compact visual fingerprints, not cryptographic integrity hashes;
    they indicate visual resemblance rather than byte-for-byte identity.
    """
    name = "image_hash_analyzer"
    requires_active = False

    @staticmethod
    def analyze(image_path: str) -> dict:
        """Open an image and return its pHash, aHash, and dHash values."""
        path = Path(image_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Immagine non trovata: {image_path}"
            )

        if not path.is_file():
            raise ValueError("Il percorso non è un file.")

        with Image.open(path) as image:
            image.verify()

        with Image.open(path) as image:
            image_format = image.format
            image = image.convert("RGB")

            return {
                "filename": path.name,
                "width": image.width,
                "height": image.height,
                "format": image_format,
                "phash": str(imagehash.phash(image)),
                "ahash": str(imagehash.average_hash(image)),
                "dhash": str(imagehash.dhash(image)),
            }

    @staticmethod
    def compare_hashes(first: str, second: str) -> dict:
        """Compare two perceptual hashes using Hamming distance and similarity."""
        hash_a = imagehash.hex_to_hash(first)
        hash_b = imagehash.hex_to_hash(second)

        distance = hash_a - hash_b
        maximum_distance = hash_a.hash.size

        similarity = (
            1 - distance / maximum_distance
        ) * 100

        return {
            "distance": distance,
            "similarity": round(similarity, 2),
        }

    def run(self, context, cancellation_event):
        """Read the image path from scan metadata and return image fingerprints."""
        if cancellation_event.is_set():
            return {"cancelled": True}

        image_path = context.metadata.get("image_path")

        if not image_path:
            return {
                "skipped": True,
                "message": "Nessuna immagine locale selezionata.",
            }

        result = self.analyze(image_path)

        if cancellation_event.is_set():
            return {"cancelled": True}

        return {
            "skipped": False,
            "image_analysis": result,
        }
