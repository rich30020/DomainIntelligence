"""Automated tests for test image analyzer.

These tests protect the documented behavior of the Domain Intelligence application
and help detect regressions when implementation details are changed.
"""

from PIL import Image

from modules.image_hash_analyzer import ImageHashAnalyzer
from modules.logo_detector import LogoDetector
from modules.image_similarity_analyzer import ImageSimilarityAnalyzer


def test_image_hash_analyzer(tmp_path):
    """Verify expected behavior for image hash analyzer.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    image_path = tmp_path / "logo.png"

    image = Image.new("RGB", (100, 100), "white")
    image.save(image_path)

    result = ImageHashAnalyzer.analyze(str(image_path))

    assert result["filename"] == "logo.png"
    assert result["width"] == 100
    assert result["height"] == 100
    assert result["phash"]


def test_identical_image_hashes(tmp_path):
    """Verify expected behavior for identical image hashes.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    image_path = tmp_path / "logo.png"

    image = Image.new("RGB", (100, 100), "white")
    image.save(image_path)

    result = ImageHashAnalyzer.analyze(str(image_path))

    comparison = ImageHashAnalyzer.compare_hashes(
        result["phash"],
        result["phash"],
    )

    assert comparison["distance"] == 0
    assert comparison["similarity"] == 100


def test_logo_detector(tmp_path):
    """Verify expected behavior for logo detector.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    image_path = tmp_path / "company_logo.png"

    image = Image.new("RGB", (100, 100), "white")
    image.save(image_path)

    result = LogoDetector().detect(str(image_path))

    assert result["possible_logo"] is True
    assert "logo" in result["matched_keywords"]


def test_logo_detector_negative(tmp_path):
    """Verify expected behavior for logo detector negative.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    image_path = tmp_path / "photo.png"

    image = Image.new("RGB", (100, 100), "white")
    image.save(image_path)

    result = LogoDetector().detect(str(image_path))

    assert result["possible_logo"] is False


def test_image_similarity_identical(tmp_path):
    """Verify expected behavior for image similarity identical.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    first_path = tmp_path / "first.png"
    second_path = tmp_path / "second.png"

    image = Image.new("RGB", (100, 100), "white")
    image.save(first_path)
    image.save(second_path)

    analyzer = ImageSimilarityAnalyzer()

    result = analyzer.compare(
        str(first_path),
        str(second_path),
    )

    assert result["similarity_score"] == 100