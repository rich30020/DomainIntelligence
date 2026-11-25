import pytest

from services.screenshot_service import (
    ScreenshotSecurityError,
    validate_capture_url,
)


def test_rejects_http():
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("http://example.com", {"example.com"})


def test_rejects_host_not_in_allowlist():
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("https://other.example", {"example.com"})


def test_rejects_embedded_credentials():
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("https://user:pass@example.com", {"example.com"})


def test_rejects_nonstandard_port():
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("https://example.com:8443", {"example.com"})


def test_rejects_localhost_even_if_allowlisted():
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("https://localhost", {"localhost"})


def test_normalises_case_and_trailing_dot(monkeypatch):
    monkeypatch.setattr(
        "services.screenshot_service._resolve_public_host",
        lambda hostname: None,
    )
    assert validate_capture_url("https://EXAMPLE.COM./", {"example.com"}) == "example.com"


def test_visual_analyzer_compares_local_images(tmp_path):
    from PIL import Image
    from modules.screenshot_visual_analyzer import ScreenshotVisualAnalyzer

    first = tmp_path / "first.png"
    second = tmp_path / "second.png"
    Image.new("RGB", (100, 100), "white").save(first)
    Image.new("RGB", (100, 100), "white").save(second)

    result = ScreenshotVisualAnalyzer().compare(first, second)
    assert result.similarity_percent == 100.0
    assert result.assessment == "somiglianza_visiva_molto_alta"
    assert "non prova" in result.disclaimer
