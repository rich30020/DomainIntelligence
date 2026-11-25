"""Automated tests for test screenshot phase.

These tests protect expected behavior and help detect regressions in the
Domain Intelligence implementation.
"""

import pytest

from services.screenshot_service import (
    ScreenshotSecurityError,
    validate_capture_url,
)


def test_rejects_http():
    """Verify expected behavior for rejects http.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("http://example.com", {"example.com"})


def test_rejects_host_not_in_allowlist():
    """Verify expected behavior for rejects host not in allowlist.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("https://other.example", {"example.com"})


def test_rejects_embedded_credentials():
    """Verify expected behavior for rejects embedded credentials.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("https://user:pass@example.com", {"example.com"})


def test_rejects_nonstandard_port():
    """Verify expected behavior for rejects nonstandard port.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("https://example.com:8443", {"example.com"})


def test_rejects_localhost_even_if_allowlisted():
    """Verify expected behavior for rejects localhost even if allowlisted.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    with pytest.raises(ScreenshotSecurityError):
        validate_capture_url("https://localhost", {"localhost"})


def test_normalises_case_and_trailing_dot(monkeypatch):
    """Verify expected behavior for normalises case and trailing dot.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
    monkeypatch.setattr(
        "services.screenshot_service._resolve_public_host",
        lambda hostname: None,
    )
    assert validate_capture_url("https://EXAMPLE.COM./", {"example.com"}) == "example.com"


def test_visual_analyzer_compares_local_images(tmp_path):
    """Verify expected behavior for visual analyzer compares local images.
    Arrange the inputs, execute the operation, and assert its observable result.
    """
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
