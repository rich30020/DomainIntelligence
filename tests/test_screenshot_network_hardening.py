from services.screenshot_service import _build_host_resolver_rules


def test_host_resolver_rules_pin_authorised_hosts(monkeypatch):
    monkeypatch.setattr(
        "services.screenshot_service._resolve_public_host",
        lambda host: ["203.0.113.10"] if host == "owned.example" else ["198.51.100.20"],
    )
    rules = _build_host_resolver_rules({"owned.example"})
    assert "MAP owned.example 203.0.113.10" in rules
    assert "EXCLUDE localhost" in rules
