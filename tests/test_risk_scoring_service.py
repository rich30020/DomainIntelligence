from types import SimpleNamespace

from services.risk_scoring_service import RiskScoringService


def scan_result_with_threat_data(data, success=True):
    module = SimpleNamespace(
        module_name="threat_intel_analyzer",
        success=success,
        data=data,
        error=None,
    )
    return SimpleNamespace(
        domain="example.com",
        results=[module],
    )


def test_no_ioc_match_is_not_reported_as_safe():
    result = scan_result_with_threat_data({
        "total_matches": 0,
        "results": [
            {
                "domain": "example.com",
                "matched": False,
                "matches": [],
            }
        ],
    })

    assessment = RiskScoringService().calculate(result)

    assert assessment["score"] is None
    assert assessment["level"] == "non_valutabile"
    assert assessment["status"] == "nessuna_corrispondenza_ioc"
    assert "non dimostra" in assessment["explanation"]


def test_single_ioc_uses_feed_confidence():
    result = scan_result_with_threat_data({
        "results": [
            {
                "domain": "example.com",
                "matched": True,
                "matches": [
                    {
                        "indicator": "example.com",
                        "type": "domain",
                        "source": "sample-feed",
                        "confidence": 82,
                    }
                ],
            }
        ]
    })

    assessment = RiskScoringService().calculate(result)

    assert assessment["score"] == 82
    assert assessment["level"] == "alto"
    assert assessment["evidence_count"] == 1


def test_distinct_sources_add_small_bonus_and_cap_at_100():
    result = scan_result_with_threat_data({
        "results": [
            {
                "domain": "example.com",
                "matches": [
                    {
                        "indicator": "example.com",
                        "type": "domain",
                        "source": "feed-a",
                        "confidence": 98,
                    },
                    {
                        "indicator": "example.com",
                        "type": "domain",
                        "source": "feed-b",
                        "confidence": 95,
                    },
                ],
            }
        ]
    })

    assessment = RiskScoringService().calculate(result)

    assert assessment["score"] == 100
    assert assessment["independent_sources"] == 2


def test_duplicate_same_indicator_and_source_is_deduplicated():
    result = scan_result_with_threat_data({
        "results": [
            {
                "domain": "example.com",
                "matches": [
                    {
                        "indicator": "example.com",
                        "type": "domain",
                        "source": "feed-a",
                        "confidence": 65,
                    },
                    {
                        "indicator": "example.com",
                        "type": "domain",
                        "source": "feed-a",
                        "confidence": 65,
                    },
                ],
            }
        ]
    })

    assessment = RiskScoringService().calculate(result)

    assert assessment["evidence_count"] == 1
    assert assessment["score"] == 65


def test_failed_threat_module_is_not_a_clean_result():
    result = scan_result_with_threat_data({}, success=False)

    assessment = RiskScoringService().calculate(result)

    assert assessment["score"] is None
    assert assessment["status"] == "verifica_non_riuscita"
    assert assessment["warnings"]


def test_missing_threat_module_is_not_a_clean_result():
    result = SimpleNamespace(domain="example.com", results=[])

    assessment = RiskScoringService().calculate(result)

    assert assessment["score"] is None
    assert assessment["status"] == "modulo_non_eseguito"


def test_dict_scan_result_is_supported():
    result = {
        "domain": "example.com",
        "results": [
            {
                "module_name": "threat_intel_analyzer",
                "success": True,
                "data": {
                    "results": [
                        {
                            "domain": "example.com",
                            "matches": [
                                {
                                    "indicator": "example.com",
                                    "type": "domain",
                                    "source": "feed",
                                    "confidence": 42,
                                }
                            ],
                        }
                    ]
                },
            }
        ],
    }

    assessment = RiskScoringService().calculate(result)

    assert assessment["score"] == 42
    assert assessment["level"] == "medio"
