
from threading import Event
from unittest.mock import Mock

from core import ScanContext, ScanScope, ScanMode

from modules.subdomain_normalizer import SubdomainNormalizer
from modules.subdomain_finder import SubdomainFinder


def test_normalize_hostname():

    normalizer = SubdomainNormalizer()

    result = normalizer.normalize(
        "*.WWW.EXAMPLE.COM."
    )

    assert result == "www.example.com"


def test_reject_invalid_hostname():

    normalizer = SubdomainNormalizer()

    assert normalizer.normalize(
        "invalid hostname"
    ) is None


def test_domain_boundary():

    normalizer = SubdomainNormalizer()

    assert normalizer.belongs_to_domain(
        "mail.example.com",
        "example.com"
    )

    assert not normalizer.belongs_to_domain(
        "fakeexample.com",
        "example.com"
    )


def test_remove_duplicates():

    normalizer = SubdomainNormalizer()

    records = [
        {
            "hostname": "www.example.com",
            "source": "crtsh"
        },
        {
            "hostname": "WWW.EXAMPLE.COM.",
            "source": "otx"
        }
    ]

    result = normalizer.process(
        "example.com",
        records
    )

    assert len(result) == 1

    assert set(result[0]["sources"]) == {
        "crtsh",
        "otx"
    }


def test_subdomain_finder():

    finder = SubdomainFinder()

    source = Mock()
    source.name = "test_source"

    source.search.return_value = {
        "success": True,
        "count": 2,
        "subdomains": [],
        "results": [
            {
                "hostname": "www.example.com",
                "ip": "192.0.2.1"
            },
            {
                "hostname": "mail.example.com",
                "ip": "192.0.2.2"
            }
        ]
    }

    finder.sources = [source]

    finder.verifier.verify = Mock(
        side_effect=[
            {
                "status": "resolved",
                "addresses": ["192.0.2.1"]
            },
            {
                "status": "unresolved",
                "addresses": []
            }
        ]
    )

    context = ScanContext(
        scan_id="test-id",
        domain="example.com",
        scope=ScanScope(
            root_domain="example.com",
            mode=ScanMode.PASSIVE
        ),
        started_at="test"
    )

    result = finder.run(context, Event())

    assert result["total_discovered"] == 2

    assert result["subdomains"][0]["hostname"] == (
        "mail.example.com"
    )

    assert result["subdomains"][1]["hostname"] == (
        "www.example.com"
    )
