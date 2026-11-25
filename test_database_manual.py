"""test database manual.

This file contains test helpers or manual checks for the Domain Intelligence
application. It is kept separate from the production application startup.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from services.database_service import DatabaseService


# Unique identifier for this test run
scan_id = str(uuid4())

# Simulated Subdomain Finder output
subdomain_result = SimpleNamespace(
    module_name="subdomain_finder",
    success=True,
    error=None,
    completed_at=datetime.now(timezone.utc),
    data={
        "subdomains": [
            {
                "hostname": "www.example.test",
                "sources": ["crtsh"],
                "ip_addresses": ["192.0.2.10"],
                "status": "resolved",
            }
        ]
    },
)

# Simulated Threat Intelligence Analyzer output
threat_result = SimpleNamespace(
    module_name="threat_intel_analyzer",
    success=True,
    error=None,
    completed_at=datetime.now(timezone.utc),
    data={
        "results": [
            {
                "domain": "bad-example.test",
                "matched": True,
                "threat_score": 95,
                "threat_level": "critical",
                "matches": [
                    {
                        "source": "TestFeed",
                        "confidence": 95,
                    }
                ],
            }
        ]
    },
)

# Combined result for the simulated scan
scan = SimpleNamespace(
    scan_id=scan_id,
    domain="example.test",
    status="completed",
    started_at=datetime.now(timezone.utc),
    completed_at=datetime.now(timezone.utc),
    results=[
        subdomain_result,
        threat_result,
    ],
)

# Open the database
database = DatabaseService()

# Save the simulated scan
saved = database.save_scan_result(scan)

print("\nSALVATAGGIO")
print(saved)

# Read scan history
print("\nCRONOLOGIA")
for item in database.get_scan_history():
    print(item)

# Read scan details
print("\nDETTAGLI SCANSIONE")
details = database.get_scan_details(scan_id)

print("Dominio:", details["domain"])
print("Stato:", details["status"])

print("\nMODULI:")
for module in details["modules"]:
    print(module["module_name"], module["success"])

print("\nEVIDENZE:")
for finding in details["findings"]:
    print(
        finding["finding_type"],
        finding["indicator"],
        finding["level"],
    )

database.close()

print("\nTEST DATABASE COMPLETATO")