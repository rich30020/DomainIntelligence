from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from services.database_service import DatabaseService


# Identificativo univoco per questa prova
scan_id = str(uuid4())

# Risultato simulato del Subdomain Finder
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

# Risultato simulato del Threat Intelligence Analyzer
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

# Risultato complessivo della scansione simulata
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

# Apertura del database
database = DatabaseService()

# Salvataggio
saved = database.save_scan_result(scan)

print("\nSALVATAGGIO")
print(saved)

# Lettura cronologia
print("\nCRONOLOGIA")
for item in database.get_scan_history():
    print(item)

# Lettura dettagli
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