from pathlib import Path

from services.threat_intel_store import ThreatIntelStore
from modules.threat_intel_analyzer import ThreatIntelAnalyzer
from threading import Event


# Percorso del feed di test
feed_path = Path("data/threat_intel/sample_iocs.csv")


# Importazione degli indicatori
store = ThreatIntelStore()

import_result = store.import_csv(str(feed_path))

print("\nIMPORTAZIONE FEED")
print("Importati:", import_result["imported"])
print("Rifiutati:", import_result["rejected"])


# Creazione motore
analyzer = ThreatIntelAnalyzer(store)


# Domini simulati da analizzare
domains = [
    "bad-example.test",
    "login.bad-example.test",
    "suspicious-example.test",
    "www.example.com",
]


print("\nRISULTATI THREAT INTELLIGENCE")

for domain in domains:
    result = analyzer.analyze_domain(domain)

    print("\nDominio:", result["domain"])
    print("Segnalato:", result["matched"])
    print("Threat score:", result["threat_score"])
    print("Livello:", result["threat_level"])
    print("Corrispondenze:", result["match_count"])

    for match in result["matches"]:
        print("Fonte:", match["source"])
        print("Tipo corrispondenza:", match["match_type"])
        print("Confidence:", match["confidence"])