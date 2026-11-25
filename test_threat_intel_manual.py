"""test threat intel manual.

This file contains test helpers or manual checks for the Domain Intelligence
application. It is kept separate from the production application startup.
"""

from pathlib import Path

from services.threat_intel_store import ThreatIntelStore
from modules.threat_intel_analyzer import ThreatIntelAnalyzer
from threading import Event


# Path to the sample test feed
feed_path = Path("data/threat_intel/sample_iocs.csv")


# Import the indicators
store = ThreatIntelStore()

import_result = store.import_csv(str(feed_path))

print("\nIMPORTAZIONE FEED")
print("Importati:", import_result["imported"])
print("Rifiutati:", import_result["rejected"])


# Create the scanner engine
analyzer = ThreatIntelAnalyzer(store)


# Simulated domains to analyze
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