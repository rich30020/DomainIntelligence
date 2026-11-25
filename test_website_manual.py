"""test website manual.

This file contains test helpers or manual checks for the Domain Intelligence
application. It is kept separate from the production application startup.
"""

from core import (
    ScannerEngine,
    ScanRequest,
    ScanScope,
    ScanMode,
)

from modules import WebsiteCloneAnalyzer


# ==========================================
# CONFIGURATION
# ==========================================

DOMINIO_PRINCIPALE = "apsprofili.com    "
DOMINIO_DA_CONFRONTARE = "TUO-SECONDO-DOMINIO.it"


# ==========================================
# CONFIGURATION CHECK
# ==========================================

if (
    DOMINIO_PRINCIPALE == "TUO-DOMINIO.it"
    or DOMINIO_DA_CONFRONTARE == "TUO-SECONDO-DOMINIO.it"
):
    raise ValueError(
        "Devi inserire i tuoi due domini autorizzati."
    )


# ==========================================
# ENGINE CREATION
# ==========================================

engine = ScannerEngine()

engine.register_module(WebsiteCloneAnalyzer())


# ==========================================
# DECLARE AUTHORIZED SCOPE
# ==========================================

scope = ScanScope(
    root_domain=DOMINIO_PRINCIPALE,
    mode=ScanMode.AUTHORIZED,
    authorized_domains=[
        DOMINIO_PRINCIPALE,
        DOMINIO_DA_CONFRONTARE,
    ],
)


# ==========================================
# BUILD SCAN REQUEST
# ==========================================

request = ScanRequest(
    domain=DOMINIO_PRINCIPALE,
    scope=scope,
    selected_modules=["website_clone_analyzer"],
    metadata={
        "comparison_domain": DOMINIO_DA_CONFRONTARE,
    },
)


# ==========================================
# EXECUTION
# ==========================================

print("\nAvvio confronto dei siti...\n")

result = engine.run_scan(request)


# ==========================================
# DISPLAY RESULTS
# ==========================================

print("STATO SCANSIONE:", result.status)

for module_result in result.results:

    print("\nMODULO:", module_result.module_name)
    print("SUCCESSO:", module_result.success)

    if module_result.error:
        print("ERRORE:", module_result.error)

    if module_result.success:
        data = module_result.data

        similarity = data.get("similarity", {})

        print(
            "DOMINIO PRINCIPALE:",
            data.get("original_domain"),
        )

        print(
            "DOMINIO CONFRONTATO:",
            data.get("comparison_domain"),
        )

        print(
            "PUNTEGGIO SOMIGLIANZA:",
            similarity.get("score"),
        )

        print(
            "LIVELLO:",
            similarity.get("level"),
        )

        print(
            "CAMPI CONFRONTATI:",
            similarity.get("compared_fields"),
        )

print("\nTest terminato.")