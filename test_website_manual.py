from core import (
    ScannerEngine,
    ScanRequest,
    ScanScope,
    ScanMode,
)

from modules import WebsiteCloneAnalyzer


# ==========================================
# CONFIGURAZIONE
# ==========================================

DOMINIO_PRINCIPALE = "apsprofili.com    "
DOMINIO_DA_CONFRONTARE = "TUO-SECONDO-DOMINIO.it"


# ==========================================
# CONTROLLO CONFIGURAZIONE
# ==========================================

if (
    DOMINIO_PRINCIPALE == "TUO-DOMINIO.it"
    or DOMINIO_DA_CONFRONTARE == "TUO-SECONDO-DOMINIO.it"
):
    raise ValueError(
        "Devi inserire i tuoi due domini autorizzati."
    )


# ==========================================
# CREAZIONE MOTORE
# ==========================================

engine = ScannerEngine()

engine.register_module(WebsiteCloneAnalyzer())


# ==========================================
# DEFINIZIONE SCOPE AUTORIZZATO
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
# CREAZIONE RICHIESTA
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
# ESECUZIONE
# ==========================================

print("\nAvvio confronto dei siti...\n")

result = engine.run_scan(request)


# ==========================================
# VISUALIZZAZIONE RISULTATI
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