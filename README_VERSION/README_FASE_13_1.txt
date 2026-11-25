FASE 13.1 – SCREENSHOT E CONFRONTO VISUALE

File inclusi:
- services/screenshot_service.py
- modules/screenshot_visual_analyzer.py
- tests/test_screenshot_phase.py

INSTALLAZIONE
1. Copia i due file Python nelle cartelle indicate.
2. Installa Playwright:
   pip install playwright
   python -m playwright install chromium
3. Pillow e ImageHash sono già previsti dalle dipendenze del progetto.

USO DEL SERVIZIO
La funzione capture_authorised_site richiede:
- URL HTTPS;
- authorised_hosts: allowlist esatta di hostname per cui hai autorizzazione;
- output_dir: cartella in cui salvare lo screenshot.

Esempio da usare solo con un host che controlli o per cui hai autorizzazione:
from services.screenshot_service import capture_authorised_site
result = capture_authorised_site(
    "https://example.com",
    {"example.com"},
    "screenshots"
)
print(result.screenshot_path)

SICUREZZA
- Non usare domini di terzi senza autorizzazione.
- Solo HTTPS, porta 443, host esplicitamente autorizzato.
- Gli IP non pubblici vengono bloccati.
- Le richieste a host esterni alla allowlist vengono bloccate.
- Nessun login, compilazione form o invio di dati.
- Non disabilitare i controlli TLS.

CONFRONTO
ScreenshotVisualAnalyzer.compare(reference_path, candidate_path) confronta due
immagini locali con perceptual hash. La percentuale è un indicatore euristico:
non dimostra che un sito sia un clone né che sia malevolo.

TEST
python -m py_compile services/screenshot_service.py modules/screenshot_visual_analyzer.py
pytest -v tests/test_screenshot_phase.py
pytest -v

NOTA DI INTEGRAZIONE
Questa è la prima sottofase autonoma. Non modifica main.py, ScannerEngine o GUI,
così non interferisce con i 75 test già superati. Dopo averla verificata,
integreremo l'acquisizione autorizzata nella GUI e nello storico DB.
