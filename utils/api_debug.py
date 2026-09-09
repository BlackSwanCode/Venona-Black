"""
Mode Debug pour les échanges avec les APIs externes (Censys, Shodan, etc.).

Objectif : pouvoir diagnostiquer un 401/403/429/timeout sans avoir à
ajouter des print() un peu partout. Quand activé, chaque appel API
instrumenté journalise :
    - la méthode + l'URL appelée
    - le code HTTP retourné
    - les paramètres/en-têtes envoyés (avec les secrets masqués)
    - un extrait du corps de la réponse en cas d'erreur

Activation :
    - Variable d'environnement : DEBUG_API_CALLS=1 (ou true/yes/on)
    - Ou dynamiquement depuis l'app (onglet "⚙️ Configuration") via
      set_debug_enabled(True), qui positionne la variable d'environnement
      pour le process en cours.

Les logs sont envoyés sur stderr (visibles dans le terminal qui lance
Streamlit) ET dans le fichier logs/api_debug.log pour relecture après coup.
"""

import os
import sys
import logging

_LOGGER_NAME = "dorker.api_debug"
_configured = False

# Clés considérées sensibles : jamais loguées en clair, même en mode debug.
_SENSITIVE_KEYS = {
    "authorization", "x-api-key", "apikey", "api-key", "api_key",
    "x-organization-id", "organization_id", "cookie", "set-cookie",
    "key", "token", "secret", "pat", "auth", "password",
}


def is_debug_enabled() -> bool:
    return os.getenv("DEBUG_API_CALLS", "false").strip().lower() in ("1", "true", "yes", "on")


def set_debug_enabled(enabled: bool) -> None:
    """Active/désactive le mode debug pour le process courant (utilisé par l'UI)."""
    os.environ["DEBUG_API_CALLS"] = "1" if enabled else "0"
    _get_logger().setLevel(logging.DEBUG if enabled else logging.WARNING)


def _redact(d):
    if not d:
        return d
    redacted = {}
    for k, v in d.items():
        if str(k).lower() in _SENSITIVE_KEYS:
            s = str(v)
            redacted[k] = (s[:4] + "…[masqué]") if len(s) > 4 else "***[masqué]***"
        else:
            redacted[k] = v
    return redacted


def _get_logger() -> logging.Logger:
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    if not _configured:
        logger.setLevel(logging.DEBUG if is_debug_enabled() else logging.WARNING)
        logger.propagate = False
        if not logger.handlers:
            stream_handler = logging.StreamHandler(sys.stderr)
            stream_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
            logger.addHandler(stream_handler)
            try:
                os.makedirs("logs", exist_ok=True)
                file_handler = logging.FileHandler("logs/api_debug.log", encoding="utf-8")
                file_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
                logger.addHandler(file_handler)
            except Exception:
                pass  # Le mode debug ne doit jamais faire planter un collecteur.
        _configured = True
    return logger


def log_api_call(
    collector: str,
    method: str,
    url: str,
    *,
    params: dict = None,
    headers: dict = None,
    payload=None,
    status: int = None,
    response_body: str = None,
    error: str = None,
) -> None:
    """
    Journalise un échange API si le mode debug est actif. No-op sinon
    (le coût est donc négligeable en usage normal).
    """
    if not is_debug_enabled():
        return

    logger = _get_logger()
    logger.setLevel(logging.DEBUG)  # au cas où activé après le premier appel

    parts = [f"[{collector}] {method} {url}"]
    if status is not None:
        parts.append(f"status={status}")
    if params:
        parts.append(f"params={_redact(params)}")
    if headers:
        parts.append(f"headers={_redact(headers)}")
    if payload:
        parts.append(f"payload={payload}")
    if error:
        parts.append(f"ERROR={error}")

    logger.debug(" | ".join(parts))

    if response_body and status is not None and status != 200:
        snippet = response_body if isinstance(response_body, str) else str(response_body)
        logger.debug(f"[{collector}] Corps de réponse (tronqué, 800 car.) : {snippet[:800]}")
