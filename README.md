# 🕵️‍♂️ Dorker Pro — OSINT Command Center v6.0

Dorker Pro est une plateforme de renseignement en sources ouvertes (OSINT) pensée pour la collecte, l'enrichissement et la corrélation d'indicateurs (IOC), la gestion de cas d'investigation, et la surveillance continue de cibles (watchlists) — le tout via une interface Streamlit.

Son architecture centrale repose sur un **système de collecteurs modulaires** : chaque source de données (moteur de recherche, plateforme de threat intel, base de fuites, etc.) est un plugin indépendant, déclaré dans un registre JSON et chargé dynamiquement au démarrage. C'est ce système que ce document met en avant, avec un guide complet pour créer et intégrer de nouveaux collecteurs.

---

## Sommaire

- [Aperçu de l'architecture](#aperçu-de-larchitecture)
- [Installation](#installation)
- [Démarrage rapide](#démarrage-rapide)
- [🧩 Créer un nouveau collecteur](#-créer-un-nouveau-collecteur)
- [🔌 Intégrer le collecteur au pipeline](#-intégrer-le-collecteur-au-pipeline)
- [Catégories de collecteurs existantes](#catégories-de-collecteurs-existantes)
- [Bonnes pratiques de collecte](#bonnes-pratiques-de-collecte)
- [Tester un collecteur](#tester-un-collecteur)
- [Structure du projet](#structure-du-projet)
- [Avertissement légal](#avertissement-légal)

---

## Aperçu de l'architecture

```
Requête utilisateur
        │
        ▼
 DorkTranslator ──► adapte la syntaxe (dorks) par moteur, via QuerySanitizer
        │
        ▼
 CollectorManager ──► lit collectors_registry.json, instancie les collecteurs actifs
        │
        ├──► Collecteur A ─┐
        ├──► Collecteur B ─┼──► exécution asynchrone parallèle (asyncio.gather)
        └──► Collecteur N ─┘
        │
        ▼
 List[SearchResult] ──► IOCExtractor, scoring, MITRE mapping, enrichissement
        │
        ▼
 Stockage (SQLite) ──► UI (recherche, dashboard, cas, graphe, watchlists, alertes)
```

Le `CollectorManager` (`collectors/manager.py`) est le chef d'orchestre : il lit `collectors_registry.json`, importe dynamiquement chaque module de collecteur, vérifie la présence des clés API requises, puis lance tous les collecteurs sélectionnés en parallèle via `asyncio.gather`. Ce découplage total entre le registre, le manager et l'implémentation de chaque collecteur est ce qui rend l'ajout d'une nouvelle source aussi simple que d'ajouter un fichier et une entrée JSON — **sans jamais toucher au cœur de l'application**.

## Installation

```bash
git clone <url-du-repo>
cd dorker-pro
python -m venv venv && source venv/bin/activate  # ou venv\Scripts\activate sous Windows
pip install -r requirements.txt
cp .env.example .env   # renseignez vos clés API
python init_db.py
streamlit run app.py
```

## Démarrage rapide

Au lancement, `app.py` vérifie la présence de la base SQLite (`osint_searches.db`), affiche la bannière légale, puis expose la navigation entre les modules : Recherche OSINT, Centre de Commandement, Gestion des Cas, Graphe d'Entités, Watchlists & Alertes, et Configuration.

---

## 🧩 Créer un nouveau collecteur

Un collecteur est une classe Python qui interroge **une** source de données et retourne une liste de `SearchResult`. C'est le point d'extension principal de Dorker Pro — la plupart des contributions au projet consistent à en ajouter un nouveau.

### 1. Choisir (ou créer) la catégorie

Les collecteurs sont rangés par catégorie sous `collectors/` :

| Dossier | Catégorie | Exemples actuels |
|---|---|---|
| `collectors/search_engines/` | Moteurs de recherche | Brave, Mojeek, DuckDuckGo, Qwant, SearXNG |
| `collectors/surface_attack/` | Surface d'attaque / recon infra | Shodan, Censys, crt.sh, SecurityTrails |
| `collectors/code_source/` | Dépôts de code | GitHub, GitHub Advanced |
| `collectors/breach_intel/` | Fuites de données / identifiants | HIBP, LeakIX, DeHashed |
| `collectors/threat_intel/` | Threat intelligence | GreyNoise, URLScan, ThreatFox, AlienVault OTX, URLhaus, MalwareBazaar, Pulsedive |
| `collectors/passive_feed/` | Flux passifs | RSS/Atom |

Si aucune catégorie n'est adaptée, créez un nouveau sous-dossier avec un `__init__.py` vide.

### 2. Hériter de `BaseCollector`

Toute la mécanique commune (configuration, rate limiting) est fournie par `collectors/base.py`. Il suffit d'implémenter la méthode asynchrone `collect()` :

```python
# collectors/threat_intel/mon_flux.py
"""
MonFlux Collector — description courte de la source.

API: https://api.monflux.example/
Clé API requise (MONFLUX_API_KEY dans .env) — ou non, selon la source.
"""

import os
import aiohttp
from typing import List
from collectors.base import BaseCollector
from core.models import SearchResult
import logging

logger = logging.getLogger("dorker.monflux")

class MonFluxCollector(BaseCollector):
    """Recherche des indicateurs sur MonFlux."""

    BASE_URL = "https://api.monflux.example"

    async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]:
        api_key = os.getenv("MONFLUX_API_KEY")
        if not api_key:
            logger.info("MonFlux désactivé (clé API manquante)")
            return []

        params = {"key": api_key, "q": query, "limit": 20}

        try:
            async with session.get(f"{self.BASE_URL}/search", params=params, timeout=15) as response:
                if response.status != 200:
                    logger.warning(f"MonFlux a retourné {response.status}")
                    return []

                data = await response.json()
                return [
                    SearchResult(
                        title=f"MonFlux: {item.get('name', 'N/A')}",
                        url=item.get("link", ""),
                        snippet=item.get("description", "")[:300],
                        source="MonFlux",
                    )
                    for item in data.get("results", [])[:20]
                ]
        except Exception as e:
            logger.error(f"Erreur MonFlux: {e}")
            return []
```

**Règles à respecter :**

- La signature de `collect()` est fixe : `async def collect(self, query: str, session: aiohttp.ClientSession) -> List[SearchResult]`.
- Le collecteur **ne doit jamais lever d'exception non gérée** — `CollectorManager.run_all()` capture bien les exceptions via `asyncio.gather(..., return_exceptions=True)`, mais un collecteur qui échoue proprement (retourne `[]` et logue l'erreur) est plus facile à diagnostiquer.
- Utilisez `self.config` pour toute option spécifique passée depuis le registre (ex. limites, endpoints alternatifs).
- Ne gérez pas vous-même le rate limiting dans `collect()` : `CollectorManager._safe_collect()` appelle déjà `self._respect_rate_limit()` avant chaque exécution, en s'appuyant sur `rate_limit.requests_per_minute` défini dans le registre.
- Si la source nécessite une clé API, lisez-la via `os.getenv()` et retournez `[]` proprement si elle est absente (voir `ShodanCollector` comme référence).

### 3. Déclarer le collecteur dans le registre

Ajoutez une entrée dans `collectors_registry.json` :

```json
{
  "id": "monflux",
  "name": "MonFlux",
  "category": "threat_intel",
  "module": "collectors.threat_intel.mon_flux",
  "class": "MonFluxCollector",
  "enabled": true,
  "rate_limit": {
    "requests_per_minute": 30
  },
  "requires_api_key": true,
  "env_var": "MONFLUX_API_KEY"
}
```

| Champ | Rôle |
|---|---|
| `id` | Identifiant unique, utilisé partout dans l'UI et l'API interne |
| `name` | Nom affiché dans l'interface |
| `category` | Regroupement logique (surface_attack, threat_intel, etc.) |
| `module` / `class` | Chemin d'import Python et nom de la classe à instancier |
| `enabled` | Active/désactive le collecteur sans supprimer sa configuration |
| `rate_limit.requests_per_minute` | Limite appliquée automatiquement par `BaseCollector` |
| `requires_api_key` / `env_var` | Si `true`, le `CollectorManager` vérifie que la variable d'environnement `env_var` est définie avant de charger le collecteur ; sinon il l'ignore silencieusement (avec un log) |

C'est cette entrée que `CollectorManager._load_collectors()` lit au démarrage pour faire l'`importlib.import_module()` + `getattr()` qui instancie votre classe — **aucune autre modification du code n'est nécessaire**.

### 4. Ajouter la clé API (si nécessaire)

Ajoutez la variable dans `.env` :

```
MONFLUX_API_KEY=votre_clé_ici
```

Si `requires_api_key` est `true` et que la variable est absente, le collecteur est simplement désactivé au chargement (log `INFO`), sans faire échouer le reste de l'application.

---

## 🔌 Intégrer le collecteur au pipeline

Une fois déclaré dans le registre, le collecteur est **automatiquement disponible** dans :

- **l'interface de recherche** (`ui/search.py`), qui liste les collecteurs actifs pour sélection ;
- **`CollectorManager.run_all()`**, qui l'inclut dans l'exécution parallèle dès qu'il est sélectionné (ou par défaut si aucune sélection n'est fournie) ;
- **le pipeline d'extraction d'IOC** (`core/ioc_extractor.py`), qui traite les `snippet` de tous les `SearchResult` de la même façon, quelle que soit leur source ;
- **le scoring** (`core/scoring.py`) et le **mapping MITRE ATT&CK** (`core/mitre_mapper.py`), appliqués uniformément.

Si votre source expose une syntaxe de requête particulière (opérateurs, dorks), ajoutez ses capacités dans `core/dork_translator.py` (`ENGINE_CAPABILITIES`) afin que `DorkTranslator.translate_for_multiple_engines()` sache adapter automatiquement la requête traduite pour ce moteur avant de l'envoyer via `use_translated_queries`.

Aucune modification de `app.py`, de `collectors/manager.py` ou de la base de données n'est requise pour un collecteur standard : le registre JSON est le seul point de couplage entre votre code et le reste de l'application.

---

## Catégories de collecteurs existantes

| Catégorie | Collecteurs |
|---|---|
| Moteurs de recherche | Brave, Mojeek, DuckDuckGo, Qwant, SearXNG |
| Surface d'attaque | Shodan, Censys, crt.sh, SecurityTrails |
| Sources de code | GitHub, GitHub Advanced |
| Fuites de données | HIBP, LeakIX, DeHashed |
| Threat intelligence | GreyNoise, URLScan, ThreatFox, AlienVault OTX, URLhaus, MalwareBazaar, Pulsedive |
| Flux passifs | RSS/Atom (BleepingComputer, The Hacker News, Dark Reading, ThreatPost, SecurityWeek, Krebs on Security, The Record) |

## Bonnes pratiques de collecte

- **Timeouts explicites** : toujours fixer un `timeout` (15s dans les collecteurs existants) sur chaque requête HTTP.
- **Tolérance aux pannes** : une source indisponible ne doit jamais interrompre les autres — retournez `[]` en cas d'erreur.
- **Respect des quotas** : laissez `BaseCollector` gérer le rythme des appels via `rate_limit.requests_per_minute` plutôt que d'ajouter des `sleep()` manuels.
- **OPSEC** : les requêtes sortantes peuvent être routées via proxy (voir `utils/opsec.py` et la vérification d'anonymat dans l'onglet Configuration) ; évitez de fuiter des identifiants dans les logs.
- **Normalisation** : renseignez toujours `source` avec un nom lisible (ex. `"crt.sh"`, `"RSS/BleepingComputer"`) pour que le dashboard et le graphe d'entités puissent regrouper correctement les résultats.

## Tester un collecteur

Les tests unitaires vivent dans `tests/`. `tests/test_collectors.py` est le point de départ pour valider :

- que `collect()` retourne bien une liste de `SearchResult` ;
- le comportement en l'absence de clé API (retour `[]`, pas d'exception) ;
- la gestion des réponses HTTP en erreur (4xx/5xx, timeout).

```bash
pytest tests/test_collectors.py -v
```

## Structure du projet

```
.
├── app.py                     # Point d'entrée Streamlit
├── init_db.py                 # Initialisation de la base SQLite
├── collectors_registry.json   # Registre déclaratif des collecteurs
├── collectors/
│   ├── base.py                # Classe abstraite BaseCollector
│   ├── manager.py              # Chargement dynamique + orchestration asynchrone
│   ├── content_scraper.py
│   ├── search_engines/
│   ├── surface_attack/
│   ├── code_source/
│   ├── breach_intel/
│   ├── threat_intel/
│   └── passive_feed/
├── core/                      # Modèles, extraction d'IOC, scoring, dorks, MITRE
├── enrichment/                # AbuseIPDB, VirusTotal, WHOIS/DNS
├── storage/                   # Persistance SQLite + export (STIX, etc.)
├── alerting/                  # Dispatch d'alertes (Telegram, webhook)
├── ui/                        # Interface Streamlit (recherche, cas, graphe, watchlists)
├── utils/                     # Logger, rate limiter, OPSEC
└── tests/
```

## Avertissement légal

Dorker Pro est un outil d'OSINT destiné à des usages légitimes : investigations autorisées, threat intelligence défensive, red/blue teaming encadré, recherche en sécurité. L'utilisateur reste seul responsable du respect des lois applicables et des conditions d'utilisation des sources interrogées (quotas API, ToS, RGPD). Une bannière de rappel légal (`ui/legal_banner.py`) est affichée à chaque lancement de l'application.
