# 🕵️‍♂️ Dorker Pro — OSINT Command Center v6.0

Dorker Pro est une plateforme de renseignement en sources ouvertes (OSINT) pensée pour la collecte, l'enrichissement et la corrélation d'indicateurs (IOC), la gestion de cas d'investigation, et la surveillance continue de cibles (watchlists) — le tout via une interface Streamlit.

Son architecture centrale repose sur un **système de collecteurs modulaires** : chaque source de données (moteur de recherche, plateforme de threat intel, base de fuites, etc.) est un plugin indépendant, déclaré dans un registre JSON et chargé dynamiquement au démarrage. C'est ce système que ce document met en avant, avec un guide complet pour créer et intégrer de nouveaux collecteurs.

---

## Sommaire

- [Aperçu de l'architecture](#aperçu-de-larchitecture)
- [Modules principaux](#modules-principaux)
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
Requête utilisateur (ui/search.py)
        │
        ▼
 QuerySanitizer ──► nettoie/valide la requête brute
        │
        ▼
 DorkTranslator ──► adapte la syntaxe (dorks/opérateurs) par moteur cible
        │
        ▼
 CollectorManager ──► lit collectors_registry.json, instancie les collecteurs actifs,
        │              vérifie la clé API requise (env_var), applique le rate limiting
        │
        ├──► Collecteur A ─┐
        ├──► Collecteur B ─┼──► exécution asynchrone parallèle (asyncio.gather)
        └──► Collecteur N ─┘
        │
        ▼
 List[SearchResult]
        │
        ├──► IOCExtractor (core/ioc_extractor.py) ──► IOC typés (IP, domaine, hash, secrets…)
        │                                                  │
        │                                                  ▼
        │                                     EnrichmentOrchestrator (enrichment/orchestrator.py)
        │                                     ── cache SQLite 7j, puis AbuseIPDB / VirusTotal / WHOIS-DNS
        │
        ├──► Scoring (core/scoring.py) ──► score de sévérité pondéré par type d'IOC
        ├──► MitreMapper (core/mitre_mapper.py) ──► mapping vers techniques ATT&CK
        └──► DomainWhitelist (core/domain_whitelist.py) ──► filtre les faux-positifs (vendors, CDN…)
        │
        ▼
 DatabaseManager (storage/db_manager.py, SQLite) ──► cases, searches, iocs, leaks, watchlists, alerts
        │
        ├──► ExportManager (storage/export_manager.py) ──► export STIX / rapports
        │
        ▼
 UI Streamlit (app.py) : Recherche, Centre de Commandement, Cas, Graphe d'Entités,
                          Watchlists & Alertes, Analyse Manuelle, Configuration
        │
        ▼ (en tâche de fond / déclenché manuellement)
 WatchlistMonitor (ui/watchlist_monitor.py) ──► rejoue les collecteurs sur les termes
                                                 surveillés ──► AlertDispatcher (alerting/dispatcher.py)
                                                 ──► Slack / Telegram / Webhook
```

Le `CollectorManager` (`collectors/manager.py`) est le chef d'orchestre de la collecte : il lit `collectors_registry.json`, importe dynamiquement chaque module de collecteur, vérifie la présence des clés API requises, puis lance tous les collecteurs sélectionnés en parallèle via `asyncio.gather`. Ce découplage total entre le registre, le manager et l'implémentation de chaque collecteur est ce qui rend l'ajout d'une nouvelle source aussi simple que d'ajouter un fichier et une entrée JSON — **sans jamais toucher au cœur de l'application**.

En aval de la collecte, le pipeline est tout aussi découplé : l'extraction d'IOC, l'enrichissement, le scoring et le mapping MITRE s'appliquent uniformément à n'importe quel `SearchResult`, quelle que soit sa source. L'`EnrichmentOrchestrator` met en cache chaque enrichissement en base pendant 7 jours (table `iocs`) pour limiter la consommation de quotas API tiers. Le `WatchlistMonitor` referme la boucle en réexécutant périodiquement (ou manuellement) les collecteurs sur des termes surveillés et en déclenchant des alertes (Slack/Telegram/webhook) via l'`AlertDispatcher` en cas de nouveauté.

## Modules principaux

Au-delà des collecteurs (voir plus bas), le projet est organisé en couches indépendantes :

| Module | Rôle |
|---|---|
| `core/models.py` | Modèles Pydantic partagés : `SearchResult`, `IOC`, `Leak`, `Case`, `WatchlistItem`, `Alert`, `EnrichmentResult`. |
| `core/query_sanitizer.py` | Nettoie/valide la requête utilisateur avant collecte. |
| `core/dork_translator.py` | Adapte une requête (dorks/opérateurs) à la syntaxe propre à chaque moteur (`ENGINE_CAPABILITIES`). |
| `core/dork_templates.py` | Bibliothèque de templates de dorks réutilisables. |
| `core/ioc_extractor.py` | Détecte les IOC (IP, domaines, hashs, emails, secrets type clés AWS/GitHub/clés privées…) dans les `snippet` des résultats. |
| `core/domain_whitelist.py` | Liste de domaines légitimes (vendors sécurité, CDN…) exclus de l'extraction d'IOC pour limiter les faux-positifs. |
| `core/scoring.py` | Calcule un score de sévérité pondéré par type d'IOC, confiance et fiabilité de la source. |
| `core/mitre_mapper.py` | Fait correspondre les IOC/techniques observées à la matrice MITRE ATT&CK. |
| `enrichment/orchestrator.py` | Orchestre l'enrichissement d'un IOC (AbuseIPDB, VirusTotal, WHOIS/DNS) avec un cache SQLite de 7 jours pour économiser les quotas. |
| `enrichment/abuseipdb.py`, `virustotal.py`, `whois_dns.py` | Un client par source d'enrichissement, appelé par l'orchestrateur. |
| `storage/db_manager.py` | Accès SQLite asynchrone (`aiosqlite`) : cas, recherches, IOC, fuites, watchlists, alertes. |
| `storage/export_manager.py` | Export des données (STIX, rapports). |
| `alerting/dispatcher.py` | Route une alerte vers les canaux configurés (Slack webhook, Telegram) en parallèle. |
| `alerting/telegram.py`, `webhook.py` | Implémentations spécifiques par canal. |
| `ui/search.py` | Interface de recherche : sélection des collecteurs, lancement de la collecte, affichage des résultats. |
| `ui/dashboard.py` | « Centre de Commandement » : statistiques globales, vue d'ensemble des cas et IOC. |
| `ui/cases.py` | Gestion des cas d'investigation (création, IOC associés). |
| `ui/graph_view.py` | Construit un graphe d'entités à partir de la base pour visualiser les corrélations. |
| `ui/watchlists.py` | Gestion des termes surveillés (ajout/liste). |
| `ui/watchlist_monitor.py` | Rejoue les collecteurs sur les watchlists et déclenche les alertes correspondantes. |
| `ui/legal_banner.py` | Bannière de rappel légal affichée à chaque lancement. |
| `ui/themes.py` | Gestion des thèmes CSS de l'interface *(en cours d'implémentation)*. |
| `utils/opsec.py` | Vérifie l'IP perçue et l'absence de fuite DNS avant une session de collecte sensible. |
| `utils/api_debug.py` | Mode debug optionnel : journalise chaque requête/réponse vers les APIs externes (secrets masqués). |
| `utils/rate_limiter.py` / `utils/logger.py` | Utilitaires partagés de limitation de débit et de logging. |

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

Au lancement, `app.py` vérifie la présence de la base SQLite (`osint_searches.db`, configurable via `OSINT_DB_PATH`), affiche la bannière légale, puis expose la navigation (menu latéral) entre les modules :

- **🔍 Recherche OSINT** — lance une collecte multi-sources sur une requête/cible.
- **📊 Centre de Commandement** — tableau de bord et statistiques globales.
- **📁 Gestion des Cas** — création et suivi des dossiers d'investigation.
- **🕸️ Graphe d'Entités** — visualisation des corrélations entre IOC pour le cas actif.
- **📡 Watchlists & Alertes** — gestion des termes/cibles surveillés.
- **🔬 Analyse Manuelle (Watchlists)** — exécution ponctuelle des collecteurs sur une watchlist.
- **⚙️ Configuration** — chemins de config (DB, registre, `.env`), activation du mode debug API (`utils/api_debug.py`) et vérification OPSEC (IP perçue / fuite DNS, `utils/opsec.py`).

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
├── app.py                       # Point d'entrée Streamlit (navigation + routage des modules)
├── init_db.py                   # Initialisation du schéma SQLite (cases, searches, iocs, leaks, watchlists, alerts)
├── collectors_registry.json     # Registre déclaratif des collecteurs (source de vérité du CollectorManager)
├── requirements.txt
├── collectors/
│   ├── base.py                  # Classe abstraite BaseCollector (config, rate limiting)
│   ├── manager.py                # Chargement dynamique du registre + orchestration asynchrone
│   ├── content_scraper.py        # Récupération/scraping du contenu des pages trouvées
│   ├── search_engines/           # Brave, Mojeek, DuckDuckGo, Qwant, SearXNG, dork_collector
│   ├── surface_attack/           # Shodan, Censys, crt.sh, SecurityTrails
│   ├── code_source/               # GitHub, GitHub Advanced, GitLab
│   ├── breach_intel/              # HIBP, LeakIX, DeHashed
│   ├── threat_intel/              # GreyNoise, URLScan, ThreatFox, AlienVault OTX, URLhaus, MalwareBazaar, Pulsedive
│   └── passive_feed/               # Flux RSS/Atom
├── core/
│   ├── models.py                 # Modèles Pydantic partagés (SearchResult, IOC, Case, Leak, Alert…)
│   ├── query_sanitizer.py        # Validation/nettoyage de la requête utilisateur
│   ├── dork_translator.py        # Adaptation de la requête par moteur (ENGINE_CAPABILITIES)
│   ├── dork_templates.py         # Bibliothèque de templates de dorks
│   ├── ioc_extractor.py          # Détection d'IOC et de secrets dans les résultats
│   ├── domain_whitelist.py       # Domaines légitimes exclus de l'extraction d'IOC
│   ├── scoring.py                # Calcul du score de sévérité
│   └── mitre_mapper.py           # Correspondance avec la matrice MITRE ATT&CK
├── enrichment/
│   ├── orchestrator.py           # Orchestration + cache SQLite 7j des enrichissements
│   ├── abuseipdb.py
│   ├── virustotal.py
│   └── whois_dns.py
├── storage/
│   ├── db_manager.py             # Accès SQLite asynchrone (aiosqlite)
│   └── export_manager.py         # Export des données (STIX, rapports)
├── alerting/
│   ├── dispatcher.py             # Routage d'une alerte vers les canaux configurés
│   ├── telegram.py
│   └── webhook.py
├── ui/
│   ├── search.py                 # Interface de recherche / lancement de collecte
│   ├── dashboard.py               # Centre de Commandement (statistiques)
│   ├── cases.py                    # Gestion des cas d'investigation
│   ├── graph_view.py               # Graphe d'entités
│   ├── watchlists.py                # Gestion des watchlists
│   ├── watchlist_monitor.py         # Exécution des collecteurs sur les watchlists + alertes
│   ├── legal_banner.py              # Bannière de rappel légal
│   └── themes.py                     # Thèmes CSS (en cours)
├── utils/
│   ├── logger.py
│   ├── rate_limiter.py
│   ├── opsec.py                   # Vérification IP perçue / fuite DNS
│   └── api_debug.py                # Mode debug des appels API externes
└── tests/
    ├── test_collectors.py
    ├── test_ioc_extractor.py
    └── test_scoring.py
```

## Avertissement légal

Dorker Pro est un outil d'OSINT destiné à des usages légitimes : investigations autorisées, threat intelligence défensive, red/blue teaming encadré, recherche en sécurité. L'utilisateur reste seul responsable du respect des lois applicables et des conditions d'utilisation des sources interrogées (quotas API, ToS, RGPD). Une bannière de rappel légal (`ui/legal_banner.py`) est affichée à chaque lancement de l'application.
