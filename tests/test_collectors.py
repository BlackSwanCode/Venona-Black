"""
Tests unitaires pour les collecteurs (collectors/).

Objectifs couverts (annoncés dans le README, absents jusqu'ici) :
  1. collect() retourne bien une liste de SearchResult ;
  2. comportement en l'absence de clé API (retour [], pas d'exception) ;
  3. gestion des réponses HTTP en erreur (4xx/5xx) et des erreurs réseau.

On simule aiohttp.ClientSession avec de petits doubles de test plutôt que
d'ajouter une dépendance supplémentaire (aioresponses) au projet.
"""

import aiohttp
import pytest

from collectors.search_engines.brave import BraveSearchCollector
from collectors.search_engines.mojeek import MojeekCollector
from collectors.manager import CollectorManager
from core.models import SearchResult


# ---------------------------------------------------------------------------
# Doubles de test pour aiohttp.ClientSession
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status=200, json_data=None, text_data="", content_type="application/json"):
        self.status = status
        self._json = json_data if json_data is not None else {}
        self._text = text_data
        self.headers = {"Content-Type": content_type}

    async def json(self):
        return self._json

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeSession:
    """Retourne toujours la même réponse (ou lève l'exception fournie) quel
    que soit l'appel .get()/.post()."""

    def __init__(self, response=None, raise_exc=None):
        self._response = response
        self._raise_exc = raise_exc

    def get(self, *args, **kwargs):
        if self._raise_exc:
            raise self._raise_exc
        return self._response

    def post(self, *args, **kwargs):
        return self.get(*args, **kwargs)


# ---------------------------------------------------------------------------
# Absence de clé API
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_brave_without_api_key_returns_empty_list(monkeypatch):
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    collector = BraveSearchCollector({"name": "Brave"})
    results = await collector.collect("site:example.com password", session=FakeSession())
    assert results == []


@pytest.mark.asyncio
async def test_mojeek_without_api_key_returns_empty_list(monkeypatch):
    monkeypatch.delenv("MOJEEK_API_KEY", raising=False)
    collector = MojeekCollector({"name": "Mojeek"})
    results = await collector.collect("test query", session=FakeSession())
    assert results == []


# ---------------------------------------------------------------------------
# Réponses HTTP en erreur / erreurs réseau : ne doit jamais lever d'exception
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_brave_handles_401_gracefully(monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "fake-key")
    collector = BraveSearchCollector({"name": "Brave"})
    session = FakeSession(response=FakeResponse(status=401))
    results = await collector.collect("query", session=session)
    assert results == []


@pytest.mark.asyncio
async def test_brave_handles_429_rate_limit_gracefully(monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "fake-key")
    collector = BraveSearchCollector({"name": "Brave"})
    session = FakeSession(response=FakeResponse(status=429))
    results = await collector.collect("query", session=session)
    assert results == []


@pytest.mark.asyncio
async def test_brave_handles_network_error_gracefully(monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "fake-key")
    collector = BraveSearchCollector({"name": "Brave"})
    session = FakeSession(raise_exc=aiohttp.ClientConnectionError("boom"))
    results = await collector.collect("query", session=session)
    assert results == []


# ---------------------------------------------------------------------------
# Cas nominal : collect() retourne bien une List[SearchResult]
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_brave_parses_successful_response_into_search_results(monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "fake-key")
    collector = BraveSearchCollector({"name": "Brave"})
    payload = {
        "web": {
            "results": [
                {"title": "Résultat 1", "url": "https://example.com/1", "description": "snippet 1"},
            ]
        }
    }
    session = FakeSession(response=FakeResponse(status=200, json_data=payload))
    results = await collector.collect("query", session=session)

    assert isinstance(results, list)
    assert len(results) == 1
    assert isinstance(results[0], SearchResult)
    assert results[0].source == "Brave Search"
    assert results[0].url == "https://example.com/1"


# ---------------------------------------------------------------------------
# CollectorManager : chargement du registre
# ---------------------------------------------------------------------------

def test_manager_skips_collectors_with_missing_api_key(monkeypatch, tmp_path):
    """Un collecteur requires_api_key=true dont la variable d'env n'est pas
    définie ne doit pas être chargé, et ne doit pas faire planter le
    chargement des autres collecteurs (rss, qui ne requiert pas de clé)."""
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    manager = CollectorManager(registry_path="collectors_registry.json")
    assert "brave" not in manager.collectors
    assert "rss" in manager.collectors
