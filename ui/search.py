import streamlit as st
import asyncio
import aiohttp
import json
import os
from datetime import datetime

from collectors.manager import CollectorManager
from collectors.content_scraper import ContentScraper
from core.ioc_extractor import IOCExtractor
from core.scoring import calculate_osint_score
from core.models import Leak
from storage.db_manager import DatabaseManager
from enrichment.orchestrator import EnrichmentOrchestrator
from core.dork_translator import DorkTranslator
from core.query_sanitizer import QuerySanitizer


async def run_osint_pipeline(
    query: str, 
    selected_collectors: list, 
    case_id: str, 
    enrich: bool = False,
    translated_queries: dict = None,
    scrape_content: bool = False,
    max_pages_to_scrape: int = 10
):
    """Pipeline complet avec scraping optionnel du contenu des pages."""
    manager = CollectorManager()
    db = DatabaseManager()

    # 1. Collecte des résultats de recherche
    async with aiohttp.ClientSession() as session:
        results = await manager.run_all(
            query, 
            session, 
            selected_ids=selected_collectors,
            use_translated_queries=translated_queries
        )

        # 2. Scraping optionnel du contenu des pages
        # CORRECTION: on réutilise la session existante au lieu de passer None
        scraped_contents = []
        if scrape_content and results:
            scraper = ContentScraper(max_concurrent=5)
            urls_to_scrape = [r.url for r in results if r.url][:max_pages_to_scrape]

            scraped_contents = await scraper.scrape_multiple(
                session=session, 
                urls=urls_to_scrape,
                max_pages=max_pages_to_scrape
            )

    # 3. Extraction IOC combinée (snippets + contenus)
    iocs, extraction_stats = IOCExtractor.extract_from_results(results, scraped_contents)

    # 4. Enrichissement (optionnel)
    if enrich and iocs:
        orchestrator = EnrichmentOrchestrator()
        api_keys = {
            "VIRUSTOTAL": os.getenv("VIRUSTOTAL_API_KEY"),
            "ABUSEIPDB": os.getenv("ABUSEIPDB_API_KEY")
        }

        for ioc in iocs:
            enrichment_result = await orchestrator.enrich(ioc.value, ioc.type, api_keys)
            ioc.enrichment = enrichment_result.get("data", {})

    # 5. Scoring v2
    score = calculate_osint_score(iocs, source_reliability=1.2)

    # 6. Stockage
    raw_json = json.dumps([r.model_dump() for r in results], default=str)
    search_id = await db.log_search(case_id, query, ",".join(selected_collectors), raw_json)

    for ioc in iocs:
        await db.save_ioc(ioc, ioc.enrichment)

        # CORRECTION: Créer un leak pour lier l'IOC au cas actif
        if case_id and case_id != "demo-case-id":
            leak = Leak(
                ioc_value=ioc.value,
                signature_type="AUTO_EXTRACTED",
                snippet=f"Extrait automatiquement depuis la recherche {search_id[:8]}",
                source_url="",
                severity="MEDIUM" if ioc.confidence > 0.8 else "LOW"
            )
            await db.save_leak(case_id, leak)

    return results, iocs, score, search_id, extraction_stats, scraped_contents


def render_search_interface():
    st.header("🔍 Recherche OSINT Multi-Sources")

    col1, col2 = st.columns([3, 1])
    with col1:
        query = st.text_input(
            "Requête (Google Dorks supportés)", 
            placeholder='ex: "Disttrack" wiper "Middle East"',
        )
    with col2:
        manager = CollectorManager()
        available_collectors = list(manager.collectors.keys())
        selected_collectors = st.multiselect(
            "Moteurs actifs", 
            options=available_collectors, 
            default=available_collectors[:3] if len(available_collectors) >= 3 else available_collectors
        )

    # Recommandation pour requêtes complexes
    if query and QuerySanitizer.is_complex_query(query):
        st.warning(
            "⚠️ **Requête complexe** détectée.\n\n"
            "**Recommandation** : Privilégiez SearXNG local (Docker) pour les opérateurs avancés."
        )

    # Aperçu des traductions
    if query and selected_collectors:
        with st.expander("🔧 Aperçu des requêtes traduites par moteur", expanded=False):
            translations = DorkTranslator.translate_for_multiple_engines(query, selected_collectors)
            for engine_id, translation in translations.items():
                st.markdown(f"**{engine_id}**")
                col_a, col_b = st.columns(2)
                with col_a:
                    st.code(translation.original, language="text")
                with col_b:
                    st.code(translation.translated, language="text")
                if translation.warnings:
                    for w in translation.warnings:
                        st.warning(w)
                st.divider()

    # Options avancées
    with st.expander("⚙️ Options avancées", expanded=True):
        col_a, col_b = st.columns(2)

        with col_a:
            enrich = st.checkbox(
                "🔬 Enrichissement automatique (VT, AbuseIPDB)", 
                value=False,
                help="Consomme des quotas API"
            )

        with col_b:
            scrape_content = st.checkbox(
                "📄 Scanner le contenu des pages", 
                value=True,
                help="Récupère le texte des pages pour extraire les IOC mentionnés (hashes, domaines C2, etc.)"
            )

        if scrape_content:
            max_pages = st.slider(
                "Nombre max de pages à scanner",
                min_value=1,
                max_value=20,
                value=10,
                help="Plus il y a de pages, plus l'extraction est complète mais plus longue"
            )
        else:
            max_pages = 0

    # Affichage du cas actif
    case_id = st.session_state.get('active_case_id', 'demo-case-id')
    case_name = st.session_state.get('active_case_name', 'Démo')

    if case_id != 'demo-case-id':
        st.info(f"📁 Cas actif : **{case_name}** (`{case_id[:8]}...`)")
    else:
        st.warning("⚠️ Aucun cas actif. Les IOCs seront stockés globalement mais non rattachés à un cas.")

    # Bouton de lancement
    if st.button("🚀 Lancer l'Investigation", type="primary", use_container_width=True):
        if not query:
            st.warning("Entrez une requête.")
        elif not selected_collectors:
            st.warning("Sélectionnez au moins un collecteur.")
        else:
            translations = DorkTranslator.translate_for_multiple_engines(query, selected_collectors)
            translated_queries = {
                engine_id: t.translated for engine_id, t in translations.items()
            }

            with st.spinner("Investigation en cours..."):
                try:
                    results, iocs, score, search_id, extraction_stats, scraped_contents = asyncio.run(
                        run_osint_pipeline(
                            query, selected_collectors, case_id, enrich,
                            translated_queries, scrape_content, max_pages
                        )
                    )

                    st.success(f"✅ Terminé. Score: **{score}** | IOC uniques: {len(iocs)}")

                    # Statistiques d'extraction
                    with st.expander("📊 Statistiques d'extraction", expanded=True):
                        col_a, col_b, col_c, col_d = st.columns(4)
                        col_a.metric("Depuis snippets", extraction_stats.get('from_snippets', 0))
                        col_b.metric("Depuis contenu réel", extraction_stats.get('from_scraped_content', 0))
                        col_c.metric("🚫 Domaines légitimes filtrés", extraction_stats.get('filtered_legitimate', 0))
                        col_d.metric("🚫 Faux positifs filtrés", extraction_stats.get('filtered_false_positive', 0))

                    # Onglets de résultats
                    tab1, tab2, tab3, tab4 = st.tabs([
                        "📄 Résultats bruts", 
                        "🎯 IOC extraits", 
                        "📊 Analyse", 
                        "🔧 Détails techniques"
                    ])

                    with tab1:
                        if not results:
                            st.info("Aucun résultat.")
                        for r in results[:20]:
                            st.markdown(f"**[{r.source}] {r.title}**")
                            st.caption(r.url)
                            st.write(r.snippet[:300] + "..." if len(r.snippet) > 300 else r.snippet)
                            st.divider()

                    with tab2:
                        if iocs:
                            iocs_by_type = {}
                            for ioc in iocs:
                                iocs_by_type.setdefault(ioc.type, []).append(ioc)

                            for ioc_type, type_iocs in iocs_by_type.items():
                                with st.expander(f"🎯 {ioc_type} ({len(type_iocs)})", expanded=True):
                                    for ioc in type_iocs[:50]:
                                        col_a, col_b = st.columns([4, 1])
                                        with col_a:
                                            st.code(ioc.value, language="text")
                                        with col_b:
                                            st.caption(f"Confiance: {ioc.confidence*100:.0f}%")
                        else:
                            st.info("Aucun IOC extrait.")
                            st.caption("💡 Activez l'option 'Scanner le contenu des pages' pour extraire les IOC mentionnés dans les articles.")

                    with tab3:
                        st.metric("Score OSINT", score)
                        st.write(f"**Résumé** : {len(results)} résultats, {len(iocs)} IOC uniques.")

                        # Détails par type
                        if iocs:
                            type_counts = {}
                            for ioc in iocs:
                                type_counts[ioc.type] = type_counts.get(ioc.type, 0) + 1
                            st.bar_chart(type_counts)

                    with tab4:
                        st.markdown("#### Requêtes envoyées")
                        for engine_id, translated in translated_queries.items():
                            st.markdown(f"**{engine_id}**")
                            st.code(translated, language="text")

                        if scraped_contents:
                            st.markdown(f"#### Pages scrapées ({len(scraped_contents)})")
                            for content in scraped_contents[:10]:
                                st.markdown(f"- **{content.get('title', 'Sans titre')}** : {content.get('url', '')}")

                except Exception as e:
                    st.error(f"Erreur : {e}")
                    import traceback
                    st.code(traceback.format_exc())
