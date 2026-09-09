import streamlit as st
import asyncio
import os
import logging
import aiohttp
from storage.db_manager import DatabaseManager
from collectors.manager import CollectorManager
from core.ioc_extractor import IOCExtractor
from core.models import Leak
from alerting.dispatcher import AlertDispatcher
from collectors.search_engines.dork_collector import DorkSecretCollector

logger = logging.getLogger("VenonaMonitor")

CRITICAL_IOC_TYPES = {
    "AWS_SECRET_KEY", "GITHUB_FINE_GRAINED", "GITHUB_CLASSIC",
    "PRIVATE_KEY", "DATABASE_CONN_STRING",
}

# Collecteurs ciblés pour les fuites et secrets (pour économiser les quotas).
# Doivent correspondre aux "id" déclarés dans collectors_registry.json.
TARGET_COLLECTOR_IDS = ["dehashed", "github_advanced", "duckduckgo"]


def _build_alert_dispatcher() -> AlertDispatcher:
    """Construit un AlertDispatcher à partir des variables d'environnement configurées."""
    return AlertDispatcher({
        "SLACK_WEBHOOK_URL": os.getenv("SLACK_WEBHOOK_URL"),
        "TELEGRAM_BOT_TOKEN": os.getenv("TELEGRAM_BOT_TOKEN"),
        "TELEGRAM_CHAT_ID": os.getenv("TELEGRAM_CHAT_ID"),
    })


async def _scan_target(collector_mgr, extractor, db, dispatcher, session, item) -> int:
    """Scanne une cible de watchlist et retourne le nombre d'alertes déclenchées."""
    all_results = []
    for coll_id in TARGET_COLLECTOR_IDS:
        try:
            results = await collector_mgr.run_single_collector(coll_id, item["term"], session)
            if results:
                all_results.extend(results)
        except Exception as e:
            logger.error(f"Erreur collecteur {coll_id} : {e}")

    # extract_from_results renvoie (liste_iocs, stats) — les stats ne sont
    # pas utiles ici, seule la liste d'IOC nous intéresse.
    iocs, _stats = extractor.extract_from_results(all_results)

    alerts_triggered = 0
    for ioc in iocs:
        is_critical = ioc.type in CRITICAL_IOC_TYPES
        is_match = item["term"].lower() in ioc.value.lower()

        if not (is_critical or is_match):
            continue

        severity = "CRITICAL" if is_critical else "HIGH"

        leak = Leak(
            ioc_value=ioc.value,
            signature_type=ioc.type,
            severity=severity,
            snippet=ioc.value[:100],
            source_url=ioc.source_url or "",
        )

        leak_category = "UNKNOWN"
        if ioc.source_url and "://" in ioc.source_url:
            try:
                leak_category = ioc.source_url.split("://", 1)[1].split("/", 1)[0]
            except IndexError:
                pass

        leak_id = await db.save_leak(
            case_id=None,
            leak=leak,
            leak_category=leak_category,
            raw_context=ioc.value[:500],
            is_secret_leak=is_critical,
        )

        alert_msg = (
            f"**Type:** {ioc.type}\n"
            f"**Valeur:** `{ioc.value[:30]}...`\n"
            f"**Source:** {ioc.source_url or 'N/A'}\n"
            f"**Cible:** {item['term']}"
        )
        try:
            await dispatcher.send_alert(
                alert_type="LEAK",
                title=f"🚨 ALERTE Fuite : {item['term']}",
                details=alert_msg,
                severity=severity,
            )
        except Exception as e:
            logger.error(f"Erreur envoi alerte (Slack/Telegram) : {e}")

        await db.create_alert(watchlist_id=item["id"], leak_id=leak_id, status="NEW")
        alerts_triggered += 1

    return alerts_triggered


def run_watchlist_scan():
    st.info("⏳ Lancement de l'analyse des watchlists actives... Cela peut prendre quelques instants.")

    db = DatabaseManager()
    collector_mgr = CollectorManager()
    extractor = IOCExtractor()
    dispatcher = _build_alert_dispatcher()

    import sqlite3
    conn = sqlite3.connect(db.db_path)
    conn.row_factory = sqlite3.Row
    watchlists = conn.execute("SELECT id, term, type FROM WATCHLISTS WHERE is_active = 1").fetchall()
    conn.close()

    if not watchlists:
        st.warning("Aucune watchlist active trouvée. Ajoutez-en une dans l'onglet 'Watchlists & Alertes'.")
        return

    progress_bar = st.progress(0)
    status_text = st.empty()
    counters = {"scanned": 0, "alerts": 0}

    async def _run_all():
        async with aiohttp.ClientSession() as session:
            for idx, item in enumerate(watchlists):
                status_text.text(f"🔍 Analyse de la cible : **{item['term']}** ({item['type']})")
                progress_bar.progress(idx / len(watchlists))
                counters["alerts"] += await _scan_target(collector_mgr, extractor, db, dispatcher, session, item)
                counters["scanned"] += 1

    # Streamlit tourne en synchrone : on pilote toute la boucle de scan avec
    # une seule boucle asyncio (plutôt qu'une boucle jetée par appel, comme
    # dans la version précédente, qui empêchait en plus tout `await` correct
    # côté DatabaseManager/AlertDispatcher).
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run_all())
    finally:
        loop.close()

    progress_bar.progress(1.0)
    status_text.text("✅ Analyse terminée !")

    if counters["alerts"] > 0:
        st.success(
            f"🎯 **{counters['alerts']} alerte(s) critique(s) détectée(s) et envoyées !** "
            "Vérifiez vos canaux Slack/Telegram et l'historique des alertes."
        )
    else:
        st.success("✅ Analyse terminée. Aucune nouvelle fuite ou secret critique détecté pour vos watchlists.")


def run_dork_secret_scan(domain: str):
    """Lance un scan de dorks ciblés (secrets exposés, buckets S3 ouverts...) sur un domaine."""
    st.info(f"🕵️ Lancement du scan de dorks & secrets exposés pour **{domain}**...")

    collector_mgr = CollectorManager()
    dork_collector = DorkSecretCollector(case_id="WATCHLIST_MONITOR")

    async def _run():
        async with aiohttp.ClientSession() as session:
            return await dork_collector.fetch(domain, collector_manager=collector_mgr, session=session)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        findings = loop.run_until_complete(_run())
    finally:
        loop.close()

    if not findings:
        st.success("✅ Aucune ressource exposée détectée via les dorks pour ce domaine.")
        return

    st.warning(f"⚠️ {len(findings)} ressource(s) exposée(s) détectée(s).")
    for finding in findings:
        with st.expander(f"{finding['url']} ({finding['category']})"):
            st.write(f"**Statut HTTP :** {finding['status_code']}")
            if finding["is_s3_bucket"]:
                st.error(
                    f"🪣 Bucket S3 ouvert — {finding['s3_objects_total']} objets, "
                    f"{len(finding['s3_sensitive_files'])} fichier(s) sensible(s)."
                )
                for f_info in finding["s3_sensitive_files"][:10]:
                    st.code(f_info["direct_url"])
            if finding["secrets_found"]:
                st.error(f"🔑 Secrets détectés : {finding['secrets_found']}")
            if finding.get("mitre_attack"):
                for m in finding["mitre_attack"]:
                    st.caption(f"MITRE ATT&CK : {m['technique_id']} — {m['technique_name']} ({m['tactic']})")


def render_watchlist_monitor():
    st.header("📡 Surveillance Continue des Watchlists (Mode Manuel)")
    st.markdown("""
    Ce module permet de lancer une analyse **ciblée** sur vos watchlists actives en utilisant des collecteurs spécialisés
    dans les fuites de données (Data Breaches) et les secrets de code (GitHub, AWS, etc.).

    > ⚠️ **Note OPSEC** : Respecte les délais de rate-limiting configurés dans `collectors_registry.json` (ex: 10+ secondes entre les requêtes).
    """)

    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("🚀 Lancer l'analyse des watchlists", type="primary"):
            run_watchlist_scan()

    with col2:
        st.info("Dernière analyse : *Jamais effectuée manuellement*")  # À améliorer avec un stockage en session

    st.divider()
    st.subheader("🕵️ Scan ciblé de Dorks & Secrets exposés")
    st.caption(
        "Recherche de buckets S3 ouverts, fichiers .env, clés API et identifiants exposés "
        "pour un domaine donné (indépendant des watchlists enregistrées)."
    )
    dork_domain = st.text_input("Domaine cible", placeholder="exemple.com", key="dork_domain_input")
    if st.button("🔎 Lancer le scan de dorks", disabled=not dork_domain):
        run_dork_secret_scan(dork_domain.strip())

    st.divider()
    st.subheader("📜 Historique récent des alertes générées")
    st.write("_Les alertes générées par ce scan apparaîtront ici et dans vos canaux de notification._")
