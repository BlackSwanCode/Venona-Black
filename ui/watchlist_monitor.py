import streamlit as st
import asyncio
import logging
from storage.db_manager import DatabaseManager
from collectors.manager import CollectorManager
from core.ioc_extractor import IOCExtractor
from core.scoring import calculate_osint_score
from alerting.dispatcher import AlertDispatcher

logger = logging.getLogger("VenonaMonitor")

def run_watchlist_scan():
    st.info("⏳ Lancement de l'analyse des watchlists actives... Cela peut prendre quelques instants.")
    
    db = DatabaseManager()
    collector_mgr = CollectorManager()
    extractor = IOCExtractor()
    dispatcher = AlertDispatcher()
    
    # Récupérer les watchlists actives (On suppose une méthode get_active_watchlists ou on la simule)
    # Si elle n'existe pas, on utilise un fallback SQL direct pour l'exemple
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
    
    total_scanned = 0
    alerts_triggered = 0

    # Collecteurs ciblés pour les fuites et secrets (pour économiser les quotas)
    target_collectors = ["dehashed", "github_advanced", "duckduckgo_html"]

    for idx, item in enumerate(watchlists):
        status_text.text(f"🔍 Analyse de la cible : **{item['term']}** ({item['type']})")
        progress_bar.progress((idx / len(watchlists)))
        
        all_results = []
        for coll_id in target_collectors:
            # Exécution synchrone du collecteur via asyncio.run (nécessaire dans Streamlit)
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(collector_mgr.run_single_collector(coll_id, item['term']))
                loop.close()
                if results:
                    all_results.extend(results)
            except Exception as e:
                logger.error(f"Erreur collecteur {coll_id} : {e}")

        # Extraction des IOC et Secrets
        iocs = extractor.extract_from_results(all_results)
        
        for ioc in iocs:
            # Déclencheur d'alerte : on se concentre sur les secrets et les emails/domaines de la watchlist
            is_critical = ioc.type in ["AWS_SECRET_KEY", "GITHUB_FINE_GRAINED", "GITHUB_CLASSIC", "PRIVATE_KEY", "DATABASE_CONN_STRING"]
            is_match = item['term'].lower() in ioc.value.lower()
            
            if is_critical or is_match:
                severity = "CRITICAL" if is_critical else "HIGH"
                
                # Sauvegarde de la fuite avec les nouvelles métadonnées
                leak_category = ioc.source_url.split('.')[-1] if ioc.source_url else "UNKNOWN"
                raw_ctx = ioc.metadata.get("raw_context", "")[:500] # Limite à 500 chars pour la DB
                
                leak_id = db.save_leak(
                    ioc_id=ioc.value, # Simplifié pour l'exemple, idéalement hasher
                    case_id=None,
                    signature_type=ioc.type,
                    snippet=ioc.value[:100] + "...",
                    source_url=ioc.source_url,
                    severity=severity,
                    leak_category=leak_category,
                    raw_context=raw_ctx,
                    is_secret_leak=1 if is_critical else 0
                )
                
                # Déclenchement de l'alerte (Slack/Telegram)
                alert_msg = f"**Type:** {ioc.type}\n**Valeur:** `{ioc.value[:30]}...`\n**Source:** {ioc.source_url}\n**Cible:** {item['term']}"
                dispatcher.send_alert(
                    title=f"🚨 ALERTE Fuite : {item['term']}",
                    message=alert_msg,
                    severity=severity.lower()
                )
                
                # Enregistrement de l'alerte en base
                db.create_alert(watchlist_id=item['id'], leak_id=leak_id, status="NEW")
                alerts_triggered += 1
                
        total_scanned += 1

    progress_bar.progress(1.0)
    status_text.text("✅ Analyse terminée !")
    
    if alerts_triggered > 0:
        st.success(f"🎯 **{alerts_triggered} alerte(s) critique(s) détectée(s) et envoyées !** Vérifiez vos canaux Slack/Telegram et l'historique des alertes.")
    else:
        st.success("✅ Analyse terminée. Aucune nouvelle fuite ou secret critique détecté pour vos watchlists.")

def render_watchlist_monitor():
    st.header("📡 Surveillance Continue des Watchlists (Mode Manuel)")
    st.markdown("""
    Ce module permet de lancer une analyse **ciblée** sur vos watchlists actives en utilisant des collecteurs spécialisés 
    dans les fuites de données (Data Breaches) et les secrets de code (GitHub, AWS, etc.).
    
    > ⚠️ **Note OPSEC** : Respecte les délais de rate-limiting configurés dans `collectors_registry.json` (ex: 10+ secondes entre les requêtes).
    """)
    
    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("🚀 Lancer l'analyse maintenant", type="primary"):
            run_watchlist_scan()
            
    with col2:
        st.info("Dernière analyse : *Jamais effectuée manuellement*") # À améliorer avec un stockage en session
        
    st.divider()
    st.subheader("📜 Historique récent des alertes générées")
    st.write("_Les alertes générées par ce scan apparaîtront ici et dans vos canaux de notification._")
    # Ici, vous pourriez appeler db.get_recent_alerts() pour les afficher dans un dataframe
