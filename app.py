import streamlit as st
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("OSINT_DB_PATH", "osint_searches.db")

from ui.legal_banner import render_legal_banner
from ui.watchlist_monitor import render_watchlist_monitor
from ui.search import render_search_interface
from ui.cases import render_case_management
from ui.dashboard import render_dashboard
from ui.graph_view import render_entity_graph
from ui.watchlists import render_watchlists
from storage.export_manager import ExportManager

st.set_page_config(page_title="Dorker Pro v6.0", page_icon="🕵️‍♂️", layout="wide")

def check_db():
    import sqlite3
    if not os.path.exists(DB_PATH):
        st.error(f"DB introuvable à {DB_PATH}. Lancez 'python init_db.py'.")
        st.stop()

def main():
    render_legal_banner()
    st.title("🕵️‍♂️ Dorker Pro — OSINT Command Center v6.0")
    
    with st.sidebar:
        st.header("🧭 Navigation")
        app_mode = st.selectbox("Module", [
            "🔍 Recherche OSINT",
            "📊 Centre de Commandement",
            "📁 Gestion des Cas",
            "🕸️ Graphe d'Entités",
            "📡 Watchlists & Alertes",
            "🔬 Analyse Manuelle (Watchlists)",
            "⚙️ Configuration"
        ])
        
        st.divider()
        st.caption(f"📦 DB: {os.path.basename(DB_PATH)}")
        st.caption(f"🔑 Proxies: {'✅' if os.getenv('HTTP_PROXY') else '❌'}")

    # Routage
    if app_mode == "🔍 Recherche OSINT":
        render_search_interface()
    elif app_mode == "📊 Centre de Commandement":
        render_dashboard()
    elif app_mode == "📁 Gestion des Cas":
        render_case_management()
    elif app_mode == "🕸️ Graphe d'Entités":
        case_id = st.session_state.get('active_case_id')
        render_entity_graph(case_id)
    elif app_mode == "📡 Watchlists & Alertes":
        render_watchlists()
    elif app_mode == "🔬 Analyse Manuelle (Watchlists)":
        render_watchlist_monitor()
    elif app_mode == "⚙️ Configuration":
        st.header("⚙️ Configuration")
        st.write("### Fichiers de configuration")
        st.code(f"DB: {DB_PATH}", language="bash")
        st.code(f"Registry: collectors_registry.json", language="bash")
        st.code(f"Env: .env", language="bash")
        
        st.write("### 🐞 Mode Debug API")
        st.caption(
            "Journalise chaque requête/réponse vers les APIs externes (Censys, Shodan, ...) : "
            "statut HTTP, paramètres/en-têtes (secrets masqués) et extrait du corps de réponse "
            "en cas d'erreur. Utile pour diagnostiquer un 401/403/429."
        )
        from utils.api_debug import is_debug_enabled, set_debug_enabled
        debug_enabled = st.checkbox("Activer le mode debug API", value=is_debug_enabled())
        set_debug_enabled(debug_enabled)
        if debug_enabled:
            st.info("Logs visibles dans le terminal (stderr) et dans `logs/api_debug.log`.")

        st.write("### Vérification OPSEC")
        if st.button("🔍 Vérifier mon anonymat"):
            from utils.opsec import check_ip_leak
            result = asyncio.run(check_ip_leak())
            if result["status"] == "success":
                st.info(f"**IP perçue** : {result['perceived_ip']}")
                st.info(f"**Proxy actif** : {'✅ Oui' if result['proxy_active'] else '❌ Non'}")
                st.warning(result["warning"])
            else:
                st.error(f"Erreur : {result['message']}")

if __name__ == "__main__":
    check_db()
    main()
