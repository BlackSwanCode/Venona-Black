import streamlit as st
import asyncio
import json
from datetime import datetime
from storage.db_manager import DatabaseManager

async def get_watchlist_items():
    """Récupère les éléments de la watchlist depuis la DB."""
    db = DatabaseManager()
    return await db.get_watchlist_items()

async def add_watchlist_item(term: str, item_type: str):
    """Ajoute un élément à la watchlist."""
    db = DatabaseManager()
    return await db.add_watchlist_item(term, item_type)

async def get_alerts(limit: int = 50):
    """Récupère les alertes récentes."""
    db = DatabaseManager()
    return await db.get_alerts(limit)

async def delete_watchlist_item(item_id: str):
    """Supprime un élément de la watchlist."""
    import aiosqlite
    import os
    db_path = os.getenv("OSINT_DB_PATH", "osint_searches.db")
    async with aiosqlite.connect(db_path) as db:
        await db.execute("DELETE FROM watchlists WHERE id = ?", (item_id,))
        await db.commit()

def render_watchlists():
    st.header("📡 Watchlists & Alertes")
    
    # Onglets
    tab1, tab2, tab3 = st.tabs(["➕ Ajouter une cible", "📋 Watchlist active", "🔔 Historique des alertes"])
    
    with tab1:
        st.subheader("Ajouter une cible à surveiller")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            term = st.text_input(
                "Terme à surveiller",
                placeholder="ex: target.com, admin@target.com, malware-name"
            )
        
        with col2:
            item_type = st.selectbox(
                "Type",
                ["DOMAIN", "EMAIL", "KEYWORD", "IPV4", "URL"],
                index=0
            )
        
        st.info("💡 **Exemples d'usage :**")
        st.markdown("""
        - **DOMAIN** : Surveiller l'apparition de domaines suspects liés à votre organisation
        - **EMAIL** : Vérifier si des adresses email professionnelles apparaissent dans des fuites
        - **KEYWORD** : Détecter des mentions de mots-clés sensibles (ex: nom de malware, campagne)
        - **IPV4** : Surveiller des adresses IP suspectes
        - **URL** : Suivre des URLs spécifiques
        """)
        
        if st.button("➕ Ajouter à la watchlist", type="primary"):
            if not term:
                st.warning("Veuillez entrer un terme à surveiller.")
            else:
                try:
                    item_id = asyncio.run(add_watchlist_item(term, item_type))
                    st.success(f"✅ '{term}' ({item_type}) ajouté à la watchlist !")
                    st.balloons()
                except Exception as e:
                    if "UNIQUE constraint failed" in str(e):
                        st.warning(f"'{term}' est déjà dans la watchlist.")
                    else:
                        st.error(f"Erreur : {e}")
    
    with tab2:
        st.subheader("Éléments surveillés")
        
        try:
            items = asyncio.run(get_watchlist_items())
            
            if not items:
                st.info("Aucun élément dans la watchlist. Ajoutez-en un dans l'onglet 'Ajouter une cible'.")
            else:
                st.write(f"**{len(items)} élément(s) surveillé(s)**")
                
                for item in items:
                    col1, col2, col3 = st.columns([3, 1, 1])
                    
                    with col1:
                        st.markdown(f"**{item['term']}**")
                        st.caption(f"Type: {item['type']} | ID: {item['id'][:8]}...")
                    
                    with col2:
                        status = "✅ Actif" if item['is_active'] else "❌ Inactif"
                        st.caption(status)
                    
                    with col3:
                        if st.button("🗑️", key=f"delete_{item['id']}", help="Supprimer"):
                            asyncio.run(delete_watchlist_item(item['id']))
                            st.rerun()
                    
                    st.divider()
                
                # Statistiques
                st.divider()
                st.subheader("📊 Statistiques")
                
                type_counts = {}
                for item in items:
                    item_type = item['type']
                    type_counts[item_type] = type_counts.get(item_type, 0) + 1
                
                cols = st.columns(len(type_counts))
                for idx, (item_type, count) in enumerate(type_counts.items()):
                    cols[idx].metric(item_type, count)
        
        except Exception as e:
            st.error(f"Erreur lors du chargement de la watchlist : {e}")
            import traceback
            st.code(traceback.format_exc())
    
    with tab3:
        st.subheader("Alertes récentes")
        
        try:
            alerts = asyncio.run(get_alerts(limit=50))
            
            if not alerts:
                st.info("Aucune alerte pour le moment. Les alertes seront générées automatiquement lors de la surveillance continue.")
            else:
                st.write(f"**{len(alerts)} alerte(s) récente(s)**")
                
                for alert in alerts:
                    # Couleur selon le statut
                    status_colors = {
                        "NEW": "🔴",
                        "VIEWED": "🟡",
                        "RESOLVED": "🟢",
                        "FALSE_POSITIVE": "⚪"
                    }
                    
                    emoji = status_colors.get(alert.get('status', 'NEW'), "⚪")
                    
                    with st.expander(f"{emoji} {alert.get('watchlist_term', 'N/A')} - {alert.get('status', 'N/A')}"):
                        st.write(f"**ID** : {alert.get('id', 'N/A')}")
                        st.write(f"**Statut** : {alert.get('status', 'N/A')}")
                        st.write(f"**Déclenchée le** : {alert.get('triggered_at', 'N/A')}")
                        
                        # Actions
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            if st.button("✅ Marquer comme vue", key=f"view_{alert['id']}"):
                                st.info("Fonction à implémenter")
                        with col2:
                            if st.button("🔧 Résoudre", key=f"resolve_{alert['id']}"):
                                st.info("Fonction à implémenter")
                        with col3:
                            if st.button("❌ Faux positif", key=f"fp_{alert['id']}"):
                                st.info("Fonction à implémenter")
                
                # Filtres
                st.divider()
                st.subheader("🔍 Filtres")
                
                col1, col2 = st.columns(2)
                with col1:
                    status_filter = st.multiselect(
                        "Filtrer par statut",
                        ["NEW", "VIEWED", "RESOLVED", "FALSE_POSITIVE"],
                        default=["NEW", "VIEWED"]
                    )
                with col2:
                    st.caption(f"Total : {len(alerts)} alertes")
        
        except Exception as e:
            st.error(f"Erreur lors du chargement des alertes : {e}")
            import traceback
            st.code(traceback.format_exc())
