import streamlit as st
import asyncio
from storage.db_manager import DatabaseManager

def render_dashboard():
    st.header("📊 Centre de Commandement")
    
    # Récupération des statistiques
    try:
        db = DatabaseManager()
        stats = asyncio.run(db.get_dashboard_stats())
    except Exception as e:
        st.error(f"Erreur lors de la récupération des statistiques : {e}")
        stats = {'open_cases': 0, 'total_iocs': 0, 'critical_leaks': 0, 'new_alerts': 0}
    
    # Métriques principales
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📁 Cas Ouverts", stats['open_cases'])
    col2.metric("🎯 IOC Total", stats['total_iocs'])
    col3.metric("🚨 Fuites Critiques", stats['critical_leaks'])
    col4.metric("🔔 Alertes Nouvelles", stats['new_alerts'])
    
    st.divider()
    
    # Activités récentes
    st.subheader("📈 Activités Récentes")
    
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.markdown("#### Dernières Investigations")
        st.info("Historique des recherches récentes (à implémenter avec la table searches)")
    
    with col_right:
        st.markdown("#### IOC les Plus Fréquents")
        st.info("Top 10 des IOC les plus rencontrés (à implémenter)")
    
    st.divider()
    
    # Carte du monde (placeholder)
    st.subheader("🌍 Répartition Géographique des IPs")
    st.info("Carte interactive des IPs géolocalisées (nécessite l'enrichissement avec géolocalisation)")
