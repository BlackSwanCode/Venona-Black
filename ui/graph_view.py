import streamlit as st
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import aiosqlite
import json
import os

async def build_entity_graph(case_id: str = None):
    """Construit le graphe d'entités à partir de la DB."""
    db_path = os.getenv("OSINT_DB_PATH", "osint_searches.db")
    
    G = nx.Graph()
    
    async with aiosqlite.connect(db_path) as db:
        # Récupérer les IOC et leurs relations
        if case_id:
            cursor = await db.execute("""
                SELECT DISTINCT i.value, i.type 
                FROM iocs i
                JOIN leaks l ON i.id = l.ioc_id
                WHERE l.case_id = ?
            """, (case_id,))
        else:
            cursor = await db.execute("SELECT value, type FROM iocs LIMIT 100")
        
        rows = await cursor.fetchall()
        
        # Ajouter les nœuds
        for value, ioc_type in rows:
            G.add_node(value, type=ioc_type, label=value[:30])
            
            # Créer des liens basés sur les domaines communs
            if ioc_type == "EMAIL":
                domain = value.split("@")[-1]
                if domain in [n for n in G.nodes()]:
                    G.add_edge(value, domain, relation="belongs_to")
    
    return G

def render_entity_graph(case_id: str = None):
    st.header("🕸️ Graphe de Corrélation d'Entités")
    
    if st.button("🔄 Générer le graphe"):
        with st.spinner("Construction du graphe..."):
            try:
                import asyncio
                G = asyncio.run(build_entity_graph(case_id))
                
                if len(G.nodes()) == 0:
                    st.warning("Aucune entité à afficher. Lancez d'abord une investigation.")
                    return
                
                # Configuration PyVis - CORRECTION ICI
                net = Network(height="600px", width="100%", bgcolor="#1a1a1a", font_color="white", directed=True)
                net.from_nx(G)
                
                # Personnalisation visuelle
                color_map = {
                    "EMAIL": "#00ff00",
                    "IPV4": "#00d0ff",
                    "DOMAIN": "#ff6600",
                    "URL": "#ff00ff",
                    "HASH_MD5": "#ffff00",
                    "HASH_SHA256": "#ffff00"
                }
                
                for node in net.nodes:
                    node_type = node.get("type", "UNKNOWN")
                    node["color"] = color_map.get(node_type, "#888888")
                    node["shape"] = "dot"
                    node["size"] = 20
                    node["title"] = f"{node['label']}\nType: {node_type}"
                
                # CORRECTION : Configuration de la physique via set_options()
                options = {
                    "physics": {
                        "enabled": True,
                        "solver": "forceAtlas2Based",
                        "forceAtlas2Based": {
                            "gravitationalConstant": -50,
                            "centralGravity": 0.01,
                            "springLength": 95,
                            "springConstant": 0.08,
                            "damping": 0.4,
                            "avoidOverlap": 0
                        },
                        "stabilization": {
                            "enabled": True,
                            "iterations": 1000
                        }
                    },
                    "interaction": {
                        "hover": True,
                        "tooltipDelay": 200
                    }
                }
                
                net.set_options(json.dumps(options))
                
                # Affichage
                html_graph = net.generate_html()
                components.html(html_graph, height=650, scrolling=True)
                
                st.success(f"Graphe généré : {len(G.nodes())} nœuds, {len(G.edges())} liens")
                
            except Exception as e:
                st.error(f"Erreur lors de la génération du graphe : {e}")
                import traceback
                st.code(traceback.format_exc())
