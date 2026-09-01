import streamlit as st
import asyncio
import json
import os
from datetime import datetime
from storage.db_manager import DatabaseManager
from storage.export_manager import ExportManager
import aiosqlite


async def get_case_iocs(case_id: str):
    """Récupère tous les IOC associés à un cas."""
    db = DatabaseManager()
    return await db.get_iocs_for_case(case_id)


async def get_case_searches(case_id: str):
    """Récupère l'historique des recherches pour un cas."""
    db_path = os.getenv("OSINT_DB_PATH", "osint_searches.db")
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT * FROM searches 
            WHERE case_id = ? 
            ORDER BY timestamp DESC
        """, (case_id,))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def update_case_status(case_id: str, status: str):
    """Met à jour le statut d'un cas."""
    db_path = os.getenv("OSINT_DB_PATH", "osint_searches.db")
    async with aiosqlite.connect(db_path) as db:
        if status == "CLOSED":
            await db.execute("""
                UPDATE cases 
                SET status = ?, closed_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            """, (status, case_id))
        else:
            await db.execute("UPDATE cases SET status = ? WHERE id = ?", (status, case_id))
        await db.commit()


def render_case_management():
    st.header("📁 Gestion des Cas d'Enquête")

    db = DatabaseManager()

    # Onglets
    tab1, tab2, tab3 = st.tabs(["➕ Nouveau Cas", "📋 Liste des Cas", "📊 Timeline"])

    with tab1:
        st.subheader("Créer un Nouveau Cas")

        case_name = st.text_input("Nom du cas *", placeholder="ex: Veille Désinformation - Campagne 2024")
        case_desc = st.text_area("Description", placeholder="Objectifs, contexte, méthodologie...")
        case_scope = st.text_input("Périmètre autorisé (Scope) *", placeholder="ex: *.target.com, admin@target.com")
        investigator = st.text_input("Investigateur", placeholder="Votre nom ou pseudonyme")

        if st.button("🚀 Créer le cas", type="primary"):
            if not case_name or not case_scope:
                st.error("Le nom et le périmètre sont obligatoires.")
            else:
                try:
                    case_id = asyncio.run(db.create_case(case_name, case_desc, case_scope, investigator))
                    st.success(f"✅ Cas créé avec succès ! ID: `{case_id[:8]}...`")
                    st.balloons()
                except Exception as e:
                    st.error(f"Erreur lors de la création : {e}")

    with tab2:
        st.subheader("Cas Existants")

        try:
            cases = asyncio.run(db.get_all_cases())

            if not cases:
                st.info("Aucun cas enregistré. Créez-en un dans l'onglet 'Nouveau Cas'.")
            else:
                for case in cases:
                    with st.expander(f"📁 {case['name']} ({case['status']})", expanded=False):
                        st.write(f"**Description** : {case.get('description', 'N/A')}")
                        st.write(f"**Périmètre** : {case.get('target_scope', 'N/A')}")
                        st.write(f"**Investigateur** : {case.get('investigator', 'N/A')}")
                        st.write(f"**Créé le** : {case.get('created_at', 'N/A')}")
                        if case.get('closed_at'):
                            st.write(f"**Fermé le** : {case.get('closed_at', 'N/A')}")

                        # CORRECTION: Bouton pour activer le cas
                        col_activate, _ = st.columns([1, 3])
                        with col_activate:
                            if st.button("▶️ Activer ce cas", key=f"activate_{case['id']}"):
                                st.session_state['active_case_id'] = case['id']
                                st.session_state['active_case_name'] = case['name']
                                st.success(f"✅ Cas actif: {case['name']}")
                                st.rerun()

                        st.divider()

                        # Section IOC
                        st.markdown("#### 🎯 Indicateurs de Compromis (IOC)")

                        if st.button("📊 Voir les IOC", key=f"view_{case['id']}"):
                            with st.spinner("Chargement des IOC..."):
                                try:
                                    iocs = asyncio.run(get_case_iocs(case['id']))

                                    if not iocs:
                                        st.info("Aucun IOC associé à ce cas. Lancez une investigation pour en extraire.")
                                    else:
                                        st.success(f"**{len(iocs)} IOC trouvé(s)**")

                                        ioc_data = []
                                        for ioc in iocs:
                                            enrichment = json.loads(ioc.get('enrichment_data', '{}') or '{}')
                                            ioc_data.append({
                                                "Type": ioc['type'],
                                                "Value": ioc['value'],
                                                "Score": f"{ioc.get('threat_score', 0):.2f}",
                                                "Dernière vue": ioc.get('last_seen', 'N/A'),
                                                "Enrichi": "✅" if enrichment else "❌"
                                            })

                                        st.dataframe(ioc_data, use_container_width=True)

                                        if st.checkbox("🔍 Afficher les détails d'enrichissement"):
                                            for ioc in iocs:
                                                enrichment = json.loads(ioc.get('enrichment_data', '{}') or '{}')
                                                if enrichment:
                                                    with st.expander(f"{ioc['type']}: {ioc['value']}"):
                                                        st.json(enrichment)

                                except Exception as e:
                                    st.error(f"Erreur lors du chargement des IOC : {e}")

                        st.divider()

                        # Section Export
                        st.markdown("#### 📥 Exports")

                        col1, col2, col3, col4 = st.columns(4)

                        with col1:
                            if st.button("🔗 STIX 2.1", key=f"stix_{case['id']}", use_container_width=True):
                                with st.spinner("Génération STIX 2.1..."):
                                    try:
                                        iocs = asyncio.run(get_case_iocs(case['id']))
                                        if not iocs:
                                            st.warning("Aucun IOC à exporter.")
                                        else:
                                            export_manager = ExportManager()
                                            filename = export_manager.export_stix21(iocs, case['name'])

                                            with open(filename, "rb") as f:
                                                st.download_button(
                                                    label="📥 Télécharger STIX",
                                                    data=f,
                                                    file_name=filename,
                                                    mime="application/json",
                                                    key=f"download_stix_{case['id']}"
                                                )
                                            st.success(f"✅ Fichier généré : {filename}")
                                    except Exception as e:
                                        st.error(f"Erreur export STIX : {e}")

                        with col2:
                            if st.button("🛡️ MISP", key=f"misp_{case['id']}", use_container_width=True):
                                with st.spinner("Génération MISP..."):
                                    try:
                                        iocs = asyncio.run(get_case_iocs(case['id']))
                                        if not iocs:
                                            st.warning("Aucun IOC à exporter.")
                                        else:
                                            export_manager = ExportManager()
                                            filename = export_manager.export_misp(iocs, case['name'])

                                            with open(filename, "rb") as f:
                                                st.download_button(
                                                    label="📥 Télécharger MISP",
                                                    data=f,
                                                    file_name=filename,
                                                    mime="application/json",
                                                    key=f"download_misp_{case['id']}"
                                                )
                                            st.success(f"✅ Fichier généré : {filename}")
                                    except Exception as e:
                                        st.error(f"Erreur export MISP : {e}")

                        with col3:
                            if st.button("📄 PDF", key=f"pdf_{case['id']}", use_container_width=True):
                                with st.spinner("Génération PDF..."):
                                    try:
                                        iocs = asyncio.run(get_case_iocs(case['id']))
                                        export_manager = ExportManager()
                                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                                        pdf_filename = f"report_{case['name'].replace(' ', '_')}_{timestamp}.pdf"

                                        export_manager.export_pdf_report(case, iocs, pdf_filename)

                                        with open(pdf_filename, "rb") as f:
                                            st.download_button(
                                                label="📥 Télécharger PDF",
                                                data=f,
                                                file_name=pdf_filename,
                                                mime="application/pdf",
                                                key=f"download_pdf_{case['id']}"
                                            )
                                        st.success(f"✅ Rapport généré : {pdf_filename}")
                                    except Exception as e:
                                        st.error(f"Erreur export PDF : {e}")

                        with col4:
                            if st.button("📦 ZIP Bundle", key=f"zip_{case['id']}", use_container_width=True):
                                with st.spinner("Génération du bundle complet..."):
                                    try:
                                        iocs = asyncio.run(get_case_iocs(case['id']))
                                        export_manager = ExportManager()
                                        zip_filename = export_manager.export_bundle_zip(case, iocs, case['name'])

                                        with open(zip_filename, "rb") as f:
                                            st.download_button(
                                                label="📥 Télécharger ZIP",
                                                data=f,
                                                file_name=zip_filename,
                                                mime="application/zip",
                                                key=f"download_zip_{case['id']}"
                                            )
                                        st.success(f"✅ Bundle généré : {zip_filename}")
                                    except Exception as e:
                                        st.error(f"Erreur export ZIP : {e}")

                        st.divider()

                        # Actions sur le cas
                        st.markdown("#### ⚙️ Actions")

                        col1, col2, col3 = st.columns(3)

                        with col1:
                            if case['status'] != "CLOSED":
                                if st.button("🔒 Fermer le cas", key=f"close_{case['id']}"):
                                    asyncio.run(update_case_status(case['id'], "CLOSED"))
                                    st.success("Cas fermé.")
                                    st.rerun()

                        with col2:
                            if case['status'] == "CLOSED":
                                if st.button("📂 Réouvrir", key=f"reopen_{case['id']}"):
                                    asyncio.run(update_case_status(case['id'], "OPEN"))
                                    st.success("Cas réouvert.")
                                    st.rerun()

                        with col3:
                            if st.button("🗄️ Archiver", key=f"archive_{case['id']}"):
                                asyncio.run(update_case_status(case['id'], "ARCHIVED"))
                                st.success("Cas archivé.")
                                st.rerun()

        except Exception as e:
            st.error(f"Erreur lors du chargement des cas : {e}")
            import traceback
            st.code(traceback.format_exc())

    with tab3:
        st.subheader("Timeline du Cas Actif")

        if 'active_case_id' in st.session_state:
            case_id = st.session_state['active_case_id']
            case_name = st.session_state.get('active_case_name', 'N/A')

            st.info(f"Timeline pour le cas : **{case_name}**")

            try:
                searches = asyncio.run(get_case_searches(case_id))

                if not searches:
                    st.warning("Aucune recherche enregistrée pour ce cas.")
                else:
                    st.write(f"**{len(searches)} recherche(s) effectuée(s)**")

                    for search in searches:
                        with st.expander(f"🔍 {search['query']} - {search['timestamp']}"):
                            st.write(f"**Collecteurs** : {search.get('collector_type', 'N/A')}")
                            st.write(f"**Hash d'intégrité** : `{search.get('raw_results_hash', 'N/A')}`")
                            st.caption("Chain of custody : ce hash garantit l'intégrité des résultats bruts.")
            except Exception as e:
                st.error(f"Erreur lors du chargement de la timeline : {e}")
        else:
            st.warning("Sélectionnez un cas dans l'onglet 'Liste des Cas' pour voir sa timeline.")
            st.info("💡 Cliquez sur un cas pour l'activer, puis revenez dans cet onglet.")
