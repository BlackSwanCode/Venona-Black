import streamlit as st

def render_legal_banner():
    st.markdown(
        """
        <div style="background-color: #ff4b4b; padding: 10px; border-radius: 5px; color: white; text-align: center; font-weight: bold;">
            ⚠️ AVERTISSEMENT LÉGAL : Usage autorisé uniquement (CTF, Bug Bounty dans le scope, systèmes propres ou avec autorisation explicite). 
            L'utilisation de cet outil pour des activités non autorisées est strictement interdite.
        </div>
        """,
        unsafe_allow_html=True
    )
    
    if "legal_accepted" not in st.session_state:
        st.session_state.legal_accepted = False

    with st.sidebar:
        st.divider()
        st.session_state.legal_accepted = st.checkbox(
            "🛡️ Je certifie utiliser cet outil dans un cadre légal et autorisé.",
            value=st.session_state.legal_accepted
        )
        
    if not st.session_state.legal_accepted:
        st.warning("Veuillez cocher la case d'acceptation des conditions légales dans la barre latérale.")
        st.stop()
