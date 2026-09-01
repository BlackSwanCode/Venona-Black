import sqlite3
import os
import hashlib
from datetime import datetime

DB_PATH = os.getenv("OSINT_DB_PATH", "osint_searches.db")

def init_database():
    print(f"[*] Initialisation de la base de données : {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Activation du mode WAL et des clés étrangères
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")

    # 1. Création des tables de base (Schéma original Venona)
    print("[*] Création/Vérification des tables de base...")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS CASES (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        target_scope TEXT NOT NULL,
        status TEXT DEFAULT 'OPEN',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        closed_at TIMESTAMP,
        investigator TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS SEARCHES (
        id TEXT PRIMARY KEY,
        case_id TEXT,
        query TEXT NOT NULL,
        collector_type TEXT,
        raw_results_hash TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (case_id) REFERENCES CASES(id) ON DELETE SET NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS IOCS (
        id TEXT PRIMARY KEY,
        value TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        threat_score REAL DEFAULT 0.0,
        enrichment_data TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS LEAKS (
        id TEXT PRIMARY KEY,
        ioc_id TEXT,
        case_id TEXT,
        signature_type TEXT,
        snippet TEXT,
        source_url TEXT,
        severity TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ioc_id) REFERENCES IOCS(id) ON DELETE CASCADE,
        FOREIGN KEY (case_id) REFERENCES CASES(id) ON DELETE SET NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS WATCHLISTS (
        id TEXT PRIMARY KEY,
        term TEXT UNIQUE NOT NULL,
        type TEXT,
        is_active BOOLEAN DEFAULT 1
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ALERTS (
        id TEXT PRIMARY KEY,
        watchlist_id TEXT,
        leak_id TEXT,
        status TEXT DEFAULT 'NEW',
        triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (watchlist_id) REFERENCES WATCHLISTS(id) ON DELETE CASCADE,
        FOREIGN KEY (leak_id) REFERENCES LEAKS(id) ON DELETE SET NULL
    );
    """)

    # 2. Migration des nouvelles colonnes pour la détection de fuites (Data Breach)
    print("[*] Application des migrations pour les fuites de données...")

    migrations = [
        "ALTER TABLE LEAKS ADD COLUMN leak_category TEXT DEFAULT 'UNKNOWN'",
        "ALTER TABLE LEAKS ADD COLUMN raw_context TEXT",
        "ALTER TABLE LEAKS ADD COLUMN is_secret_leak BOOLEAN DEFAULT 0"
    ]

    for query in migrations:
        try:
            cursor.execute(query)
            col_name = query.split("ADD COLUMN")[1].split(" ")[0]
            print(f"    [+] Colonne ajoutée : {col_name}")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                pass # La colonne existe déjà, on ignore silencieusement
            else:
                print(f"    [-] Erreur SQL inattendue : {e}")

    # 3. Création des index pour optimiser les recherches
    print("[*] Création des index d'optimisation...")
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_iocs_value ON IOCS(value)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_type ON IOCS(type)",
        "CREATE INDEX IF NOT EXISTS idx_leaks_case_id ON LEAKS(case_id)",
        "CREATE INDEX IF NOT EXISTS idx_leaks_severity ON LEAKS(severity)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON ALERTS(status)",
        "CREATE INDEX IF NOT EXISTS idx_searches_case_id ON SEARCHES(case_id)"
    ]
    for idx_query in indexes:
        cursor.execute(idx_query)

    # 4. Insertion des données de démonstration (si la base est vide)
    cursor.execute("SELECT COUNT(*) FROM CASES")
    if cursor.fetchone()[0] == 0:
        print("[*] Insertion des données de démonstration...")

        demo_case_id = "demo-case-id"
        demo_ioc_id = hashlib.sha256("admin@exemple-cible.com".encode()).hexdigest()
        demo_search_id = "demo-search-001"
        demo_watchlist_id = "demo-watchlist-001"

        cursor.execute("""
            INSERT INTO CASES (id, name, description, target_scope, investigator)
            VALUES (?, ?, ?, ?, ?)
        """, (demo_case_id, "Cas Démo : Veille de Marque", "Étude de cas pour tester l'interface", "*.exemple-cible.com, admin@exemple-cible.com", "Pyer"))

        cursor.execute("""
            INSERT INTO IOCS (id, value, type, threat_score)
            VALUES (?, ?, ?, ?)
        """, (demo_ioc_id, "admin@exemple-cible.com", "EMAIL", 0.65))

        cursor.execute("""
            INSERT INTO SEARCHES (id, case_id, query, collector_type)
            VALUES (?, ?, ?, ?)
        """, (demo_search_id, demo_case_id, "exemple-cible.com", "duckduckgo_html"))

        cursor.execute("""
            INSERT INTO WATCHLISTS (id, term, type, is_active)
            VALUES (?, ?, ?, ?)
        """, (demo_watchlist_id, "exemple-cible.com", "DOMAIN", 1))

        print("[+] Données de démo insérées.")
    else:
        print("[*] Base de données déjà peuplée, skip de la démo.")

    conn.commit()
    conn.close()
    print("[SUCCESS] Initialisation de la base de données terminée avec succès !")

if __name__ == "__main__":
    init_database()
