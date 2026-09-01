import aiosqlite
import os
import hashlib
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from core.models import Case, IOC, Leak, WatchlistItem, Alert

DB_PATH = os.getenv("OSINT_DB_PATH", "osint_searches.db")

class DatabaseManager:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    async def create_case(self, name: str, description: str, target_scope: str, investigator: str = None) -> str:
        import uuid
        case_id = str(uuid.uuid4())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO cases (id, name, description, target_scope, investigator) VALUES (?, ?, ?, ?, ?)",
                (case_id, name, description, target_scope, investigator)
            )
            await db.commit()
        return case_id

    async def get_all_cases(self) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM cases ORDER BY created_at DESC")
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def log_search(self, case_id: str, query: str, collector_type: str, raw_results: str) -> str:
        import uuid
        search_id = str(uuid.uuid4())
        results_hash = hashlib.sha256(raw_results.encode('utf-8')).hexdigest()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO searches (id, case_id, query, collector_type, raw_results_hash) VALUES (?, ?, ?, ?, ?)",
                (search_id, case_id, query, collector_type, results_hash)
            )
            await db.commit()
        return search_id

    async def save_ioc(self, ioc: IOC, enrichment_data: Dict[str, Any] = None) -> str:
        import uuid
        ioc_id = hashlib.sha256(ioc.value.encode()).hexdigest()
        enrichment_json = json.dumps(enrichment_data) if enrichment_data else None
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO iocs (id, value, type, first_seen, last_seen, threat_score, enrichment_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(value) DO UPDATE SET 
                last_seen = CURRENT_TIMESTAMP,
                enrichment_data = excluded.enrichment_data
            """, (ioc_id, ioc.value, ioc.type, datetime.utcnow(), datetime.utcnow(), ioc.confidence, enrichment_json))
            await db.commit()
        return ioc_id

    async def save_leak(self, case_id: str, leak: Leak) -> str:
        import uuid
        leak_id = str(uuid.uuid4())
        
        # Récupérer l'IOC ID
        ioc_id = hashlib.sha256(leak.ioc_value.encode()).hexdigest()
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO leaks (id, ioc_id, case_id, signature_type, snippet, source_url, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (leak_id, ioc_id, case_id, leak.signature_type, leak.snippet, leak.source_url, leak.severity))
            await db.commit()
        return leak_id

    async def get_iocs_for_case(self, case_id: str) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT DISTINCT i.* FROM iocs i
                JOIN leaks l ON i.id = l.ioc_id
                WHERE l.case_id = ?
                ORDER BY i.last_seen DESC
            """, (case_id,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_dashboard_stats(self) -> Dict[str, int]:
        async with aiosqlite.connect(self.db_path) as db:
            stats = {}
            
            cursor = await db.execute("SELECT COUNT(*) FROM cases WHERE status = 'OPEN'")
            stats['open_cases'] = (await cursor.fetchone())[0]
            
            cursor = await db.execute("SELECT COUNT(*) FROM iocs")
            stats['total_iocs'] = (await cursor.fetchone())[0]
            
            cursor = await db.execute("SELECT COUNT(*) FROM leaks WHERE severity IN ('HIGH', 'CRITICAL')")
            stats['critical_leaks'] = (await cursor.fetchone())[0]
            
            cursor = await db.execute("SELECT COUNT(*) FROM alerts WHERE status = 'NEW'")
            stats['new_alerts'] = (await cursor.fetchone())[0]
            
            return stats

    async def add_watchlist_item(self, term: str, item_type: str) -> str:
        import uuid
        item_id = str(uuid.uuid4())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR IGNORE INTO watchlists (id, term, type, is_active) VALUES (?, ?, ?, 1)",
                (item_id, term, item_type)
            )
            await db.commit()
        return item_id

    async def get_watchlist_items(self) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM watchlists ORDER BY term")
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT a.*, w.term as watchlist_term 
                FROM alerts a 
                LEFT JOIN watchlists w ON a.watchlist_id = w.id
                ORDER BY a.triggered_at DESC 
                LIMIT ?
            """, (limit,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def create_alert(self, watchlist_id: str, alert_type: str, severity: str, details: str) -> str:
        import uuid
        alert_id = str(uuid.uuid4())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO alerts (id, watchlist_id, status, triggered_at)
                VALUES (?, ?, 'NEW', CURRENT_TIMESTAMP)
            """, (alert_id, watchlist_id))
            await db.commit()
        return alert_id

db = DatabaseManager()
