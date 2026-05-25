"""
PySecOps — Base de données SQLite
Persistance des stats et historique des analyses.
"""
import sqlite3
import datetime
import threading
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'pysecops.db')
_lock   = threading.Lock()


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock:
        conn = _conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS analyses (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                module  TEXT    NOT NULL,
                detail  TEXT    DEFAULT '',
                date    TEXT    NOT NULL,
                heure   TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS compteurs (
                module  TEXT PRIMARY KEY,
                total   INTEGER DEFAULT 0
            );
        """)
        conn.commit()
        conn.close()


def enregistrer(module: str, detail: str = ""):
    now = datetime.datetime.now()
    with _lock:
        conn = _conn()
        conn.execute(
            "INSERT INTO analyses (module, detail, date, heure) VALUES (?,?,?,?)",
            (module, str(detail)[:100],
             now.strftime("%d/%m/%Y"), now.strftime("%H:%M:%S"))
        )
        conn.execute("""
            INSERT INTO compteurs (module, total) VALUES (?,1)
            ON CONFLICT(module) DO UPDATE SET total = total + 1
        """, (module,))
        conn.commit()
        conn.close()


def get_stats() -> dict:
    with _lock:
        conn  = _conn()
        rows  = conn.execute("SELECT module, total FROM compteurs").fetchall()
        compt = {r["module"]: r["total"] for r in rows}
        total = sum(compt.values())
        acts  = conn.execute(
            "SELECT module, detail, date, heure FROM analyses ORDER BY id DESC LIMIT 20"
        ).fetchall()
        conn.close()

    return {
        "total":       total,
        "ports":       compt.get("ports",       0),
        "owasp":       compt.get("owasp",        0),
        "logs":        compt.get("logs",         0),
        "secops":      compt.get("secops",       0),
        "whois":       compt.get("whois",        0),
        "ip_intel":    compt.get("ip_intel",     0),
        "ssl":         compt.get("ssl",          0),
        "qrcode":      compt.get("qrcode",       0),
        "recon_scan":  compt.get("recon_scan",   0),
        "recon_sub":   compt.get("recon_sub",    0),
        "recon_cve":   compt.get("recon_cve",    0),
        "ids":         compt.get("ids",          0),
        "audit":       compt.get("audit",        0),
        "assistant":   compt.get("assistant",    0),
        "threat":      compt.get("threat",       0),
        "nmap_import": compt.get("nmap_import",  0),
        "osint_emails":compt.get("osint_emails", 0),
        "osint_dorks": compt.get("osint_dorks",  0),
        "modules":     15,
        "version":     "3.0",
        "activites":   [dict(a) for a in acts],
    }


def get_historique_complet() -> list:
    with _lock:
        conn = _conn()
        rows = conn.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT 100"
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]
