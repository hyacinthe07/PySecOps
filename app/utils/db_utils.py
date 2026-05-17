"""
PySecOps — Base de données SQLite
Persistance des stats et de l'historique des analyses.
"""
import sqlite3
import datetime
import threading
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'pysecops.db')
_lock = threading.Lock()


def _connexion():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crée les tables si elles n'existent pas."""
    with _lock:
        conn = _connexion()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS analyses (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                module    TEXT    NOT NULL,
                detail    TEXT    DEFAULT '',
                date      TEXT    NOT NULL,
                heure     TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS compteurs (
                module    TEXT PRIMARY KEY,
                total     INTEGER DEFAULT 0
            );
        """)
        conn.commit()
        conn.close()


def enregistrer(module: str, detail: str = ""):
    """Enregistre une analyse et incrémente le compteur."""
    now = datetime.datetime.now()
    with _lock:
        conn = _connexion()
        conn.execute(
            "INSERT INTO analyses (module, detail, date, heure) VALUES (?, ?, ?, ?)",
            (module, detail[:100], now.strftime("%d/%m/%Y"), now.strftime("%H:%M:%S"))
        )
        conn.execute("""
            INSERT INTO compteurs (module, total) VALUES (?, 1)
            ON CONFLICT(module) DO UPDATE SET total = total + 1
        """, (module,))
        conn.commit()
        conn.close()


def get_stats() -> dict:
    """Retourne les statistiques globales depuis la base."""
    with _lock:
        conn = _connexion()
        rows = conn.execute("SELECT module, total FROM compteurs").fetchall()
        compteurs = {r["module"]: r["total"] for r in rows}
        total = sum(compteurs.values())
        activites = conn.execute(
            "SELECT module, detail, date, heure FROM analyses ORDER BY id DESC LIMIT 15"
        ).fetchall()
        conn.close()

    return {
        "total":      total,
        "ports":      compteurs.get("ports",      0),
        "owasp":      compteurs.get("owasp",      0),
        "logs":       compteurs.get("logs",       0),
        "secops":     compteurs.get("secops",     0),
        "whois":      compteurs.get("whois",      0),
        "ip_intel":   compteurs.get("ip_intel",   0),
        "ssl":        compteurs.get("ssl",        0),
        "qrcode":     compteurs.get("qrcode",     0),
        "recon_scan": compteurs.get("recon_scan", 0),
        "recon_sub":  compteurs.get("recon_sub",  0),
        "recon_cve":  compteurs.get("recon_cve",  0),
        "ids":        compteurs.get("ids",        0),
        "audit":      compteurs.get("audit",      0),
        "assistant":  compteurs.get("assistant",  0),
        "modules":    14,
        "version":    "2.0",
        "activites":  [dict(a) for a in activites],
    }
