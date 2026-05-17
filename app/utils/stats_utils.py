"""
PySecOps — Statistiques du dashboard
Compteurs persistants en mémoire (reset au redémarrage).
Pour une persistance réelle, utiliser SQLite à l'étape suivante.
"""
from collections import defaultdict
import datetime
import threading

# ── Stockage thread-safe en mémoire
_lock = threading.Lock()

_compteurs = defaultdict(int)   # {"ports": 12, "owasp": 5, ...}
_activites = []                 # liste des dernières actions (max 20)


def incrementer(module: str, detail: str = ""):
    """Incrémente le compteur d'un module et enregistre l'activité."""
    with _lock:
        _compteurs[module] += 1
        _compteurs["total"] += 1
        _activites.insert(0, {
            "module":  module,
            "detail":  detail,
            "heure":   datetime.datetime.now().strftime("%H:%M:%S"),
            "date":    datetime.datetime.now().strftime("%d/%m/%Y"),
        })
        # Garder seulement les 20 dernières activités
        if len(_activites) > 20:
            _activites.pop()


def get_stats() -> dict:
    """Retourne les stats actuelles."""
    with _lock:
        return {
            "total":     _compteurs.get("total", 0),
            "ports":     _compteurs.get("ports", 0),
            "owasp":     _compteurs.get("owasp", 0),
            "logs":      _compteurs.get("logs", 0),
            "secops":    _compteurs.get("secops", 0),
            "whois":     _compteurs.get("whois", 0),
            "ip_intel":  _compteurs.get("ip_intel", 0),
            "ssl":       _compteurs.get("ssl", 0),
            "modules":   10,
            "version":   "2.0",
            "uptime":    _get_uptime(),
            "activites": list(_activites[:10]),
        }


_start_time = datetime.datetime.now()

def _get_uptime() -> str:
    delta = datetime.datetime.now() - _start_time
    heures = int(delta.total_seconds() // 3600)
    minutes = int((delta.total_seconds() % 3600) // 60)
    return f"{heures}h {minutes}m"
