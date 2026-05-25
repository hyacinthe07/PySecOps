"""
PySecOps — API REST v1
Endpoints pour le dashboard React et intégration externe.
"""
from flask import Blueprint, jsonify, request
from app.utils.db_utils import get_stats, get_historique_complet
from app.security import limiter
import datetime

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')


@api_bp.route('/health')
def health():
    return jsonify({
        "status":  "online",
        "version": "3.0",
        "time":    datetime.datetime.now().isoformat(),
    })


@api_bp.route('/stats')
@limiter.limit("60 per minute")
def stats():
    return jsonify(get_stats())


@api_bp.route('/alertes')
@limiter.limit("30 per minute")
def alertes():
    """Retourne les alertes actionnables basées sur l'historique réel."""
    stats = get_stats()
    alertes_list = []

    if (stats.get('owasp') or 0) > 0:
        alertes_list.append({
            "type":    "CRITIQUE",
            "module":  "Web Audit OWASP",
            "msg":     f"{stats['owasp']} audit(s) web effectué(s)",
            "action":  "Vérifier les vulnérabilités SQLi/XSS détectées",
            "url":     "/owasp",
            "icon":    "◇",
        })
    if (stats.get('ids') or 0) > 0:
        alertes_list.append({
            "type":    "HAUTE",
            "module":  "IDS / Forensique",
            "msg":     f"{stats['ids']} analyse(s) IDS effectuée(s)",
            "action":  "Consulter la timeline d'attaque et les IOCs",
            "url":     "/ids",
            "icon":    "🛡",
        })
    if (stats.get('ports') or 0) > 0:
        alertes_list.append({
            "type":    "INFO",
            "module":  "Port Scanner",
            "msg":     f"{stats['ports']} scan(s) de ports effectués",
            "action":  "Vérifier les services dangereux exposés",
            "url":     "/ports",
            "icon":    "◎",
        })
    if (stats.get('recon_scan') or 0) > 0:
        alertes_list.append({
            "type":    "INFO",
            "module":  "Deep Recon",
            "msg":     f"{stats['recon_scan']} scan(s) Deep Recon effectués",
            "action":  "Consulter les CVEs et vecteurs d'attaque",
            "url":     "/recon/scan",
            "icon":    "🎯",
        })
    if (stats.get('threat') or 0) > 0:
        alertes_list.append({
            "type":    "HAUTE",
            "module":  "Threat Intel",
            "msg":     f"{stats['threat']} analyse(s) de réputation",
            "action":  "Vérifier les IPs/domaines suspects",
            "url":     "/threat",
            "icon":    "🚨",
        })
    if (stats.get('nmap_import') or 0) > 0:
        alertes_list.append({
            "type":    "INFO",
            "module":  "Import Nmap",
            "msg":     f"{stats['nmap_import']} fichier(s) Nmap analysé(s)",
            "action":  "Consulter les CVEs et recommandations",
            "url":     "/nmap-import",
            "icon":    "📡",
        })

    if not alertes_list:
        alertes_list.append({
            "type":   "OK",
            "module": "Système",
            "msg":    "Aucune analyse effectuée pour l'instant",
            "action": "Lancez un scan depuis n'importe quel module",
            "url":    "/recon/scan",
            "icon":   "✅",
        })

    return jsonify({
        "alertes":     alertes_list,
        "nb_alertes":  len(alertes_list),
        "nb_critiques":sum(1 for a in alertes_list if a["type"] == "CRITIQUE"),
    })


@api_bp.route('/activite-recente')
@limiter.limit("30 per minute")
def activite_recente():
    """Retourne les 20 dernières activités."""
    stats = get_stats()
    return jsonify({
        "activites": stats.get("activites", []),
        "total":     stats.get("total", 0),
    })


@api_bp.route('/check')
@limiter.limit("5 per minute")
def api_check():
    """Vérification rapide de sécurité d'une URL."""
    url = request.args.get('url', '').strip()
    if not url:
        return jsonify({"erreur": "Paramètre 'url' manquant"}), 400

    from app.utils.recon_utils import scanner_secrets, detecter_technologies
    import requests as req
    import urllib3
    urllib3.disable_warnings()

    resultats = {
        "url":       url,
        "timestamp": datetime.datetime.now().isoformat(),
        "checks":    {},
        "score":     100,
        "niveau":    "BON",
    }

    try:
        r = req.get(url, timeout=8, verify=False)
        headers_manquants = []
        for h in ['Strict-Transport-Security', 'Content-Security-Policy',
                  'X-Frame-Options', 'X-Content-Type-Options']:
            if not r.headers.get(h):
                headers_manquants.append(h)
        resultats["checks"]["headers"] = {
            "score":     100 - len(headers_manquants) * 25,
            "manquants": headers_manquants,
        }
        resultats["score"] -= len(headers_manquants) * 10
    except Exception:
        pass

    if resultats["score"] < 30:   resultats["niveau"] = "CRITIQUE"
    elif resultats["score"] < 60: resultats["niveau"] = "ÉLEVÉ"
    elif resultats["score"] < 80: resultats["niveau"] = "MODÉRÉ"

    return jsonify(resultats)


@api_bp.route('/docs')
def docs():
    return jsonify({
        "api":      "PySecOps API v1",
        "base_url": "https://pysecops.onrender.com/api/v1",
        "endpoints": [
            {"GET":  "/health",          "desc": "Statut plateforme",           "limit": "illimité"},
            {"GET":  "/stats",           "desc": "Statistiques globales",       "limit": "60/min"},
            {"GET":  "/alertes",         "desc": "Alertes actionnables",        "limit": "30/min"},
            {"GET":  "/activite-recente","desc": "Dernières activités",         "limit": "30/min"},
            {"GET":  "/check?url=",      "desc": "Vérification rapide sécurité","limit": "5/min"},
        ]
    })
