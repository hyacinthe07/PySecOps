"""
PySecOps — Blueprint Deep Recon Engine
Streaming temps réel via Server-Sent Events (SSE).
"""
from flask import Blueprint, render_template, request, Response, stream_with_context
from app.utils.recon_utils import (
    grab_banner, extraire_version, chercher_cves,
    detecter_technologies, scanner_secrets,
    calculer_attack_surface, SERVICES_DANGEREUX,
    enumerer_subdomains, scanner_secrets,
    detecter_technologies, chercher_cves
)
from app.utils.db_utils import enregistrer
import socket
import json
import concurrent.futures
import time

recon_bp = Blueprint('recon', __name__)

# Services courants à scanner
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 465, 587, 993, 995, 1433, 1723,
    3306, 3389, 5432, 5900, 6379, 8080, 8443,
    9200, 27017, 2375, 11211, 8888, 9090,
]

SERVICES_MAP = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
    53:"DNS", 80:"HTTP", 110:"POP3", 135:"RPC",
    139:"NetBIOS", 143:"IMAP", 443:"HTTPS",
    445:"SMB", 465:"SMTPS", 587:"SMTP-TLS",
    993:"IMAPS", 995:"POP3S", 1433:"MSSQL",
    1723:"PPTP", 3306:"MySQL", 3389:"RDP",
    5432:"PostgreSQL", 5900:"VNC", 6379:"Redis",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt",
    9200:"Elasticsearch", 27017:"MongoDB",
    2375:"Docker-API", 11211:"Memcached",
    8888:"Jupyter", 9090:"Prometheus",
}


def _event(type_: str, data: dict) -> str:
    """Formate un événement SSE."""
    return f"data: {json.dumps({'type': type_, **data})}\n\n"


@recon_bp.route('/recon')
def recon():
    return render_template('recon/index.html', active='recon')


@recon_bp.route('/recon/scan')
def deep_scan():
    return render_template('recon/scan.html', active='recon')


@recon_bp.route('/recon/stream')
def stream():
    """
    Endpoint SSE — envoie les résultats du scan en temps réel.
    Le client JS écoute cet endpoint et affiche chaque événement.
    """
    cible = request.args.get('cible', '').strip()

    if not cible:
        return Response("data: {\"type\": \"erreur\", \"msg\": \"Cible manquante\"}\n\n",
                        mimetype='text/event-stream')

    def generer():
        domaine = cible.replace("https://","").replace("http://","").split("/")[0].strip()

        # ── ÉTAPE 1 : Résolution DNS
        yield _event("etape", {"msg": f"🔍 Résolution DNS de {domaine}...", "step": 1, "total": 6})
        try:
            ip = socket.gethostbyname(domaine)
            yield _event("info", {"msg": f"✅ IP résolue : {ip}"})
        except Exception:
            yield _event("erreur", {"msg": f"❌ Impossible de résoudre '{domaine}'"})
            return

        # ── ÉTAPE 2 : Scan de ports
        yield _event("etape", {"msg": f"⚡ Scan des {len(TOP_PORTS)} ports principaux...", "step": 2, "total": 6})
        ports_ouverts = []

        def _scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.8)
                    if s.connect_ex((ip, port)) == 0:
                        banner  = grab_banner(ip, port)
                        version = extraire_version("", banner)
                        service = SERVICES_MAP.get(port, "Unknown")
                        dangereux = port in SERVICES_DANGEREUX
                        return {
                            "port":      port,
                            "service":   service,
                            "banner":    banner[:100],
                            "version":   version,
                            "dangereux": dangereux,
                            "risque":    SERVICES_DANGEREUX[port]["risque"] if dangereux else "—",
                        }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(_scan_port, p): p for p in TOP_PORTS}
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r:
                    ports_ouverts.append(r)
                    # Envoyer le port trouvé immédiatement
                    yield _event("port", {
                        "port":      r["port"],
                        "service":   r["service"],
                        "version":   r["version"],
                        "dangereux": r["dangereux"],
                        "risque":    r["risque"],
                        "banner":    r["banner"][:60],
                    })

        ports_ouverts.sort(key=lambda x: x["port"])
        yield _event("info", {"msg": f"✅ {len(ports_ouverts)} port(s) ouvert(s) détecté(s)"})

        # ── ÉTAPE 3 : CVE Lookup
        yield _event("etape", {"msg": "💀 Recherche CVEs via NIST NVD...", "step": 3, "total": 6})
        cves_totales = []
        services_vus = set()

        for p in ports_ouverts:
            keyword = f"{p['service']} {p['version']}".strip() if p.get("version") else p["service"]
            if keyword in services_vus:
                continue
            services_vus.add(keyword)
            yield _event("info", {"msg": f"🔎 CVE lookup : {keyword}"})
            cves = chercher_cves(keyword, max_results=3)
            for cve in cves:
                cve["service_associe"] = p["service"]
                cve["port_associe"]    = p["port"]
                cves_totales.append(cve)
                yield _event("cve", {
                    "id":       cve["id"],
                    "score":    cve["score"],
                    "severite": cve["severite"],
                    "desc":     cve["desc"][:100],
                    "service":  p["service"],
                    "port":     p["port"],
                    "url":      cve["url"],
                })

        cves_totales.sort(key=lambda x: x.get("score", 0), reverse=True)
        yield _event("info", {"msg": f"✅ {len(cves_totales)} CVE(s) trouvée(s)"})

        # ── ÉTAPE 4 : Technologies
        yield _event("etape", {"msg": "🖥 Détection des technologies...", "step": 4, "total": 6})
        techs = {}
        url_base = None

        for p in ports_ouverts:
            if p["port"] in (443, 8443):
                url_base = f"https://{domaine}"
                break
            if p["port"] in (80, 8080):
                url_base = f"http://{domaine}"

        if url_base:
            techs = detecter_technologies(url_base)
            tech_list = list(techs.get("technologies", {}).keys())
            if tech_list:
                yield _event("tech", {"technologies": tech_list})
                yield _event("info", {"msg": f"✅ Technologies : {', '.join(tech_list[:5])}"})
            else:
                yield _event("info", {"msg": "ℹ Aucune technologie identifiée"})
        else:
            yield _event("info", {"msg": "ℹ Pas de service web détecté"})

        # ── ÉTAPE 5 : Secrets exposés
        yield _event("etape", {"msg": "🔑 Scan des fichiers sensibles (35 endpoints)...", "step": 5, "total": 6})
        secrets = []

        if url_base:
            secrets = scanner_secrets(url_base)
            for s in secrets:
                yield _event("secret", {
                    "chemin":      s["chemin"],
                    "severite":    s["severite"],
                    "description": s["description"],
                    "url":         s["url"],
                    "taille":      s["taille"],
                })
            yield _event("info", {"msg": f"✅ {len(secrets)} fichier(s) sensible(s) trouvé(s)"})
        else:
            yield _event("info", {"msg": "ℹ Pas de service web — scan secrets ignoré"})

        # ── ÉTAPE 6 : Attack Surface Score
        yield _event("etape", {"msg": "📊 Calcul du score de surface d'attaque...", "step": 6, "total": 6})
        attack_surface = calculer_attack_surface({
            "ports":        ports_ouverts,
            "cves":         cves_totales,
            "secrets":      secrets,
            "technologies": techs.get("technologies", {}),
        })

        yield _event("score", {
            "score":           attack_surface["score"],
            "niveau":          attack_surface["niveau"],
            "couleur":         attack_surface["couleur"],
            "nb_vecteurs":     attack_surface["nb_vecteurs"],
            "vecteurs":        attack_surface["vecteurs"][:10],
            "recommandations": attack_surface["recommandations"],
        })

        enregistrer("recon_scan", domaine)

        # ── FIN
        yield _event("termine", {
            "msg":       "✅ Scan terminé",
            "nb_ports":  len(ports_ouverts),
            "nb_cves":   len(cves_totales),
            "nb_secrets":len(secrets),
            "score":     attack_surface["score"],
            "ip":        ip,
            "domaine":   domaine,
        })

    return Response(
        stream_with_context(generer()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )


@recon_bp.route('/recon/subdomains', methods=['GET', 'POST'])
def subdomains():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        domaine = request.form.get('domaine', '').strip()
        if not domaine:
            erreur = "Entrez un nom de domaine."
        else:
            resultat = enumerer_subdomains(domaine)
            enregistrer("recon_sub", domaine)
    return render_template(
        'recon/subdomains.html', active='recon',
        resultat=resultat, erreur=erreur
    )


@recon_bp.route('/recon/secrets', methods=['GET', 'POST'])
def secrets():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            erreur = "Entrez une URL."
        else:
            if not url.startswith('http'):
                url = 'http://' + url
            resultat = {
                "url":     url,
                "secrets": scanner_secrets(url),
            }
            enregistrer("recon_secrets", url)
    return render_template(
        'recon/secrets.html', active='recon',
        resultat=resultat, erreur=erreur
    )


@recon_bp.route('/recon/cve', methods=['GET', 'POST'])
def cve_lookup():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip()
        nb      = int(request.form.get('nb', 10))
        if not keyword:
            erreur = "Entrez un service ou une version."
        else:
            cves = chercher_cves(keyword, max_results=nb)
            resultat = {"keyword": keyword, "cves": cves, "total": len(cves)}
            enregistrer("recon_cve", keyword)
    return render_template(
        'recon/cve.html', active='recon',
        resultat=resultat, erreur=erreur
    )
