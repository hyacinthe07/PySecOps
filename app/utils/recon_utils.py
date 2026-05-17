"""
PySecOps — Deep Recon Engine
Fingerprinting multi-couches, CVE lookup, attack surface scoring,
détection de secrets exposés, enrichissement multi-sources.
"""

import socket
import ssl
import re
import json
import hashlib
import datetime
import concurrent.futures
import requests
import urllib3

urllib3.disable_warnings()

# ─────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────

TIMEOUT = 4

# Services dangereux — exposition = risque immédiat
SERVICES_DANGEREUX = {
    21:    {"nom": "FTP",        "risque": "CRITIQUE", "raison": "Transfert en clair, auth anonyme possible"},
    23:    {"nom": "Telnet",     "risque": "CRITIQUE", "raison": "Protocole non chiffré — credentials en clair"},
    445:   {"nom": "SMB",        "risque": "CRITIQUE", "raison": "Exploitable EternalBlue/WannaCry si non patché"},
    3389:  {"nom": "RDP",        "risque": "CRITIQUE", "raison": "BlueKeep, brute-force, exposition directe"},
    1433:  {"nom": "MSSQL",      "risque": "HAUTE",    "raison": "Base de données exposée sur internet"},
    3306:  {"nom": "MySQL",      "risque": "HAUTE",    "raison": "Base de données exposée sur internet"},
    5432:  {"nom": "PostgreSQL", "risque": "HAUTE",    "raison": "Base de données exposée sur internet"},
    27017: {"nom": "MongoDB",    "risque": "CRITIQUE", "raison": "Souvent sans auth par défaut"},
    6379:  {"nom": "Redis",      "risque": "CRITIQUE", "raison": "Souvent sans auth — RCE possible"},
    9200:  {"nom": "Elasticsearch","risque":"CRITIQUE", "raison": "API ouverte sans auth par défaut"},
    11211: {"nom": "Memcached",  "risque": "HAUTE",    "raison": "Amplification DDoS + données exposées"},
    2375:  {"nom": "Docker API", "risque": "CRITIQUE", "raison": "Contrôle total du serveur si exposé"},
    5900:  {"nom": "VNC",        "risque": "CRITIQUE", "raison": "Accès bureau distant souvent mal protégé"},
    512:   {"nom": "rexec",      "risque": "CRITIQUE", "raison": "Protocole obsolète — exécution distante"},
    513:   {"nom": "rlogin",     "risque": "CRITIQUE", "raison": "Protocole obsolète sans chiffrement"},
}

# Endpoints sensibles à vérifier
ENDPOINTS_SENSIBLES = [
    ("/.git/config",           "CRITIQUE", "Code source Git exposé"),
    ("/.env",                  "CRITIQUE", "Variables d'environnement (API keys, passwords)"),
    ("/.env.backup",           "CRITIQUE", "Backup fichier .env"),
    ("/backup.sql",            "CRITIQUE", "Dump de base de données"),
    ("/dump.sql",              "CRITIQUE", "Dump de base de données"),
    ("/db.sql",                "CRITIQUE", "Dump de base de données"),
    ("/phpinfo.php",           "HAUTE",    "Informations serveur PHP sensibles"),
    ("/info.php",              "HAUTE",    "Informations serveur PHP"),
    ("/wp-config.php.bak",     "CRITIQUE", "Config WordPress sauvegardée"),
    ("/wp-config.php~",        "CRITIQUE", "Config WordPress temporaire"),
    ("/config.php.bak",        "CRITIQUE", "Fichier de configuration sauvegardé"),
    ("/.htpasswd",             "CRITIQUE", "Credentials Apache exposés"),
    ("/.DS_Store",             "MOYENNE",  "Métadonnées macOS — structure du projet"),
    ("/robots.txt",            "INFO",     "Chemins cachés révélés"),
    ("/sitemap.xml",           "INFO",     "Structure du site"),
    ("/api/swagger.json",      "HAUTE",    "Documentation API exposée"),
    ("/api/swagger.yaml",      "HAUTE",    "Documentation API exposée"),
    ("/swagger-ui.html",       "HAUTE",    "Interface Swagger exposée"),
    ("/actuator",              "CRITIQUE", "Spring Boot Actuator exposé"),
    ("/actuator/env",          "CRITIQUE", "Variables d'environnement Spring Boot"),
    ("/actuator/heapdump",     "CRITIQUE", "Dump mémoire JVM téléchargeable"),
    ("/server-status",         "HAUTE",    "Apache server-status exposé"),
    ("/server-info",           "HAUTE",    "Apache server-info exposé"),
    ("/.well-known/security.txt","INFO",   "Politique de sécurité déclarée"),
    ("/crossdomain.xml",       "MOYENNE",  "Politique cross-domain Flash/Adobe"),
    ("/elmah.axd",             "HAUTE",    "Logs d'erreurs ASP.NET exposés"),
    ("/trace.axd",             "HAUTE",    "Trace ASP.NET exposée"),
    ("/web.config.bak",        "CRITIQUE", "Config IIS sauvegardée"),
    ("/.svn/entries",          "HAUTE",    "Dépôt SVN exposé"),
    ("/admin",                 "MOYENNE",  "Interface admin détectée"),
    ("/administrator",         "MOYENNE",  "Interface admin Joomla détectée"),
    ("/phpmyadmin",            "HAUTE",    "phpMyAdmin exposé"),
    ("/adminer.php",           "HAUTE",    "Adminer DB exposé"),
    ("/jenkins",               "HAUTE",    "Jenkins CI/CD exposé"),
    ("/console",               "HAUTE",    "Console d'administration exposée"),
]

# Signatures de technologies
SIGNATURES_TECH = {
    "WordPress":   [r"wp-content", r"wp-includes", r"WordPress"],
    "Joomla":      [r"Joomla!", r"/components/com_"],
    "Drupal":      [r"Drupal", r"/sites/default/"],
    "Laravel":     [r"laravel_session", r"Laravel"],
    "Django":      [r"csrfmiddlewaretoken", r"Django"],
    "React":       [r"react\.js", r"react\.min\.js", r"__REACT"],
    "Angular":     [r"ng-version", r"angular\.js"],
    "jQuery":      [r"jquery[.-](\d+\.\d+\.\d+)"],
    "Bootstrap":   [r"bootstrap[.-](\d+\.\d+\.\d+)"],
    "PHP":         [r"X-Powered-By: PHP/([\d.]+)"],
    "ASP.NET":     [r"X-Powered-By: ASP\.NET", r"__VIEWSTATE"],
    "nginx":       [r"Server: nginx[/\s]?([\d.]+)?"],
    "Apache":      [r"Server: Apache[/\s]?([\d.]+)?"],
    "IIS":         [r"Server: Microsoft-IIS[/\s]?([\d.]+)?"],
    "Cloudflare":  [r"cf-ray", r"cloudflare"],
    "AWS":         [r"x-amz-", r"amazonaws\.com"],
}


# ─────────────────────────────────────────────
# 1. BANNER GRABBING AVANCÉ
# ─────────────────────────────────────────────

def grab_banner(ip: str, port: int) -> str:
    """Récupère la bannière d'un service sur un port donné."""
    probes = {
        80:   b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
        443:  b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
        21:   None,
        22:   None,
        25:   None,
        110:  None,
        143:  None,
        3306: None,
        6379: b"INFO\r\n",
        9200: b"GET / HTTP/1.0\r\n\r\n",
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, port))
            probe = probes.get(port, b"\r\n")
            if probe:
                s.send(probe)
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:300]
    except Exception:
        return ""


def extraire_version(service: str, banner: str) -> str:
    """Extrait la version d'un service depuis sa bannière."""
    patterns = {
        "SSH":   r"SSH-[\d.]+-(.+)",
        "FTP":   r"[\d]{3}[- ](.+)",
        "SMTP":  r"[\d]{3}[- ](.+)",
        "HTTP":  r"Server: (.+)",
        "MySQL": r"(\d+\.\d+\.\d+)",
        "Redis": r"redis_version:(.+)",
    }
    for nom, pattern in patterns.items():
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:80]
    # Pattern générique version X.Y.Z
    m = re.search(r"(\d+\.\d+[\.\d]*)", banner)
    if m:
        return m.group(1)
    return ""


# ─────────────────────────────────────────────
# 2. CVE LOOKUP — API NIST NVD
# ─────────────────────────────────────────────

def chercher_cves(keyword: str, max_results: int = 5) -> list:
    """
    Interroge l'API NIST NVD pour trouver les CVEs
    associées à un service/version.
    """
    if not keyword or len(keyword) < 3:
        return []
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "keywordSearch": keyword,
                "resultsPerPage": max_results,
            },
            timeout=8,
            headers={"User-Agent": "PySecOps-Scanner/2.0"}
        )
        if r.status_code != 200:
            return []
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
            # Score CVSS
            score = 0.0
            severite = "INCONNUE"
            metrics = cve.get("metrics", {})
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    cvss_data = metrics[version][0].get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severite = metrics[version][0].get("baseSeverity",
                               _score_to_severite(score))
                    break
            # Date de publication
            published = cve.get("published", "")[:10]
            cves.append({
                "id":       cve_id,
                "score":    score,
                "severite": severite.upper(),
                "desc":     desc[:200],
                "published": published,
                "url":      f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return sorted(cves, key=lambda x: x["score"], reverse=True)
    except Exception:
        return []


def _score_to_severite(score: float) -> str:
    if score >= 9.0: return "CRITIQUE"
    if score >= 7.0: return "HAUTE"
    if score >= 4.0: return "MOYENNE"
    if score > 0:    return "BASSE"
    return "INCONNUE"


# ─────────────────────────────────────────────
# 3. DÉTECTION DE TECHNOLOGIES
# ─────────────────────────────────────────────

def detecter_technologies(url: str) -> dict:
    """
    Détecte les technologies utilisées par un site web.
    Analyse headers HTTP + contenu HTML.
    """
    techs = {}
    headers_bruts = ""
    contenu = ""

    try:
        r = requests.get(
            url, timeout=8, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PySecOps/2.0)"},
            allow_redirects=True
        )
        headers_bruts = str(dict(r.headers))
        contenu = r.text[:50000]
        code_http = r.status_code

        # Analyser les headers + contenu
        texte_complet = headers_bruts + "\n" + contenu

        for tech, patterns in SIGNATURES_TECH.items():
            for pattern in patterns:
                m = re.search(pattern, texte_complet, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex else ""
                    techs[tech] = version.strip() if version else "détecté"
                    break

        # Headers de sécurité
        headers_securite = {
            "Content-Security-Policy":    r.headers.get("Content-Security-Policy"),
            "Strict-Transport-Security":  r.headers.get("Strict-Transport-Security"),
            "X-Frame-Options":            r.headers.get("X-Frame-Options"),
            "X-Content-Type-Options":     r.headers.get("X-Content-Type-Options"),
            "Referrer-Policy":            r.headers.get("Referrer-Policy"),
            "Permissions-Policy":         r.headers.get("Permissions-Policy"),
        }

        # Cookies sécurisés
        cookies_info = []
        for cookie in r.cookies:
            cookies_info.append({
                "nom":      cookie.name,
                "secure":   cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.get_nonstandard_attr("SameSite", "Non défini"),
            })

        return {
            "technologies":      techs,
            "code_http":         code_http,
            "headers_securite":  headers_securite,
            "cookies":           cookies_info,
            "server":            r.headers.get("Server", ""),
            "powered_by":        r.headers.get("X-Powered-By", ""),
            "redirect_url":      r.url,
        }
    except Exception as e:
        return {"erreur": str(e), "technologies": {}}


# ─────────────────────────────────────────────
# 4. DÉTECTION DE SECRETS EXPOSÉS
# ─────────────────────────────────────────────

def scanner_secrets(base_url: str) -> list:
    """
    Teste les endpoints sensibles sur un serveur web.
    Retourne la liste des fichiers/endpoints accessibles.
    """
    if not base_url.startswith("http"):
        base_url = "http://" + base_url
    base_url = base_url.rstrip("/")

    resultats = []

    def tester_endpoint(endpoint_info):
        chemin, severite, description = endpoint_info
        url = base_url + chemin
        try:
            r = requests.get(
                url, timeout=4, verify=False, allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; PySecOps/2.0)"}
            )
            if r.status_code in (200, 206):
                taille = len(r.content)
                extrait = r.text[:100].replace("\n", " ").strip()
                return {
                    "chemin":      chemin,
                    "url":         url,
                    "code":        r.status_code,
                    "taille":      taille,
                    "severite":    severite,
                    "description": description,
                    "extrait":     extrait,
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = [ex.submit(tester_endpoint, ep) for ep in ENDPOINTS_SENSIBLES]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                resultats.append(r)

    resultats.sort(
        key=lambda x: ["CRITIQUE","HAUTE","MOYENNE","INFO"].index(x["severite"])
        if x["severite"] in ["CRITIQUE","HAUTE","MOYENNE","INFO"] else 99
    )
    return resultats


# ─────────────────────────────────────────────
# 5. RÉPUTATION IP MULTI-SOURCES
# ─────────────────────────────────────────────

def enrichir_reputation(ip: str) -> dict:
    """
    Enrichit les informations d'une IP via plusieurs sources gratuites.
    """
    resultats = {}

    # Source 1 : AbuseIPDB (gratuit sans clé pour vérif basique)
    try:
        r = requests.get(
            f"https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={
                "Key": "ABUSEIPDB_KEY",
                "Accept": "application/json"
            },
            timeout=5
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            resultats["abuseipdb"] = {
                "score_abus":     d.get("abuseConfidenceScore", 0),
                "nb_rapports":    d.get("totalReports", 0),
                "pays":           d.get("countryCode", ""),
                "isp":            d.get("isp", ""),
                "est_tor":        d.get("isTor", False),
            }
    except Exception:
        pass

    # Source 2 : ipinfo.io (gratuit 50k req/mois)
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            d = r.json()
            resultats["ipinfo"] = {
                "org":      d.get("org", ""),
                "hostname": d.get("hostname", ""),
                "city":     d.get("city", ""),
                "region":   d.get("region", ""),
                "country":  d.get("country", ""),
                "timezone": d.get("timezone", ""),
            }
    except Exception:
        pass

    # Source 3 : Certificats SSL historiques via crt.sh
    try:
        r = requests.get(
            f"https://crt.sh/?q={ip}&output=json",
            timeout=8
        )
        if r.status_code == 200:
            certs = r.json()[:10]
            domaines = list(set(
                c.get("name_value", "").replace("*.","")
                for c in certs
                if c.get("name_value")
            ))
            resultats["crtsh"] = {"domaines_associes": domaines[:10]}
    except Exception:
        pass

    return resultats


# ─────────────────────────────────────────────
# 6. SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────

def enumerer_subdomains(domaine: str) -> dict:
    """
    Trouve les sous-domaines via :
    1. Certificate Transparency Logs (crt.sh) — passif
    2. Brute-force DNS sur wordlist commune
    """
    domaine = domaine.replace("https://","").replace("http://","").split("/")[0].strip()
    subdomains = set()

    # Source 1 : crt.sh (Certificate Transparency)
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domaine}&output=json",
            timeout=10
        )
        if r.status_code == 200:
            for cert in r.json():
                noms = cert.get("name_value","").split("\n")
                for nom in noms:
                    nom = nom.strip().lstrip("*.")
                    if nom.endswith(f".{domaine}") or nom == domaine:
                        subdomains.add(nom.lower())
    except Exception:
        pass

    # Source 2 : Brute-force DNS wordlist commune
    wordlist = [
        "www","mail","ftp","admin","vpn","api","dev","test","staging",
        "beta","app","shop","blog","forum","support","help","docs",
        "portal","dashboard","login","auth","secure","cdn","static",
        "assets","media","img","images","video","download","upload",
        "smtp","pop","imap","ns1","ns2","mx","remote","ssh","git",
        "gitlab","jenkins","jira","confluence","wiki","intranet",
        "extranet","web","server","host","cloud","monitor","status",
        "analytics","tracking","payment","checkout","store","m",
        "mobile","old","new","backup","db","database","mysql","redis",
        "elastic","kibana","grafana","prometheus","vault","consul",
    ]

    def tester_subdomain(sub):
        fqdn = f"{sub}.{domaine}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {"fqdn": fqdn, "ip": ip}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(tester_subdomain, sub) for sub in wordlist]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                subdomains.add(r["fqdn"])

    # Résolution IP pour chaque subdomain trouvé
    resultats = []
    for sub in sorted(subdomains):
        try:
            ip = socket.gethostbyname(sub)
            resultats.append({"fqdn": sub, "ip": ip})
        except Exception:
            resultats.append({"fqdn": sub, "ip": "non résolu"})

    return {
        "domaine":    domaine,
        "total":      len(resultats),
        "subdomains": resultats,
    }


# ─────────────────────────────────────────────
# 7. ATTACK SURFACE SCORING
# ─────────────────────────────────────────────

def calculer_attack_surface(scan_data: dict) -> dict:
    """
    Calcule un score de surface d'attaque global
    et génère les vecteurs d'attaque probables.
    """
    score = 0
    vecteurs = []
    recommandations = []

    ports_ouverts = scan_data.get("ports", [])
    cves_trouvees = scan_data.get("cves", [])
    secrets_trouves = scan_data.get("secrets", [])
    techs = scan_data.get("technologies", {})

    # Points par service dangereux exposé
    for port_info in ports_ouverts:
        port = port_info.get("port")
        if port in SERVICES_DANGEREUX:
            info = SERVICES_DANGEREUX[port]
            pts = 30 if info["risque"] == "CRITIQUE" else 20
            score += pts
            vecteurs.append({
                "etape":       f"Service {info['nom']} exposé (port {port})",
                "risque":      info["risque"],
                "detail":      info["raison"],
                "port":        port,
            })

    # Points par CVE critique
    for cve in cves_trouvees:
        cvss = cve.get("score", 0)
        if cvss >= 9.0:
            score += 25
            vecteurs.append({
                "etape":  f"{cve['id']} — CVSS {cvss}",
                "risque": "CRITIQUE",
                "detail": cve.get("desc", "")[:100],
                "url":    cve.get("url", ""),
            })
        elif cvss >= 7.0:
            score += 15

    # Points par secret exposé
    for secret in secrets_trouves:
        pts = {"CRITIQUE": 35, "HAUTE": 20, "MOYENNE": 10, "INFO": 2}
        score += pts.get(secret.get("severite", "INFO"), 2)
        vecteurs.append({
            "etape":  f"Fichier sensible : {secret['chemin']}",
            "risque": secret["severite"],
            "detail": secret["description"],
            "url":    secret.get("url",""),
        })

    # Recommandations
    if any(p.get("port") in [3306,5432,27017,6379] for p in ports_ouverts):
        recommandations.append({
            "priorite": "CRITIQUE",
            "action":   "Fermer immédiatement l'accès public aux bases de données",
            "detail":   "Utiliser un firewall ou VPN pour restreindre l'accès DB"
        })
    if any(p.get("port") == 23 for p in ports_ouverts):
        recommandations.append({
            "priorite": "CRITIQUE",
            "action":   "Désactiver Telnet — remplacer par SSH",
            "detail":   "Telnet transmet les credentials en clair sur le réseau"
        })
    if secrets_trouves:
        recommandations.append({
            "priorite": "CRITIQUE",
            "action":   f"Sécuriser {len(secrets_trouves)} fichier(s) sensible(s) exposé(s)",
            "detail":   "Configurer le serveur web pour bloquer l'accès à ces chemins"
        })
    if cves_trouvees:
        critiques = [c for c in cves_trouvees if c.get("score",0) >= 7.0]
        if critiques:
            recommandations.append({
                "priorite": "CRITIQUE",
                "action":   f"Patcher {len(critiques)} CVE(s) de sévérité haute/critique",
                "detail":   "Mettre à jour les services affectés immédiatement"
            })

    score = min(score, 100)
    if score >= 75:   niveau, couleur = "CRITIQUE", "red"
    elif score >= 50: niveau, couleur = "ÉLEVÉ",    "orange"
    elif score >= 25: niveau, couleur = "MODÉRÉ",   "yellow"
    else:             niveau, couleur = "FAIBLE",    "green"

    # Trier par risque
    ordre = ["CRITIQUE","HAUTE","MOYENNE","BASSE","INFO"]
    vecteurs.sort(key=lambda x: ordre.index(x["risque"])
                  if x["risque"] in ordre else 99)

    return {
        "score":             score,
        "niveau":            niveau,
        "couleur":           couleur,
        "nb_vecteurs":       len(vecteurs),
        "vecteurs":          vecteurs[:15],
        "recommandations":   recommandations,
    }


# ─────────────────────────────────────────────
# 8. SCAN COMPLET — ORCHESTRATEUR
# ─────────────────────────────────────────────

def scan_complet(cible: str) -> dict:
    """
    Lance un scan de reconnaissance complet sur une cible.
    Orchestre tous les modules en parallèle.
    """
    now = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    # Résoudre la cible
    domaine = cible.replace("https://","").replace("http://","").split("/")[0].strip()
    try:
        ip = socket.gethostbyname(domaine)
    except Exception:
        return {"erreur": f"Impossible de résoudre '{domaine}'"}

    # 1. Scan de ports rapide (top 100)
    from app.utils.recon_utils import SERVICES_DANGEREUX
    ports_ouverts = []

    def _scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.8)
                if s.connect_ex((ip, port)) == 0:
                    banner  = grab_banner(ip, port)
                    version = extraire_version("", banner)
                    service = {
                        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",
                        53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",
                        443:"HTTPS",445:"SMB",993:"IMAPS",1433:"MSSQL",
                        1723:"PPTP",3306:"MySQL",3389:"RDP",
                        5432:"PostgreSQL",5900:"VNC",6379:"Redis",
                        8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elasticsearch",
                        27017:"MongoDB",2375:"Docker-API",
                    }.get(port,"Unknown")
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

    TOP_PORTS = [
        21,22,23,25,53,80,110,135,139,143,443,445,
        465,587,993,995,1433,1723,3306,3389,5432,
        5900,6379,8080,8443,9200,27017,2375,11211,
        8888,9090,4848,7001,7002,8161,61616,
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(_scan_port, p) for p in TOP_PORTS]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                ports_ouverts.append(r)
    ports_ouverts.sort(key=lambda x: x["port"])

    # 2. CVE lookup pour les services détectés
    cves_totales = []
    services_detectes = set()
    for p in ports_ouverts:
        keyword = p["service"]
        if p.get("version"):
            keyword = f"{p['service']} {p['version']}"
        if keyword not in services_detectes:
            services_detectes.add(keyword)
            cves = chercher_cves(keyword, max_results=3)
            for cve in cves:
                cve["service_associe"] = p["service"]
                cve["port_associe"]    = p["port"]
            cves_totales.extend(cves)

    cves_totales.sort(key=lambda x: x.get("score",0), reverse=True)

    # 3. Technologies (si HTTP/HTTPS)
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

    # 4. Secrets exposés
    secrets = []
    if url_base:
        secrets = scanner_secrets(url_base)

    # 5. Attack surface score
    attack_surface = calculer_attack_surface({
        "ports":        ports_ouverts,
        "cves":         cves_totales,
        "secrets":      secrets,
        "technologies": techs.get("technologies", {}),
    })

    return {
        "cible":          cible,
        "domaine":        domaine,
        "ip":             ip,
        "date_scan":      now,
        "ports":          ports_ouverts,
        "nb_ports":       len(ports_ouverts),
        "cves":           cves_totales[:20],
        "nb_cves":        len(cves_totales),
        "technologies":   techs,
        "secrets":        secrets,
        "nb_secrets":     len(secrets),
        "attack_surface": attack_surface,
    }
