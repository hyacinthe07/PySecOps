"""
PySecOps — Scanner de vulnérabilités actif
Tests réels : SQLi, XSS, LFI, RFI, SSTI, Open Redirect,
crawler de liens, détection de services.
"""
import requests
import re
import socket
import urllib.parse
import concurrent.futures
import datetime
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings()

TIMEOUT = 6
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; PySecOps-Scanner/2.0)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ─────────────────────────────────────────────
# PAYLOADS DE TEST
# ─────────────────────────────────────────────

PAYLOADS_SQLI = [
    ("'", "SQLi basique — apostrophe"),
    ("' OR '1'='1", "SQLi — OR toujours vrai"),
    ("' OR 1=1 --", "SQLi — commentaire SQL"),
    ("'; DROP TABLE users; --", "SQLi — drop table"),
    ("' UNION SELECT NULL,NULL,NULL --", "SQLi — UNION"),
    ("1' AND SLEEP(3) --", "SQLi — time-based blind"),
    ("\" OR \"\"=\"", "SQLi double quote"),
    ("1 OR 1=1", "SQLi numérique"),
]

PAYLOADS_XSS = [
    ("<script>alert('XSS')</script>", "XSS basique script"),
    ("<img src=x onerror=alert('XSS')>", "XSS img onerror"),
    ("javascript:alert('XSS')", "XSS javascript:"),
    ("'><script>alert(1)</script>", "XSS break quote"),
    ("<svg onload=alert(1)>", "XSS SVG"),
    ("<iframe src=javascript:alert('XSS')>", "XSS iframe"),
    ("{{7*7}}", "SSTI — template injection"),
    ("${7*7}", "SSTI — expression"),
]

PAYLOADS_LFI = [
    ("../../../etc/passwd", "LFI Unix classique"),
    ("....//....//....//etc/passwd", "LFI double dot"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "LFI URL encoded"),
    ("../../../windows/win.ini", "LFI Windows"),
    ("php://filter/convert.base64-encode/resource=index.php", "LFI PHP wrapper"),
    ("/proc/self/environ", "LFI proc environ"),
]

PAYLOADS_OPEN_REDIRECT = [
    ("https://evil.com", "Open Redirect direct"),
    ("//evil.com", "Open Redirect protocol-relative"),
    ("/\\evil.com", "Open Redirect backslash"),
    ("https:evil.com", "Open Redirect no slashes"),
]

# Signatures d'erreurs SQL dans les réponses
SIGNATURES_SQLI = [
    r"sql syntax.*mysql", r"warning.*mysql_", r"valid mysql result",
    r"mysqlclient\.", r"postgresql.*error", r"warning.*pg_",
    r"sqlite.*exception", r"sqlite3.*operationalerror",
    r"ora-[0-9]{5}", r"oracle.*driver", r"sqlserver.*driver",
    r"microsoft.*ole db.*sql", r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"syntax error.*sql", r"sql command not properly ended",
    r"you have an error in your sql syntax",
    r"warning.*mssql_", r"jdbc.*exception", r"sqlexception",
]

# ─────────────────────────────────────────────
# 1. CRAWLER — collecte les URLs et paramètres
# ─────────────────────────────────────────────

def crawler(url_base: str, profondeur: int = 2) -> dict:
    """
    Crawle le site pour collecter :
    - Tous les liens internes
    - Tous les formulaires avec leurs champs
    - Tous les paramètres GET
    """
    if not url_base.startswith("http"):
        url_base = "http://" + url_base

    domaine = urllib.parse.urlparse(url_base).netloc
    visitees = set()
    a_visiter = {url_base}
    liens = []
    formulaires = []
    params_get = []

    for _ in range(profondeur):
        nouvelle_vague = set()
        for url in list(a_visiter)[:20]:  # max 20 par niveau
            if url in visitees:
                continue
            visitees.add(url)
            try:
                r = requests.get(
                    url, timeout=TIMEOUT, verify=False,
                    headers=HEADERS, allow_redirects=True
                )
                soup = BeautifulSoup(r.text, 'html.parser')

                # Collecter les liens
                for tag in soup.find_all('a', href=True):
                    href = tag['href']
                    href_abs = urllib.parse.urljoin(url, href)
                    parsed = urllib.parse.urlparse(href_abs)

                    if parsed.netloc == domaine:
                        liens.append(href_abs)
                        nouvelle_vague.add(href_abs)

                        # Extraire paramètres GET
                        if parsed.query:
                            params = urllib.parse.parse_qs(parsed.query)
                            for param in params:
                                params_get.append({
                                    "url":   href_abs,
                                    "param": param,
                                    "valeur":params[param][0] if params[param] else "",
                                })

                # Collecter les formulaires
                for form in soup.find_all('form'):
                    action = form.get('action', url)
                    methode = form.get('method', 'get').upper()
                    action_abs = urllib.parse.urljoin(url, action)
                    champs = []
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        nom = inp.get('name', '')
                        typ = inp.get('type', 'text')
                        if nom and typ not in ('hidden', 'submit', 'button',
                                               'checkbox', 'radio', 'file'):
                            champs.append({
                                "nom": nom,
                                "type": typ,
                            })
                    if champs:
                        formulaires.append({
                            "url":     action_abs,
                            "methode": methode,
                            "champs":  champs,
                            "page":    url,
                        })

            except Exception:
                pass

        a_visiter = nouvelle_vague - visitees

    return {
        "url_base":    url_base,
        "domaine":     domaine,
        "nb_pages":    len(visitees),
        "liens":       list(set(liens))[:50],
        "formulaires": formulaires[:20],
        "params_get":  params_get[:30],
    }


# ─────────────────────────────────────────────
# 2. TEST SQLi
# ─────────────────────────────────────────────

def tester_sqli_param(url: str, param: str, valeur: str) -> list:
    """Teste les injections SQL sur un paramètre GET."""
    vulns = []
    parsed = urllib.parse.urlparse(url)
    params_base = urllib.parse.parse_qs(parsed.query)

    for payload, description in PAYLOADS_SQLI:
        try:
            params_test = {k: v[0] for k, v in params_base.items()}
            params_test[param] = payload

            new_query = urllib.parse.urlencode(params_test)
            url_test  = urllib.parse.urlunparse(
                parsed._replace(query=new_query)
            )

            r = requests.get(
                url_test, timeout=TIMEOUT, verify=False,
                headers=HEADERS, allow_redirects=False
            )

            # Détecter les erreurs SQL dans la réponse
            corps = r.text.lower()
            for signature in SIGNATURES_SQLI:
                if re.search(signature, corps, re.I):
                    vulns.append({
                        "type":        "SQL Injection",
                        "severite":    "CRITIQUE",
                        "url":         url_test,
                        "parametre":   param,
                        "payload":     payload,
                        "description": description,
                        "evidence":    f"Erreur SQL détectée : {signature}",
                        "cvss":        "9.8",
                    })
                    break

        except Exception:
            pass

    return vulns


def tester_sqli_form(form: dict) -> list:
    """Teste les injections SQL sur un formulaire."""
    vulns = []
    for payload, description in PAYLOADS_SQLI[:4]:
        try:
            data = {c["nom"]: payload for c in form["champs"]}

            if form["methode"] == "POST":
                r = requests.post(
                    form["url"], data=data, timeout=TIMEOUT,
                    verify=False, headers=HEADERS, allow_redirects=False
                )
            else:
                r = requests.get(
                    form["url"], params=data, timeout=TIMEOUT,
                    verify=False, headers=HEADERS, allow_redirects=False
                )

            corps = r.text.lower()
            for signature in SIGNATURES_SQLI:
                if re.search(signature, corps, re.I):
                    vulns.append({
                        "type":        "SQL Injection (formulaire)",
                        "severite":    "CRITIQUE",
                        "url":         form["url"],
                        "parametre":   ", ".join(c["nom"] for c in form["champs"]),
                        "payload":     payload,
                        "description": description,
                        "evidence":    f"Erreur SQL dans réponse formulaire",
                        "cvss":        "9.8",
                    })
                    break

        except Exception:
            pass

    return vulns


# ─────────────────────────────────────────────
# 3. TEST XSS
# ─────────────────────────────────────────────

def tester_xss_param(url: str, param: str) -> list:
    """Teste XSS sur un paramètre GET."""
    vulns = []
    parsed = urllib.parse.urlparse(url)
    params_base = urllib.parse.parse_qs(parsed.query)

    for payload, description in PAYLOADS_XSS[:5]:
        try:
            params_test = {k: v[0] for k, v in params_base.items()}
            params_test[param] = payload

            new_query = urllib.parse.urlencode(params_test)
            url_test  = urllib.parse.urlunparse(
                parsed._replace(query=new_query)
            )

            r = requests.get(
                url_test, timeout=TIMEOUT, verify=False,
                headers=HEADERS, allow_redirects=False
            )

            # Vérifier si le payload est reflété non-échappé
            if payload in r.text and '<script>' not in r.text.lower().replace(
                payload.lower(), ''
            ):
                vulns.append({
                    "type":        "XSS Réfléchi",
                    "severite":    "HAUTE",
                    "url":         url_test,
                    "parametre":   param,
                    "payload":     payload,
                    "description": description,
                    "evidence":    "Payload reflété dans la réponse sans échappement",
                    "cvss":        "7.4",
                })
                break

        except Exception:
            pass

    return vulns


# ─────────────────────────────────────────────
# 4. TEST LFI
# ─────────────────────────────────────────────

def tester_lfi_param(url: str, param: str) -> list:
    """Teste LFI sur un paramètre GET."""
    vulns = []
    parsed = urllib.parse.urlparse(url)
    params_base = urllib.parse.parse_qs(parsed.query)

    for payload, description in PAYLOADS_LFI:
        try:
            params_test = {k: v[0] for k, v in params_base.items()}
            params_test[param] = payload

            new_query = urllib.parse.urlencode(params_test)
            url_test  = urllib.parse.urlunparse(
                parsed._replace(query=new_query)
            )

            r = requests.get(
                url_test, timeout=TIMEOUT, verify=False,
                headers=HEADERS, allow_redirects=False
            )

            # Signatures de succès LFI
            if any(sig in r.text for sig in [
                'root:x:0:0', '[boot loader]', 'daemon:x:',
                '<?php', 'HTTP_USER_AGENT'
            ]):
                vulns.append({
                    "type":        "LFI — Local File Inclusion",
                    "severite":    "CRITIQUE",
                    "url":         url_test,
                    "parametre":   param,
                    "payload":     payload,
                    "description": description,
                    "evidence":    "Contenu de fichier système détecté dans la réponse",
                    "cvss":        "9.1",
                })
                break

        except Exception:
            pass

    return vulns


# ─────────────────────────────────────────────
# 5. TEST OPEN REDIRECT
# ─────────────────────────────────────────────

def tester_open_redirect(url: str, param: str) -> list:
    """Teste Open Redirect sur les paramètres de redirection."""
    mots_cles_redirect = [
        'url', 'redirect', 'return', 'next', 'goto',
        'link', 'target', 'redir', 'destination', 'to'
    ]

    if not any(k in param.lower() for k in mots_cles_redirect):
        return []

    vulns = []
    parsed = urllib.parse.urlparse(url)
    params_base = urllib.parse.parse_qs(parsed.query)

    for payload, description in PAYLOADS_OPEN_REDIRECT[:2]:
        try:
            params_test = {k: v[0] for k, v in params_base.items()}
            params_test[param] = payload

            new_query = urllib.parse.urlencode(params_test)
            url_test  = urllib.parse.urlunparse(
                parsed._replace(query=new_query)
            )

            r = requests.get(
                url_test, timeout=TIMEOUT, verify=False,
                headers=HEADERS, allow_redirects=False
            )

            location = r.headers.get('Location', '')
            if r.status_code in (301, 302, 303, 307, 308):
                if 'evil.com' in location:
                    vulns.append({
                        "type":        "Open Redirect",
                        "severite":    "MOYENNE",
                        "url":         url_test,
                        "parametre":   param,
                        "payload":     payload,
                        "description": description,
                        "evidence":    f"Redirection vers : {location}",
                        "cvss":        "6.1",
                    })
                    break

        except Exception:
            pass

    return vulns


# ─────────────────────────────────────────────
# 6. TEST SSTI
# ─────────────────────────────────────────────

def tester_ssti_param(url: str, param: str) -> list:
    """Teste SSTI — Server-Side Template Injection."""
    vulns = []
    parsed = urllib.parse.urlparse(url)
    params_base = urllib.parse.parse_qs(parsed.query)

    payloads_ssti = [
        ("{{7*7}}", "49", "Jinja2/Twig SSTI"),
        ("${7*7}", "49", "FreeMarker/Thymeleaf SSTI"),
        ("<%= 7*7 %>", "49", "ERB/ASP SSTI"),
        ("#{7*7}", "49", "Ruby SSTI"),
    ]

    for payload, expected, description in payloads_ssti:
        try:
            params_test = {k: v[0] for k, v in params_base.items()}
            params_test[param] = payload

            new_query = urllib.parse.urlencode(params_test)
            url_test  = urllib.parse.urlunparse(
                parsed._replace(query=new_query)
            )

            r = requests.get(
                url_test, timeout=TIMEOUT, verify=False,
                headers=HEADERS, allow_redirects=False
            )

            if expected in r.text:
                vulns.append({
                    "type":        "SSTI — Template Injection",
                    "severite":    "CRITIQUE",
                    "url":         url_test,
                    "parametre":   param,
                    "payload":     payload,
                    "description": description,
                    "evidence":    f"Expression évaluée → résultat {expected} dans la réponse",
                    "cvss":        "9.8",
                })
                break

        except Exception:
            pass

    return vulns


# ─────────────────────────────────────────────
# 7. SCAN DE PORTS AVEC IDENTIFICATION SERVICES
# ─────────────────────────────────────────────

SERVICES_COMPLETS = {
    21:   {"nom":"FTP",           "dangereux":True,  "raison":"Non chiffré, auth anonyme possible"},
    22:   {"nom":"SSH",           "dangereux":False, "raison":""},
    23:   {"nom":"Telnet",        "dangereux":True,  "raison":"Non chiffré — credentials en clair"},
    25:   {"nom":"SMTP",          "dangereux":False, "raison":""},
    53:   {"nom":"DNS",           "dangereux":False, "raison":""},
    80:   {"nom":"HTTP",          "dangereux":False, "raison":""},
    110:  {"nom":"POP3",          "dangereux":False, "raison":""},
    135:  {"nom":"RPC",           "dangereux":True,  "raison":"Vecteur d'exploitation Windows"},
    139:  {"nom":"NetBIOS",       "dangereux":True,  "raison":"Enumération réseau Windows"},
    143:  {"nom":"IMAP",          "dangereux":False, "raison":""},
    443:  {"nom":"HTTPS",         "dangereux":False, "raison":""},
    445:  {"nom":"SMB",           "dangereux":True,  "raison":"EternalBlue/WannaCry si non patché"},
    1433: {"nom":"MSSQL",         "dangereux":True,  "raison":"Base de données exposée"},
    1521: {"nom":"Oracle DB",     "dangereux":True,  "raison":"Base de données exposée"},
    2375: {"nom":"Docker API",    "dangereux":True,  "raison":"Contrôle total du serveur"},
    2376: {"nom":"Docker TLS",    "dangereux":True,  "raison":"Docker avec TLS"},
    3306: {"nom":"MySQL",         "dangereux":True,  "raison":"Base de données exposée"},
    3389: {"nom":"RDP",           "dangereux":True,  "raison":"BlueKeep, brute-force direct"},
    5432: {"nom":"PostgreSQL",    "dangereux":True,  "raison":"Base de données exposée"},
    5900: {"nom":"VNC",           "dangereux":True,  "raison":"Accès bureau distant"},
    5984: {"nom":"CouchDB",       "dangereux":True,  "raison":"Souvent sans auth"},
    6379: {"nom":"Redis",         "dangereux":True,  "raison":"Sans auth par défaut → RCE"},
    7001: {"nom":"WebLogic",      "dangereux":True,  "raison":"Nombreuses RCEs critiques"},
    8080: {"nom":"HTTP-Alt",      "dangereux":False, "raison":""},
    8443: {"nom":"HTTPS-Alt",     "dangereux":False, "raison":""},
    8888: {"nom":"Jupyter",       "dangereux":True,  "raison":"Notebooks Python sans auth"},
    9200: {"nom":"Elasticsearch", "dangereux":True,  "raison":"API ouverte sans auth"},
    9300: {"nom":"Elasticsearch-Cluster","dangereux":True,"raison":"Cluster exposé"},
    11211:{"nom":"Memcached",     "dangereux":True,  "raison":"Amplification DDoS"},
    27017:{"nom":"MongoDB",       "dangereux":True,  "raison":"Sans auth par défaut"},
    27018:{"nom":"MongoDB-Shard", "dangereux":True,  "raison":"Sans auth par défaut"},
    50000:{"nom":"SAP",           "dangereux":True,  "raison":"Interface SAP exposée"},
}


def identifier_service_complet(ip: str, port: int) -> dict:
    """
    Identification complète d'un service :
    bannière, version, protocole, niveau de risque.
    """
    info_service = SERVICES_COMPLETS.get(port, {"nom":"Unknown", "dangereux":False, "raison":""})
    resultat = {
        "port":      port,
        "service":   info_service["nom"],
        "dangereux": info_service["dangereux"],
        "risque":    info_service["raison"],
        "banner":    "",
        "version":   "",
        "protocole": "TCP",
        "ssl":       False,
        "detail":    {},
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ip, port))

            # Probes par service
            probes = {
                21:   None,             # FTP envoie banner automatiquement
                22:   None,             # SSH envoie banner automatiquement
                25:   None,             # SMTP envoie banner automatiquement
                80:   b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n",
                110:  None,             # POP3
                143:  None,             # IMAP
                6379: b"INFO\r\n",      # Redis
                9200: b"GET / HTTP/1.0\r\n\r\n",  # Elasticsearch
            }

            probe = probes.get(port, b"\r\n")
            if probe:
                s.send(probe)

            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            resultat["banner"] = banner[:200]

            # Extraction de version
            version_patterns = {
                "SSH":   r"SSH-[\d.]+-(.+)",
                "FTP":   r"220[- ](.+)",
                "SMTP":  r"220[- ](.+)",
                "HTTP":  r"Server: (.+)",
                "MySQL": r"(\d+\.\d+\.\d+)",
                "Redis": r"redis_version:(.+)",
            }

            for nom, pattern in version_patterns.items():
                if nom.lower() in info_service["nom"].lower() or nom == "HTTP":
                    m = re.search(pattern, banner, re.I)
                    if m:
                        resultat["version"] = m.group(1).strip()[:80]
                        break

            # Détails spécifiques
            if port == 6379 and "redis_version" in banner:
                lines = dict(l.split(":", 1) for l in banner.split('\n')
                            if ':' in l)
                resultat["detail"] = {
                    "version":  lines.get("redis_version",""),
                    "os":       lines.get("os",""),
                    "auth":     "non" if "requirepass" not in banner else "oui",
                }

            if port == 9200 and banner:
                try:
                    import json
                    data = json.loads(banner.split('\r\n\r\n', 1)[-1])
                    resultat["detail"] = {
                        "cluster": data.get("cluster_name",""),
                        "version": data.get("version",{}).get("number",""),
                    }
                except Exception:
                    pass

    except Exception:
        pass

    # Vérification SSL/TLS
    if port in (443, 8443, 465, 993, 995, 636):
        try:
            import ssl
            ctx = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    resultat["ssl"]  = True
                    resultat["detail"]["tls"] = ssock.version()
                    subj = dict(x[0] for x in cert.get("subject", []))
                    resultat["detail"]["cn"] = subj.get("commonName", "")
        except Exception:
            pass

    return resultat


def scan_ports_complet(cible: str, port_range: int = 1024) -> dict:
    """Scan complet avec identification de chaque service."""
    try:
        ip = socket.gethostbyname(cible)
    except Exception:
        return {"erreur": f"Impossible de résoudre '{cible}'"}

    ports_ouverts = []

    def _scan(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    # Scan rapide d'abord
    ports_detectes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        futures = [ex.submit(_scan, p) for p in range(1, port_range + 1)]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                ports_detectes.append(r)

    # Identification complète de chaque port ouvert
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(identifier_service_complet, ip, p)
                  for p in sorted(ports_detectes)]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                ports_ouverts.append(r)

    ports_ouverts.sort(key=lambda x: x["port"])

    nb_dangereux = sum(1 for p in ports_ouverts if p["dangereux"])
    score = min(nb_dangereux * 20 + len(ports_ouverts) * 2, 100)

    if score >= 60:   niveau, couleur = "CRITIQUE", "red"
    elif score >= 30: niveau, couleur = "ÉLEVÉ",    "orange"
    else:             niveau, couleur = "FAIBLE",    "green"

    return {
        "cible":       cible,
        "ip":          ip,
        "ports":       ports_ouverts,
        "total":       len(ports_ouverts),
        "range":       port_range,
        "nb_dangereux":nb_dangereux,
        "score":       score,
        "niveau":      niveau,
        "couleur":     couleur,
        "date":        datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
    }


# ─────────────────────────────────────────────
# 8. ORCHESTRATEUR — SCAN VULNÉRABILITÉS COMPLET
# ─────────────────────────────────────────────

def scanner_vulnerabilites(url: str) -> dict:
    """
    Lance un scan de vulnérabilités complet sur une URL.
    1. Crawl du site
    2. Test SQLi sur tous les paramètres
    3. Test XSS sur tous les paramètres
    4. Test LFI sur les paramètres suspects
    5. Test SSTI
    6. Test Open Redirect
    """
    if not url.startswith("http"):
        url = "http://" + url

    vulnerabilites = []
    stats = {"sqli": 0, "xss": 0, "lfi": 0, "ssti": 0, "redirect": 0}

    # 1. Crawler
    crawl = crawler(url, profondeur=2)

    # 2. Tester chaque paramètre GET
    def tester_parametre(param_info):
        resultats = []
        u = param_info["url"]
        p = param_info["param"]
        resultats += tester_sqli_param(u, p, param_info.get("valeur",""))
        resultats += tester_xss_param(u, p)
        resultats += tester_lfi_param(u, p)
        resultats += tester_ssti_param(u, p)
        resultats += tester_open_redirect(u, p)
        return resultats

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(tester_parametre, p) for p in crawl["params_get"]]
        for f in concurrent.futures.as_completed(futures):
            for vuln in f.result():
                vulnerabilites.append(vuln)
                t = vuln["type"].lower()
                if "sql" in t:     stats["sqli"] += 1
                elif "xss" in t:   stats["xss"] += 1
                elif "lfi" in t:   stats["lfi"] += 1
                elif "ssti" in t:  stats["ssti"] += 1
                elif "redirect" in t: stats["redirect"] += 1

    # 3. Tester les formulaires (SQLi + XSS)
    for form in crawl["formulaires"][:10]:
        vulns_form = tester_sqli_form(form)
        for v in vulns_form:
            vulnerabilites.append(v)
            stats["sqli"] += 1

    # Déduplication
    vus = set()
    vulns_uniques = []
    for v in vulnerabilites:
        cle = f"{v['type']}:{v['url']}:{v['parametre']}"
        if cle not in vus:
            vus.add(cle)
            vulns_uniques.append(v)

    # Score de criticité
    score = min(
        sum(25 for v in vulns_uniques if v["severite"] == "CRITIQUE") +
        sum(15 for v in vulns_uniques if v["severite"] == "HAUTE") +
        sum(5  for v in vulns_uniques if v["severite"] == "MOYENNE"),
        100
    )

    if score >= 60:   niveau, couleur = "CRITIQUE", "red"
    elif score >= 30: niveau, couleur = "ÉLEVÉ",    "orange"
    elif score > 0:   niveau, couleur = "MODÉRÉ",   "orange"
    else:             niveau, couleur = "AUCUNE VULNÉRABILITÉ", "green"

    return {
        "url":             url,
        "crawl":           crawl,
        "vulnerabilites":  vulns_uniques,
        "nb_vulns":        len(vulns_uniques),
        "stats":           stats,
        "score":           score,
        "niveau":          niveau,
        "couleur":         couleur,
        "date":            datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
    }
