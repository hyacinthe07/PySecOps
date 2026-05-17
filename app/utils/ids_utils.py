"""
PySecOps — IDS Engine / Forensique
Analyse réelle de logs Apache, Nginx, SSH.
Détection de patterns d'attaque, corrélation temporelle,
extraction d'IOC, timeline d'intrusion.
"""

import re
import datetime
from collections import defaultdict, Counter
from typing import Optional


# ─────────────────────────────────────────────
# PATTERNS D'ATTAQUE — signatures réelles
# ─────────────────────────────────────────────

PATTERNS_ATTAQUE = [
    # Injections Web
    {
        "id":       "WEB-001",
        "nom":      "Injection SQL",
        "severite": "CRITIQUE",
        "categorie":"Injection",
        "regex":    r"(?i)(union\s+select|select\s+\*\s+from|drop\s+table|insert\s+into|"
                    r"or\s+1=1|and\s+1=1|benchmark\s*\(|sleep\s*\(|waitfor\s+delay|"
                    r"load_file\s*\(|into\s+outfile|information_schema|xp_cmdshell)",
    },
    {
        "id":       "WEB-002",
        "nom":      "Cross-Site Scripting (XSS)",
        "severite": "HAUTE",
        "categorie":"Injection",
        "regex":    r"(?i)(<script|javascript:|onerror=|onload=|onclick=|"
                    r"alert\s*\(|document\.cookie|eval\s*\(|fromcharcode)",
    },
    {
        "id":       "WEB-003",
        "nom":      "Local File Inclusion (LFI)",
        "severite": "CRITIQUE",
        "categorie":"Path Traversal",
        "regex":    r"(?i)(\.\.\/\.\.\/|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|"
                    r"/proc/self|/var/log|boot\.ini|win\.ini|system32)",
    },
    {
        "id":       "WEB-004",
        "nom":      "Remote File Inclusion (RFI)",
        "severite": "CRITIQUE",
        "categorie":"Injection",
        "regex":    r"(?i)(https?://[^/]+/.*\.(php|txt|sh|pl|py)|"
                    r"=https?://|=ftp://)",
    },
    {
        "id":       "WEB-005",
        "nom":      "Command Injection",
        "severite": "CRITIQUE",
        "categorie":"Injection",
        "regex":    r"(?i)(;ls\s|;id\s|;whoami|;cat\s|;wget\s|;curl\s|"
                    r"\|ls\s|\|id\s|\|whoami|\|cat\s|`id`|`whoami`|"
                    r"&&id|&&ls|&&whoami|\$\(id\)|\$\(ls\))",
    },
    {
        "id":       "WEB-006",
        "nom":      "Server-Side Template Injection (SSTI)",
        "severite": "CRITIQUE",
        "categorie":"Injection",
        "regex":    r"(\{\{.*\}\}|\{%.*%\}|\${.*}|<%.*%>|"
                    r"\{\{7\*7\}\}|\{\{config\}\})",
    },
    {
        "id":       "WEB-007",
        "nom":      "XXE Injection",
        "severite": "HAUTE",
        "categorie":"Injection",
        "regex":    r"(?i)(<!entity|system\s*['\"]|SYSTEM\s*['\"]|"
                    r"file:///|/etc/passwd)",
    },
    # Reconnaissance & Scan
    {
        "id":       "RECON-001",
        "nom":      "Scan de répertoires (DirBuster/Gobuster)",
        "severite": "MOYENNE",
        "categorie":"Reconnaissance",
        "regex":    r"(?i)(gobuster|dirbuster|dirb\s|nikto|nmap|masscan|"
                    r"sqlmap|wpscan|joomscan|whatweb|nuclei|ffuf|feroxbuster)",
    },
    {
        "id":       "RECON-002",
        "nom":      "Accès fichiers sensibles",
        "severite": "HAUTE",
        "categorie":"Reconnaissance",
        "regex":    r"(?i)(\.env|\.git/|wp-config|phpinfo|"
                    r"\.htpasswd|\.htaccess|backup\.sql|dump\.sql|"
                    r"adminer\.php|phpmyadmin|web\.config|"
                    r"actuator/env|actuator/heapdump|swagger\.json)",
    },
    {
        "id":       "RECON-003",
        "nom":      "User-Agent malveillant/scanner",
        "severite": "MOYENNE",
        "categorie":"Reconnaissance",
        "regex":    r"(?i)(sqlmap|nikto|nessus|openvas|masscan|"
                    r"python-requests|go-http-client|curl/[0-9]|"
                    r"zgrab|shodan|censys|binaryedge)",
    },
    # Authentification
    {
        "id":       "AUTH-001",
        "nom":      "Brute-force HTTP (401 répétés)",
        "severite": "HAUTE",
        "categorie":"Authentification",
        "regex":    r'" 401 ',
    },
    {
        "id":       "AUTH-002",
        "nom":      "Accès interfaces admin",
        "severite": "MOYENNE",
        "categorie":"Authentification",
        "regex":    r"(?i)(/(admin|administrator|wp-admin|login|signin|"
                    r"wp-login\.php|manager/html|console|dashboard|"
                    r"panel|cpanel|plesk|webmail))",
    },
    # Exploitation
    {
        "id":       "EXP-001",
        "nom":      "Tentative Shellshock",
        "severite": "CRITIQUE",
        "categorie":"Exploitation",
        "regex":    r"\(\)\s*\{[^}]*\}\s*;",
    },
    {
        "id":       "EXP-002",
        "nom":      "Log4Shell (CVE-2021-44228)",
        "severite": "CRITIQUE",
        "categorie":"Exploitation",
        "regex":    r"(?i)(\$\{jndi:|jndi:ldap|jndi:rmi|jndi:dns|"
                    r"\$\{lower:|lower:j\})",
    },
    {
        "id":       "EXP-003",
        "nom":      "Path Traversal Windows",
        "severite": "HAUTE",
        "categorie":"Exploitation",
        "regex":    r"(?i)(\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e/|"
                    r"\.\.%252f|%c0%ae|%c1%9c)",
    },
    {
        "id":       "EXP-004",
        "nom":      "Spring4Shell (CVE-2022-22965)",
        "severite": "CRITIQUE",
        "categorie":"Exploitation",
        "regex":    r"(?i)(class\.module\.classLoader|"
                    r"class\[module\]\[classLoader\])",
    },
    # SSH
    {
        "id":       "SSH-001",
        "nom":      "Échec authentification SSH",
        "severite": "MOYENNE",
        "categorie":"Authentification",
        "regex":    r"(?i)(Failed password|Invalid user|"
                    r"authentication failure|Connection closed by|"
        r"Did not receive identification string)",
    },
    {
        "id":       "SSH-002",
        "nom":      "Succès connexion SSH inhabituel",
        "severite": "HAUTE",
        "categorie":"Authentification",
        "regex":    r"(?i)(Accepted password|Accepted publickey|"
                    r"session opened for user root)",
    },
]

# Formats de log supportés
FORMATS_LOG = {
    "apache_combined": (
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+'
        r'\[(?P<date>[^\]]+)\]\s+'
        r'"(?P<methode>\S+)\s+(?P<url>\S+)\s+\S+"\s+'
        r'(?P<code>\d{3})\s+(?P<taille>\S+)'
        r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    ),
    "nginx": (
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+'
        r'\[(?P<date>[^\]]+)\]\s+'
        r'"(?P<methode>\S+)?\s*(?P<url>\S+)?\s*\S*"\s+'
        r'(?P<code>\d{3})\s+(?P<taille>\d+)'
    ),
    "ssh": (
        r'(?P<date>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<host>\S+)\s+\S+:\s+(?P<message>.+)'
    ),
    "brut": r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})',
}


# ─────────────────────────────────────────────
# PARSER DE LOGS
# ─────────────────────────────────────────────

def parser_logs(texte: str) -> dict:
    """
    Parse un fichier de log et détecte le format automatiquement.
    """
    lignes = [l.strip() for l in texte.splitlines() if l.strip()]
    if not lignes:
        return {"erreur": "Fichier vide."}

    # Détecter le format
    format_detecte = "brut"
    for nom, pattern in FORMATS_LOG.items():
        if nom == "brut":
            continue
        matches = sum(1 for l in lignes[:20] if re.match(pattern, l))
        if matches >= 5:
            format_detecte = nom
            break

    # Parser chaque ligne
    entrees = []
    pattern = FORMATS_LOG[format_detecte]

    for ligne in lignes:
        m = re.match(pattern, ligne)
        if m:
            d = m.groupdict()
            entrees.append({
                "ip":      d.get("ip", ""),
                "date":    d.get("date", ""),
                "methode": d.get("methode", ""),
                "url":     d.get("url", d.get("message", "")),
                "code":    d.get("code", ""),
                "ua":      d.get("ua", ""),
                "ligne":   ligne,
            })
        else:
            # Extraction minimale
            ip_m = re.search(r'\d{1,3}(?:\.\d{1,3}){3}', ligne)
            entrees.append({
                "ip":    ip_m.group(0) if ip_m else "",
                "url":   ligne,
                "ligne": ligne,
                "code":  "",
                "date":  "",
                "methode":"",
                "ua":    "",
            })

    return {
        "format":   format_detecte,
        "total":    len(lignes),
        "parsees":  len(entrees),
        "entrees":  entrees,
    }


# ─────────────────────────────────────────────
# DÉTECTION D'ATTAQUES
# ─────────────────────────────────────────────

def detecter_attaques(entrees: list) -> list:
    """
    Applique tous les patterns d'attaque sur les entrées parsées.
    """
    alertes = []

    for entree in entrees:
        texte_complet = entree.get("ligne", "") + " " + entree.get("ua", "")

        for pattern in PATTERNS_ATTAQUE:
            if re.search(pattern["regex"], texte_complet):
                alertes.append({
                    "id":       pattern["id"],
                    "nom":      pattern["nom"],
                    "severite": pattern["severite"],
                    "categorie":pattern["categorie"],
                    "ip":       entree.get("ip", ""),
                    "url":      entree.get("url", "")[:200],
                    "code":     entree.get("code", ""),
                    "date":     entree.get("date", ""),
                    "methode":  entree.get("methode", ""),
                    "ua":       entree.get("ua", "")[:100],
                    "ligne":    entree.get("ligne", "")[:300],
                })

    return alertes


# ─────────────────────────────────────────────
# DÉTECTION BRUTE-FORCE (corrélation temporelle)
# ─────────────────────────────────────────────

def detecter_bruteforce(entrees: list) -> list:
    """
    Détecte les tentatives de brute-force par IP.
    Seuil : 10+ requêtes en erreur (401/403/404) par IP.
    """
    ip_echecs = defaultdict(list)

    for e in entrees:
        code = e.get("code", "")
        ip   = e.get("ip", "")
        if ip and code in ("401","403","400"):
            ip_echecs[ip].append({
                "code": code,
                "url":  e.get("url",""),
                "date": e.get("date",""),
            })

    resultats = []
    for ip, echecs in ip_echecs.items():
        if len(echecs) >= 10:
            codes = Counter(e["code"] for e in echecs)
            resultats.append({
                "ip":          ip,
                "nb_echecs":   len(echecs),
                "codes":       dict(codes),
                "severite":    "CRITIQUE" if len(echecs) >= 50 else "HAUTE",
                "type":        "Brute-force HTTP",
                "premier":     echecs[0].get("date",""),
                "dernier":     echecs[-1].get("date",""),
                "urls_cibles": list(set(e["url"] for e in echecs[:5])),
            })

    resultats.sort(key=lambda x: x["nb_echecs"], reverse=True)
    return resultats


# ─────────────────────────────────────────────
# EXTRACTION D'IOC
# ─────────────────────────────────────────────

def extraire_ioc(entrees: list, alertes: list) -> dict:
    """
    Extrait les Indicators of Compromise depuis les logs.
    IOC : IPs malveillantes, URLs suspects, User-Agents malveillants.
    """
    # IPs dans les alertes
    ips_malveillantes = Counter()
    urls_suspectes    = set()
    uas_suspects      = set()
    patterns_detectes = Counter()

    for a in alertes:
        if a.get("ip"):
            ips_malveillantes[a["ip"]] += 1
        if a.get("url"):
            urls_suspectes.add(a["url"][:150])
        if a.get("ua"):
            uas_suspects.add(a["ua"])
        patterns_detectes[a["nom"]] += 1

    # Top requêtes en erreur
    codes_erreur = Counter()
    for e in entrees:
        code = e.get("code","")
        if code and code.startswith(("4","5")):
            codes_erreur[code] += 1

    # Top User-Agents
    top_uas = Counter(
        e.get("ua","") for e in entrees
        if e.get("ua")
    ).most_common(5)

    return {
        "ips_malveillantes": [
            {"ip": ip, "nb_alertes": nb}
            for ip, nb in ips_malveillantes.most_common(15)
        ],
        "urls_suspectes":    list(urls_suspectes)[:20],
        "uas_suspects":      list(uas_suspects)[:10],
        "patterns_detectes": dict(patterns_detectes.most_common(10)),
        "codes_erreur":      dict(codes_erreur.most_common(8)),
        "top_uas":           top_uas,
    }


# ─────────────────────────────────────────────
# TIMELINE D'ATTAQUE
# ─────────────────────────────────────────────

def construire_timeline(alertes: list) -> list:
    """
    Reconstruit la chronologie des événements suspects.
    Regroupe par IP et ordre chronologique.
    """
    # Grouper par IP
    par_ip = defaultdict(list)
    for a in alertes:
        if a.get("ip"):
            par_ip[a["ip"]].append(a)

    timeline = []
    for ip, events in par_ip.items():
        if len(events) < 2:
            continue

        categories = list(set(e["categorie"] for e in events))
        severites  = [e["severite"] for e in events]
        max_sev    = (
            "CRITIQUE" if "CRITIQUE" in severites else
            "HAUTE"    if "HAUTE"    in severites else
            "MOYENNE"
        )

        # Détecter la progression d'attaque
        progression = []
        cats_order  = ["Reconnaissance","Authentification","Injection","Path Traversal","Exploitation"]
        for cat in cats_order:
            if cat in categories:
                progression.append(cat)

        timeline.append({
            "ip":          ip,
            "nb_events":   len(events),
            "categories":  categories,
            "progression": progression,
            "severite":    max_sev,
            "est_apt":     len(progression) >= 3,
            "events":      sorted(
                events,
                key=lambda x: x.get("date","")
            )[:8],
        })

    timeline.sort(key=lambda x: x["nb_events"], reverse=True)
    return timeline[:10]


# ─────────────────────────────────────────────
# STATISTIQUES GLOBALES
# ─────────────────────────────────────────────

def calculer_stats(entrees: list, alertes: list) -> dict:
    """Calcule les statistiques globales de l'analyse."""
    total = len(entrees)

    # Répartition des codes HTTP
    codes = Counter(e.get("code","?") for e in entrees if e.get("code"))

    # Top IPs
    top_ips = Counter(e.get("ip","") for e in entrees if e.get("ip")).most_common(10)

    # Alertes par sévérité
    sev = Counter(a["severite"] for a in alertes)

    # Alertes par catégorie
    cats = Counter(a["categorie"] for a in alertes)

    # Score de menace global
    score = min(
        sev.get("CRITIQUE",0) * 25 +
        sev.get("HAUTE",0)    * 15 +
        sev.get("MOYENNE",0)  * 5,
        100
    )

    if score >= 75:   niveau, couleur = "CRITIQUE", "red"
    elif score >= 40: niveau, couleur = "ÉLEVÉ",    "orange"
    elif score >= 15: niveau, couleur = "MODÉRÉ",   "yellow"
    else:             niveau, couleur = "FAIBLE",    "green"

    return {
        "total_lignes":    total,
        "total_alertes":   len(alertes),
        "nb_critique":     sev.get("CRITIQUE",0),
        "nb_haute":        sev.get("HAUTE",0),
        "nb_moyenne":      sev.get("MOYENNE",0),
        "top_ips":         [{"ip":ip,"nb":nb} for ip,nb in top_ips],
        "codes_http":      dict(codes.most_common(8)),
        "alertes_par_cat": dict(cats.most_common()),
        "score_menace":    score,
        "niveau_menace":   niveau,
        "couleur_menace":  couleur,
    }


# ─────────────────────────────────────────────
# ORCHESTRATEUR PRINCIPAL
# ─────────────────────────────────────────────

def analyser_complet(texte: str) -> dict:
    """
    Lance l'analyse IDS complète sur un fichier de log.
    """
    # 1. Parser
    parsed = parser_logs(texte)
    if "erreur" in parsed:
        return parsed

    entrees = parsed["entrees"]

    # 2. Détecter les attaques
    alertes = detecter_attaques(entrees)

    # 3. Détecter le brute-force
    bruteforce = detecter_bruteforce(entrees)

    # 4. Extraire les IOC
    ioc = extraire_ioc(entrees, alertes)

    # 5. Construire la timeline
    timeline = construire_timeline(alertes)

    # 6. Statistiques globales
    stats = calculer_stats(entrees, alertes)

    return {
        "format":     parsed["format"],
        "total":      parsed["total"],
        "parsees":    parsed["parsees"],
        "alertes":    alertes[:100],
        "bruteforce": bruteforce,
        "ioc":        ioc,
        "timeline":   timeline,
        "stats":      stats,
        "date_analyse": datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
    }
