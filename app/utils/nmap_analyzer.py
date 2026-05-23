"""
PySecOps — Analyseur Nmap XML intelligent
Lit un fichier XML Nmap et produit une analyse complète :
- Services détectés avec versions
- CVEs associées via NIST NVD
- Score de risque global
- Recommandations en français
- Vecteurs d'attaque probables
"""

import defusedxml.ElementTree as ET
import requests
import datetime
import re


# ─────────────────────────────────────────────
# SERVICES DANGEREUX — explication en français
# ─────────────────────────────────────────────
SERVICES_DANGEREUX = {
    "ftp":        {"risque": "CRITIQUE", "raison": "Protocole non chiffré — credentials transmis en clair"},
    "telnet":     {"risque": "CRITIQUE", "raison": "Protocole non chiffré — remplacez par SSH immédiatement"},
    "smb":        {"risque": "CRITIQUE", "raison": "Exploitable via EternalBlue/WannaCry si non patché"},
    "rdp":        {"risque": "CRITIQUE", "raison": "Exposé à BlueKeep et aux attaques brute-force"},
    "mysql":      {"risque": "HAUTE",    "raison": "Base de données exposée directement sur internet"},
    "postgresql": {"risque": "HAUTE",    "raison": "Base de données exposée directement sur internet"},
    "mongodb":    {"risque": "CRITIQUE", "raison": "Souvent sans authentification par défaut"},
    "redis":      {"risque": "CRITIQUE", "raison": "Sans authentification par défaut — RCE possible"},
    "elasticsearch":{"risque":"CRITIQUE","raison": "API ouverte sans authentification par défaut"},
    "docker":     {"risque": "CRITIQUE", "raison": "Contrôle total du serveur si API exposée"},
    "vnc":        {"risque": "CRITIQUE", "raison": "Accès bureau distant souvent mal protégé"},
    "memcached":  {"risque": "HAUTE",    "raison": "Amplification DDoS + données exposées"},
}

RECOMMANDATIONS_PAR_SERVICE = {
    "ftp":     "Désactivez FTP et utilisez SFTP ou SCP à la place.",
    "telnet":  "Désactivez Telnet immédiatement. Utilisez SSH avec authentification par clé.",
    "smb":     "Appliquez les patches MS17-010. Désactivez SMBv1. Bloquez le port 445 sur internet.",
    "rdp":     "Placez RDP derrière un VPN. Activez NLA. Changez le port par défaut.",
    "mysql":   "N'exposez jamais MySQL sur internet. Utilisez un tunnel SSH ou VPN.",
    "postgresql":"N'exposez jamais PostgreSQL sur internet. Configurez pg_hba.conf correctement.",
    "mongodb": "Activez l'authentification MongoDB. Ne l'exposez pas sur internet.",
    "redis":   "Configurez requirepass dans redis.conf. Liez à 127.0.0.1 uniquement.",
    "elasticsearch":"Activez X-Pack Security. Ne l'exposez jamais sans authentification.",
    "docker":  "Ne jamais exposer l'API Docker. Utilisez Unix socket uniquement.",
    "vnc":     "Utilisez VNC uniquement via tunnel SSH. Activez l'authentification.",
    "memcached":"Liez à 127.0.0.1. N'exposez jamais Memcached sur internet.",
}


# ─────────────────────────────────────────────
# PARSER XML NMAP
# ─────────────────────────────────────────────

def parser_nmap_xml(contenu_xml: str) -> dict:
    """
    Parse un fichier XML Nmap et extrait toutes les informations.
    Supporte les formats : nmap -oX, nmap -oA
    """
    try:
        root = ET.fromstring(contenu_xml)
    except Exception as e:
        return {"erreur": f"Fichier XML invalide : {e}"}

    # Infos générales du scan
    args       = root.get("args", "")
    start_time = root.get("startstr", "")
    version    = root.get("version", "")

    # Stats du scan
    runstats = root.find("runstats")
    nb_hosts_total = 0
    nb_hosts_up    = 0
    if runstats is not None:
        hosts_elem = runstats.find("hosts")
        if hosts_elem is not None:
            nb_hosts_total = int(hosts_elem.get("total", 0))
            nb_hosts_up    = int(hosts_elem.get("up", 0))

    hotes = []

    for host in root.findall("host"):
        # Statut de l'hôte
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Adresses IP et MAC
        adresses = {}
        for addr in host.findall("address"):
            adresses[addr.get("addrtype")] = addr.get("addr")

        ip  = adresses.get("ipv4", adresses.get("ipv6", "inconnu"))
        mac = adresses.get("mac", "")

        # Nom d'hôte
        hostnames_elem = host.find("hostnames")
        hostname = ""
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        # OS
        os_info = ""
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_info = osmatch.get("name", "")

        # Ports
        ports_info = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id   = port.get("portid")
                protocol  = port.get("protocol", "tcp")

                service_elem = port.find("service")
                service_nom  = ""
                service_prod = ""
                service_ver  = ""
                service_extra= ""
                tunnel       = ""
                cpe_list     = []

                if service_elem is not None:
                    service_nom   = service_elem.get("name", "")
                    service_prod  = service_elem.get("product", "")
                    service_ver   = service_elem.get("version", "")
                    service_extra = service_elem.get("extrainfo", "")
                    tunnel        = service_elem.get("tunnel", "")
                    for cpe in service_elem.findall("cpe"):
                        cpe_list.append(cpe.text)

                # Scripts Nmap
                scripts = {}
                for script in port.findall("script"):
                    scripts[script.get("id")] = script.get("output", "")

                # Service dangereux ?
                est_dangereux = False
                raison_danger = ""
                for kw, info in SERVICES_DANGEREUX.items():
                    if kw in service_nom.lower() or kw in service_prod.lower():
                        est_dangereux = True
                        raison_danger = info["raison"]
                        break

                ports_info.append({
                    "port":       int(port_id),
                    "protocol":   protocol,
                    "service":    service_nom,
                    "produit":    service_prod,
                    "version":    service_ver,
                    "extra":      service_extra,
                    "tunnel":     tunnel,
                    "cpes":       cpe_list,
                    "scripts":    scripts,
                    "dangereux":  est_dangereux,
                    "raison":     raison_danger,
                })

        ports_info.sort(key=lambda x: x["port"])

        hotes.append({
            "ip":       ip,
            "mac":      mac,
            "hostname": hostname,
            "os":       os_info,
            "ports":    ports_info,
            "nb_ports": len(ports_info),
        })

    return {
        "args":          args,
        "start_time":    start_time,
        "version_nmap":  version,
        "nb_hosts_total":nb_hosts_total,
        "nb_hosts_up":   nb_hosts_up,
        "hotes":         hotes,
        "nb_hotes":      len(hotes),
    }


# ─────────────────────────────────────────────
# CVE LOOKUP NIST NVD
# ─────────────────────────────────────────────

def chercher_cves_service(produit: str, version: str, max_results: int = 3) -> list:
    """Cherche les CVEs pour un service/version via NIST NVD."""
    if not produit:
        return []

    keyword = produit
    if version:
        keyword = f"{produit} {version}"

    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            timeout=8,
            headers={"User-Agent": "PySecOps/3.0"}
        )
        if r.status_code != 200:
            return []

        cves = []
        for item in r.json().get("vulnerabilities", []):
            cve  = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs  = cve.get("descriptions", [])
            desc   = next((d["value"] for d in descs if d["lang"] == "en"), "")

            score    = 0.0
            severite = "INCONNUE"
            metrics  = cve.get("metrics", {})
            for v in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if v in metrics and metrics[v]:
                    d = metrics[v][0]
                    score    = d.get("cvssData", {}).get("baseScore", 0.0)
                    severite = d.get("baseSeverity", _score_to_sev(score))
                    break

            cves.append({
                "id":       cve_id,
                "score":    score,
                "severite": severite.upper(),
                "desc":     desc[:200],
                "url":      f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        return sorted(cves, key=lambda x: x["score"], reverse=True)

    except Exception:
        return []


def _score_to_sev(score: float) -> str:
    if score >= 9.0: return "CRITIQUE"
    if score >= 7.0: return "HAUTE"
    if score >= 4.0: return "MOYENNE"
    if score > 0:    return "BASSE"
    return "INCONNUE"


# ─────────────────────────────────────────────
# ANALYSE INTELLIGENTE COMPLÈTE
# ─────────────────────────────────────────────

def analyser_nmap_complet(contenu_xml: str) -> dict:
    """
    Analyse complète d'un fichier Nmap XML :
    1. Parse le XML
    2. Lookup CVEs pour chaque service
    3. Calcule le score de risque global
    4. Génère les recommandations en français
    5. Identifie les vecteurs d'attaque probables
    """
    # 1. Parser le XML
    parsed = parser_nmap_xml(contenu_xml)
    if "erreur" in parsed:
        return parsed

    tous_les_ports    = []
    tous_les_services = set()
    toutes_cves       = []
    recommandations   = []
    vecteurs          = []
    services_vus      = set()

    # 2. Pour chaque hôte et chaque port
    for hote in parsed["hotes"]:
        for port in hote["ports"]:
            tous_les_ports.append(port)

            service_key = f"{port['produit']} {port['version']}".strip()
            if not service_key:
                service_key = port["service"]

            # CVEs (une seule requête par service unique)
            if service_key and service_key not in services_vus and port["produit"]:
                services_vus.add(service_key)
                cves = chercher_cves_service(port["produit"], port["version"])
                for cve in cves:
                    cve["service"]  = port["produit"]
                    cve["port"]     = port["port"]
                    cve["hote"]     = hote["ip"]
                toutes_cves.extend(cves)

            # Service dangereux → vecteur d'attaque
            if port["dangereux"]:
                vecteurs.append({
                    "port":    port["port"],
                    "service": port["produit"] or port["service"],
                    "hote":    hote["ip"],
                    "risque":  "CRITIQUE",
                    "detail":  port["raison"],
                })

                # Recommandation
                for kw, reco in RECOMMANDATIONS_PAR_SERVICE.items():
                    if kw in port["service"].lower() or kw in port["produit"].lower():
                        if reco not in recommandations:
                            recommandations.append({
                                "priorite": "CRITIQUE",
                                "service":  port["produit"] or port["service"],
                                "port":     port["port"],
                                "action":   reco,
                            })
                        break

    # Trier les CVEs par score
    toutes_cves.sort(key=lambda x: x["score"], reverse=True)

    # 3. Score de risque global
    nb_dangereux  = len(vecteurs)
    nb_cves_crit  = sum(1 for c in toutes_cves if c["score"] >= 9.0)
    nb_cves_haute = sum(1 for c in toutes_cves if 7.0 <= c["score"] < 9.0)

    score = min(
        nb_dangereux  * 20 +
        nb_cves_crit  * 25 +
        nb_cves_haute * 10 +
        len(tous_les_ports) * 2,
        100
    )

    if score >= 75:   niveau, couleur = "CRITIQUE", "red"
    elif score >= 50: niveau, couleur = "ÉLEVÉ",    "orange"
    elif score >= 25: niveau, couleur = "MODÉRÉ",   "yellow"
    else:             niveau, couleur = "FAIBLE",   "green"

    # 4. Résumé en français
    resume = _generer_resume(parsed, tous_les_ports, toutes_cves, vecteurs, score, niveau)

    return {
        "scan":           parsed,
        "ports":          tous_les_ports,
        "nb_ports":       len(tous_les_ports),
        "cves":           toutes_cves[:20],
        "nb_cves":        len(toutes_cves),
        "vecteurs":       vecteurs,
        "recommandations":recommandations,
        "score":          score,
        "niveau":         niveau,
        "couleur":        couleur,
        "resume":         resume,
        "date_analyse":   datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
    }


def _generer_resume(parsed, ports, cves, vecteurs, score, niveau) -> str:
    """Génère un résumé en français clair et actionnable."""
    nb_hotes  = parsed["nb_hotes"]
    nb_ports  = len(ports)
    nb_cves   = len(cves)
    nb_danger = len(vecteurs)

    resume = f"L'analyse du scan Nmap a couvert {nb_hotes} hôte(s) "
    resume += f"avec {nb_ports} port(s) ouvert(s) détecté(s).\n\n"

    if nb_danger > 0:
        services = list(set(v["service"] for v in vecteurs))[:3]
        resume += f"⚠️ {nb_danger} service(s) dangereux détecté(s) : "
        resume += ", ".join(services) + ".\n"
        resume += "Ces services exposent directement votre infrastructure à des attaques.\n\n"

    if nb_cves > 0:
        cves_critiques = [c for c in cves if c["score"] >= 9.0]
        resume += f"💀 {nb_cves} CVE(s) identifiée(s)"
        if cves_critiques:
            resume += f", dont {len(cves_critiques)} critique(s) "
            resume += f"(ex: {cves_critiques[0]['id']} - CVSS {cves_critiques[0]['score']})"
        resume += ".\n\n"

    if niveau == "CRITIQUE":
        resume += "🚨 NIVEAU CRITIQUE — Des actions immédiates sont nécessaires "
        resume += "pour sécuriser cette infrastructure."
    elif niveau == "ÉLEVÉ":
        resume += "⚠️ NIVEAU ÉLEVÉ — Plusieurs vulnérabilités importantes requièrent "
        resume += "une attention rapide."
    elif niveau == "MODÉRÉ":
        resume += "⚡ NIVEAU MODÉRÉ — Des améliorations sont recommandées "
        resume += "mais le risque immédiat est limité."
    else:
        resume += "✅ NIVEAU FAIBLE — L'infrastructure semble correctement configurée. "
        resume += "Continuez à appliquer les mises à jour régulièrement."

    return resume
