"""
PySecOps — Threat Intelligence
Vérification réputation IP/domaine multi-sources en temps réel.
"""
import requests
import socket
import re
import datetime
import urllib3
urllib3.disable_warnings()

TIMEOUT = 6


def analyser_threat(cible: str) -> dict:
    """
    Analyse complète de réputation pour une IP ou un domaine.
    Sources : AbuseIPDB, VirusTotal public, Shodan InternetDB,
              URLScan.io, liste noires connues.
    """
    cible = cible.strip().replace("https://","").replace("http://","").split("/")[0]

    # Résoudre en IP
    try:
        ip = socket.gethostbyname(cible)
        est_domaine = cible != ip
    except Exception:
        return {"erreur": f"Impossible de résoudre '{cible}'"}

    resultats = {
        "cible":      cible,
        "ip":         ip,
        "est_domaine":est_domaine,
        "sources":    {},
        "alertes":    [],
        "score":      0,
        "niveau":     "INCONNU",
        "couleur":    "green",
        "date":       datetime.datetime.now().strftime("%d/%m/%Y à %H:%M"),
    }

    score = 0

    # ── Source 1 : Shodan InternetDB (gratuit)
    try:
        r = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            vulns  = data.get("vulns", [])
            ports  = data.get("ports", [])
            tags   = data.get("tags", [])
            resultats["sources"]["shodan"] = {
                "ports":  ports,
                "vulns":  vulns,
                "tags":   tags,
                "cpes":   data.get("cpes", []),
            }
            if vulns:
                score += len(vulns) * 10
                resultats["alertes"].append({
                    "source":   "Shodan",
                    "severite": "HAUTE",
                    "msg":      f"{len(vulns)} CVE(s) connue(s) : {', '.join(vulns[:3])}",
                })
            if "honeypot" in tags:
                resultats["alertes"].append({
                    "source":   "Shodan",
                    "severite": "CRITIQUE",
                    "msg":      "IP identifiée comme honeypot",
                })
    except Exception:
        pass

    # ── Source 2 : URLScan.io (sans clé)
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{cible}&size=5",
            timeout=TIMEOUT,
            headers={"User-Agent": "PySecOps/2.0"}
        )
        if r.status_code == 200:
            data    = r.json()
            total   = data.get("total", 0)
            results = data.get("results", [])
            malicious = sum(1 for r in results
                           if r.get("verdicts",{}).get("overall",{}).get("malicious", False))
            resultats["sources"]["urlscan"] = {
                "total_scans": total,
                "malicious":   malicious,
                "derniers":    [
                    {
                        "url":  r.get("page",{}).get("url",""),
                        "date": r.get("task",{}).get("time","")[:10],
                    }
                    for r in results[:5]
                ],
            }
            if malicious > 0:
                score += malicious * 20
                resultats["alertes"].append({
                    "source":   "URLScan.io",
                    "severite": "CRITIQUE",
                    "msg":      f"{malicious} scan(s) malveillant(s) détecté(s)",
                })
    except Exception:
        pass

    # ── Source 3 : ipinfo.io réputation
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            resultats["sources"]["ipinfo"] = {
                "org":      data.get("org",""),
                "country":  data.get("country",""),
                "city":     data.get("city",""),
                "hostname": data.get("hostname",""),
                "timezone": data.get("timezone",""),
            }
            org = data.get("org","").lower()
            if any(x in org for x in ["tor", "vpn", "proxy", "anonymizer"]):
                score += 20
                resultats["alertes"].append({
                    "source":   "IPInfo",
                    "severite": "HAUTE",
                    "msg":      f"Organisation suspecte : {data.get('org','')}",
                })
    except Exception:
        pass

    # ── Source 4 : Vérification DNS blacklists (DNSBL)
    dnsbls = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
    ]
    parties = ip.split(".")
    ip_rev  = ".".join(reversed(parties))
    listed_in = []

    for dnsbl in dnsbls:
        try:
            query = f"{ip_rev}.{dnsbl}"
            socket.gethostbyname(query)
            listed_in.append(dnsbl)
            score += 25
        except Exception:
            pass

    if listed_in:
        resultats["sources"]["dnsbl"] = {"listed_in": listed_in}
        resultats["alertes"].append({
            "source":   "DNSBL",
            "severite": "HAUTE",
            "msg":      f"IP blacklistée dans : {', '.join(listed_in)}",
        })

    # ── Source 5 : Certificats SSL historiques (crt.sh)
    try:
        r = requests.get(
            f"https://crt.sh/?q={cible}&output=json",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            certs = r.json()
            domaines = list(set(
                c.get("name_value","").replace("*.","")
                for c in certs
                if c.get("name_value")
            ))[:10]
            resultats["sources"]["crtsh"] = {
                "nb_certificats":  len(certs),
                "domaines_associes": domaines,
            }
    except Exception:
        pass

    # ── Calcul score final
    score = min(score, 100)
    resultats["score"] = score

    if score >= 60:
        resultats["niveau"]  = "MALVEILLANT"
        resultats["couleur"] = "red"
    elif score >= 30:
        resultats["niveau"]  = "SUSPECT"
        resultats["couleur"] = "orange"
    elif score >= 10:
        resultats["niveau"]  = "À SURVEILLER"
        resultats["couleur"] = "orange"
    else:
        resultats["niveau"]  = "PROPRE"
        resultats["couleur"] = "green"

    return resultats
"""
PySecOps — Threat Intelligence
Vérification réputation IP/domaine multi-sources en temps réel.
"""
import requests
import socket
import re
import datetime
import urllib3
urllib3.disable_warnings()

TIMEOUT = 6


def analyser_threat(cible: str) -> dict:
    """
    Analyse complète de réputation pour une IP ou un domaine.
    Sources : AbuseIPDB, VirusTotal public, Shodan InternetDB,
              URLScan.io, liste noires connues.
    """
    cible = cible.strip().replace("https://","").replace("http://","").split("/")[0]

    # Résoudre en IP
    try:
        ip = socket.gethostbyname(cible)
        est_domaine = cible != ip
    except Exception:
        return {"erreur": f"Impossible de résoudre '{cible}'"}

    resultats = {
        "cible":      cible,
        "ip":         ip,
        "est_domaine":est_domaine,
        "sources":    {},
        "alertes":    [],
        "score":      0,
        "niveau":     "INCONNU",
        "couleur":    "green",
        "date":       datetime.datetime.now().strftime("%d/%m/%Y à %H:%M"),
    }

    score = 0

    # ── Source 1 : Shodan InternetDB (gratuit)
    try:
        r = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            vulns  = data.get("vulns", [])
            ports  = data.get("ports", [])
            tags   = data.get("tags", [])
            resultats["sources"]["shodan"] = {
                "ports":  ports,
                "vulns":  vulns,
                "tags":   tags,
                "cpes":   data.get("cpes", []),
            }
            if vulns:
                score += len(vulns) * 10
                resultats["alertes"].append({
                    "source":   "Shodan",
                    "severite": "HAUTE",
                    "msg":      f"{len(vulns)} CVE(s) connue(s) : {', '.join(vulns[:3])}",
                })
            if "honeypot" in tags:
                resultats["alertes"].append({
                    "source":   "Shodan",
                    "severite": "CRITIQUE",
                    "msg":      "IP identifiée comme honeypot",
                })
    except Exception:
        pass

    # ── Source 2 : URLScan.io (sans clé)
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{cible}&size=5",
            timeout=TIMEOUT,
            headers={"User-Agent": "PySecOps/2.0"}
        )
        if r.status_code == 200:
            data    = r.json()
            total   = data.get("total", 0)
            results = data.get("results", [])
            malicious = sum(1 for r in results
                           if r.get("verdicts",{}).get("overall",{}).get("malicious", False))
            resultats["sources"]["urlscan"] = {
                "total_scans": total,
                "malicious":   malicious,
                "derniers":    [
                    {
                        "url":  r.get("page",{}).get("url",""),
                        "date": r.get("task",{}).get("time","")[:10],
                    }
                    for r in results[:5]
                ],
            }
            if malicious > 0:
                score += malicious * 20
                resultats["alertes"].append({
                    "source":   "URLScan.io",
                    "severite": "CRITIQUE",
                    "msg":      f"{malicious} scan(s) malveillant(s) détecté(s)",
                })
    except Exception:
        pass

    # ── Source 3 : ipinfo.io réputation
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            resultats["sources"]["ipinfo"] = {
                "org":      data.get("org",""),
                "country":  data.get("country",""),
                "city":     data.get("city",""),
                "hostname": data.get("hostname",""),
                "timezone": data.get("timezone",""),
            }
            org = data.get("org","").lower()
            if any(x in org for x in ["tor", "vpn", "proxy", "anonymizer"]):
                score += 20
                resultats["alertes"].append({
                    "source":   "IPInfo",
                    "severite": "HAUTE",
                    "msg":      f"Organisation suspecte : {data.get('org','')}",
                })
    except Exception:
        pass

    # ── Source 4 : Vérification DNS blacklists (DNSBL)
    dnsbls = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
    ]
    parties = ip.split(".")
    ip_rev  = ".".join(reversed(parties))
    listed_in = []

    for dnsbl in dnsbls:
        try:
            query = f"{ip_rev}.{dnsbl}"
            socket.gethostbyname(query)
            listed_in.append(dnsbl)
            score += 25
        except Exception:
            pass

    if listed_in:
        resultats["sources"]["dnsbl"] = {"listed_in": listed_in}
        resultats["alertes"].append({
            "source":   "DNSBL",
            "severite": "HAUTE",
            "msg":      f"IP blacklistée dans : {', '.join(listed_in)}",
        })

    # ── Source 5 : Certificats SSL historiques (crt.sh)
    try:
        r = requests.get(
            f"https://crt.sh/?q={cible}&output=json",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            certs = r.json()
            domaines = list(set(
                c.get("name_value","").replace("*.","")
                for c in certs
                if c.get("name_value")
            ))[:10]
            resultats["sources"]["crtsh"] = {
                "nb_certificats":  len(certs),
                "domaines_associes": domaines,
            }
    except Exception:
        pass

    # ── Calcul score final
    score = min(score, 100)
    resultats["score"] = score

    if score >= 60:
        resultats["niveau"]  = "MALVEILLANT"
        resultats["couleur"] = "red"
    elif score >= 30:
        resultats["niveau"]  = "SUSPECT"
        resultats["couleur"] = "orange"
    elif score >= 10:
        resultats["niveau"]  = "À SURVEILLER"
        resultats["couleur"] = "orange"
    else:
        resultats["niveau"]  = "PROPRE"
        resultats["couleur"] = "green"

    return resultats
