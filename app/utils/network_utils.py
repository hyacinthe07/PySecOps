"""
PySecOps — Utilitaires réseau
WHOIS, DNS, géolocalisation IP, réputation.
"""

import socket
import datetime
from typing import Optional


# ─────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────

def analyser_whois(domaine: str) -> dict:
    """
    Récupère les informations WHOIS d'un domaine.
    Retourne : registrant, dates, registrar, nameservers, statuts.
    """
    try:
        import whois as w
    except ImportError:
        return {"erreur": "Module python-whois non installé. Lancez : pip install python-whois"}

    domaine = domaine.replace("https://", "").replace("http://", "").split("/")[0].strip()

    try:
        data = w.whois(domaine)
    except Exception as e:
        return {"erreur": f"WHOIS introuvable pour '{domaine}' : {e}"}

    def fmt_date(d):
        if d is None:
            return "—"
        if isinstance(d, list):
            d = d[0]
        if isinstance(d, datetime.datetime):
            return d.strftime("%d/%m/%Y")
        return str(d)[:10]

    def safe(val, fallback="—"):
        if val is None:
            return fallback
        if isinstance(val, list):
            val = val[0] if val else fallback
        return str(val).strip() or fallback

    creation    = fmt_date(data.creation_date)
    expiration  = fmt_date(data.expiration_date)
    updated     = fmt_date(data.updated_date)

    # Jours avant expiration
    jours_exp = None
    try:
        exp_dt = data.expiration_date
        if isinstance(exp_dt, list):
            exp_dt = exp_dt[0]
        if exp_dt:
            jours_exp = (exp_dt - datetime.datetime.utcnow()).days
    except Exception:
        pass

    nameservers = data.name_servers or []
    if isinstance(nameservers, str):
        nameservers = [nameservers]
    nameservers = sorted(set(ns.lower() for ns in nameservers))[:8]

    statuts = data.status or []
    if isinstance(statuts, str):
        statuts = [statuts]

    # Alertes
    alertes = []
    if jours_exp is not None:
        if jours_exp < 0:
            alertes.append({"type": "CRITIQUE", "msg": f"Domaine expiré depuis {abs(jours_exp)} jours"})
        elif jours_exp < 14:
            alertes.append({"type": "CRITIQUE", "msg": f"Expiration dans {jours_exp} jours — URGENT"})
        elif jours_exp < 30:
            alertes.append({"type": "HAUTE",    "msg": f"Expiration dans {jours_exp} jours"})
        elif jours_exp < 60:
            alertes.append({"type": "MOYENNE",  "msg": f"Expiration dans {jours_exp} jours — planifiez le renouvellement"})

    if not any("clientTransferProhibited" in s for s in statuts):
        alertes.append({"type": "BASSE", "msg": "Protection anti-transfert absente (clientTransferProhibited)"})

    return {
        "domaine":       domaine,
        "registrant":    safe(data.registrant_name or data.org or data.name),
        "organisation":  safe(data.org),
        "pays":          safe(data.country),
        "registrar":     safe(data.registrar),
        "email":         safe(data.emails),
        "creation":      creation,
        "expiration":    expiration,
        "updated":       updated,
        "jours_exp":     jours_exp,
        "nameservers":   nameservers,
        "statuts":       [s[:60] for s in statuts[:5]],
        "alertes":       alertes,
        "dnssec":        safe(data.dnssec),
    }


# ─────────────────────────────────────────────
# DNS LOOKUP
# ─────────────────────────────────────────────

def analyser_dns(domaine: str) -> dict:
    """
    Résout tous les enregistrements DNS d'un domaine.
    Types : A, AAAA, MX, NS, TXT, CNAME, SOA.
    """
    try:
        import dns.resolver as res
        import dns.exception
    except ImportError:
        return {"erreur": "Module dnspython non installé. Lancez : pip install dnspython"}

    domaine = domaine.replace("https://", "").replace("http://", "").split("/")[0].strip()
    enregistrements = {}
    alertes = []

    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in types:
        try:
            reponse = res.resolve(domaine, rtype, lifetime=5)
            valeurs = []
            for r in reponse:
                if rtype == "MX":
                    valeurs.append(f"{r.preference} {r.exchange}")
                elif rtype == "SOA":
                    valeurs.append(f"ns={r.mname} email={r.rname} serial={r.serial}")
                elif rtype == "TXT":
                    valeurs.append(r.to_text().strip('"'))
                else:
                    valeurs.append(r.to_text())
            enregistrements[rtype] = valeurs
        except dns.exception.DNSException:
            enregistrements[rtype] = []
        except Exception:
            enregistrements[rtype] = []

    # Résolution IP inverse (PTR)
    ptr_resultats = []
    for ip in enregistrements.get("A", [])[:2]:
        try:
            ptr = socket.gethostbyaddr(ip)
            ptr_resultats.append(f"{ip} → {ptr[0]}")
        except Exception:
            ptr_resultats.append(f"{ip} → (PTR introuvable)")
    enregistrements["PTR"] = ptr_resultats

    # Alertes DNS
    if not enregistrements.get("MX"):
        alertes.append({"type": "INFO", "msg": "Aucun enregistrement MX — ce domaine ne reçoit pas d'emails"})

    txts = " ".join(enregistrements.get("TXT", []))
    if "v=spf1" not in txts:
        alertes.append({"type": "MOYENNE", "msg": "Pas de SPF détecté — risque de spoofing email"})
    if "v=DMARC1" not in txts and "_dmarc" not in domaine:
        alertes.append({"type": "MOYENNE", "msg": "DMARC non configuré — les emails peuvent être forgés"})

    total = sum(len(v) for v in enregistrements.values())

    return {
        "domaine":         domaine,
        "enregistrements": enregistrements,
        "total":           total,
        "alertes":         alertes,
        "has_ipv6":        bool(enregistrements.get("AAAA")),
        "has_spf":         "v=spf1" in txts,
        "has_dmarc":       "v=DMARC1" in txts,
    }


# ─────────────────────────────────────────────
# GÉOLOCALISATION + RÉPUTATION IP
# ─────────────────────────────────────────────

def analyser_ip(ip_ou_domaine: str) -> dict:
    """
    Géolocalise une IP et récupère ses infos ASN/réputation
    via l'API gratuite ip-api.com (pas de clé requise).
    """
    import requests

    cible = ip_ou_domaine.replace("https://", "").replace("http://", "").split("/")[0].strip()

    # Résoudre le domaine en IP si nécessaire
    ip_resolue = cible
    est_domaine = False
    try:
        if not _est_ip(cible):
            ip_resolue = socket.gethostbyname(cible)
            est_domaine = True
    except Exception:
        return {"erreur": f"Impossible de résoudre '{cible}'"}

    # Appel API ip-api.com (gratuit, 45 req/min)
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip_resolue}",
            params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"},
            timeout=8
        )
        data = r.json()
    except Exception as e:
        return {"erreur": f"API géolocalisation indisponible : {e}"}

    if data.get("status") != "success":
        return {"erreur": f"IP non géolocalisable : {data.get('message', 'erreur inconnue')}"}

    # Indicateurs de risque
    alertes = []
    score_risque = 0

    if data.get("proxy"):
        alertes.append({"type": "HAUTE",   "msg": "IP identifiée comme proxy / VPN"})
        score_risque += 30
    if data.get("hosting"):
        alertes.append({"type": "MOYENNE", "msg": "IP hébergée chez un fournisseur cloud / datacenter"})
        score_risque += 15
    if data.get("mobile"):
        alertes.append({"type": "INFO",    "msg": "IP mobile (réseau cellulaire)"})

    # Vérification IP privée
    if _est_ip_privee(ip_resolue):
        alertes.append({"type": "INFO", "msg": "IP privée / réseau local — non routable sur internet"})

    if score_risque >= 30:
        niveau_risque, couleur = "SUSPECT", "orange"
    elif score_risque >= 15:
        niveau_risque, couleur = "À SURVEILLER", "orange"
    else:
        niveau_risque, couleur = "NORMAL", "green"

    return {
        "cible":         cible,
        "ip":            ip_resolue,
        "est_domaine":   est_domaine,
        "pays":          data.get("country", "—"),
        "code_pays":     data.get("countryCode", ""),
        "region":        data.get("regionName", "—"),
        "ville":         data.get("city", "—"),
        "cp":            data.get("zip", "—"),
        "lat":           data.get("lat"),
        "lon":           data.get("lon"),
        "timezone":      data.get("timezone", "—"),
        "isp":           data.get("isp", "—"),
        "org":           data.get("org", "—"),
        "asn":           data.get("as", "—"),
        "asname":        data.get("asname", "—"),
        "reverse_dns":   data.get("reverse", "—"),
        "est_proxy":     data.get("proxy", False),
        "est_hosting":   data.get("hosting", False),
        "est_mobile":    data.get("mobile", False),
        "score_risque":  min(score_risque, 100),
        "niveau_risque": niveau_risque,
        "couleur":       couleur,
        "alertes":       alertes,
    }


def _est_ip(s: str) -> bool:
    import re
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s))

def _est_ip_privee(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False
