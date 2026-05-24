"""
PySecOps — Analyseur de logs intelligent
Lit n'importe quel format de log et produit :
- Résumé en français simple
- Timeline des attaques
- Score de danger
- Recommandations actionnables
"""

import re
import datetime
from collections import defaultdict, Counter


# ─────────────────────────────────────────────
# FORMATS DE LOGS SUPPORTÉS
# ─────────────────────────────────────────────

FORMATS = {
    "apache": (
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+'
        r'\[(?P<date>[^\]]+)\]\s+'
        r'"(?P<methode>\w+)\s+(?P<url>\S+)[^"]*"\s+'
        r'(?P<code>\d{3})\s+(?P<taille>\S+)'
        r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
    ),
    "nginx": (
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+'
        r'\[(?P<date>[^\]]+)\]\s+'
        r'"(?P<methode>\w+)?\s*(?P<url>\S+)?[^"]*"\s+'
        r'(?P<code>\d{3})\s+(?P<taille>\d+)'
    ),
    "ssh": (
        r'(?P<date>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+'
        r'\S+\s+\S+:\s+(?P<message>.+)'
    ),
    "windows": (
        r'(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<niveau>\w+)\s+(?P<source>\S+)\s+(?P<message>.+)'
    ),
}

# Signatures d'attaques avec explications
SIGNATURES = [
    {
        "id":       "ATK-001",
        "nom":      "Injection SQL",
        "regex":    r"(?i)(union\s+select|or\s+1=1|drop\s+table|select\s+\*\s+from|insert\s+into|benchmark\s*\(|sleep\s*\(|information_schema)",
        "severite": "CRITIQUE",
        "explication": "Tentative d'injection SQL détectée — un attaquant essaie de manipuler votre base de données.",
        "action":   "Vérifiez et renforcez la validation des entrées dans votre code. Utilisez des requêtes préparées.",
    },
    {
        "id":       "ATK-002",
        "nom":      "Cross-Site Scripting (XSS)",
        "regex":    r"(?i)(<script|javascript:|onerror=|onload=|alert\s*\(|document\.cookie)",
        "severite": "HAUTE",
        "explication": "Tentative d'injection XSS — un attaquant essaie d'injecter du JavaScript malveillant.",
        "action":   "Échappez toutes les sorties HTML. Mettez en place une Content Security Policy (CSP).",
    },
    {
        "id":       "ATK-003",
        "nom":      "Path Traversal / LFI",
        "regex":    r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%252e|/etc/passwd|/etc/shadow|boot\.ini|win\.ini)",
        "severite": "CRITIQUE",
        "explication": "Tentative de lecture de fichiers système — un attaquant essaie d'accéder à des fichiers sensibles.",
        "action":   "Validez et filtrez tous les chemins de fichiers. N'utilisez jamais les entrées utilisateur dans les chemins.",
    },
    {
        "id":       "ATK-004",
        "nom":      "Scan de répertoires",
        "regex":    r"(?i)(\.env|\.git/|wp-config|phpinfo|adminer|phpmyadmin|backup\.sql|\.htpasswd|\.DS_Store|web\.config)",
        "severite": "HAUTE",
        "explication": "Scan de fichiers sensibles — un attaquant recherche des fichiers de configuration exposés.",
        "action":   "Bloquez l'accès à ces fichiers dans votre configuration serveur. Vérifiez qu'ils ne sont pas exposés.",
    },
    {
        "id":       "ATK-005",
        "nom":      "Scanner / Bot malveillant",
        "regex":    r"(?i)(sqlmap|nikto|nessus|masscan|nmap|dirbuster|gobuster|hydra|metasploit|burpsuite|zgrab)",
        "severite": "HAUTE",
        "explication": "Un outil de scanning automatisé a été détecté — votre site est activement scanné.",
        "action":   "Bloquez l'IP source. Vérifiez si d'autres attaques ont suivi ce scan.",
    },
    {
        "id":       "ATK-006",
        "nom":      "Injection de commandes",
        "regex":    r"(?i)(;ls\s|;id\s|;whoami|;cat\s|`id`|`whoami`|\$\(id\)|\|whoami|\|ls\s)",
        "severite": "CRITIQUE",
        "explication": "Tentative d'injection de commandes système — un attaquant essaie d'exécuter des commandes sur votre serveur.",
        "action":   "Ne passez jamais les entrées utilisateur à un shell. Utilisez des fonctions sécurisées.",
    },
    {
        "id":       "ATK-007",
        "nom":      "Log4Shell (CVE-2021-44228)",
        "regex":    r"(?i)(\$\{jndi:|jndi:ldap|jndi:rmi|jndi:dns|\$\{lower:)",
        "severite": "CRITIQUE",
        "explication": "Tentative d'exploitation Log4Shell — une des vulnérabilités les plus critiques de 2021.",
        "action":   "Mettez à jour Log4j2 vers la version 2.17.1+. Désactivez les lookups JNDI immédiatement.",
    },
    {
        "id":       "ATK-008",
        "nom":      "Brute-force HTTP",
        "regex":    r'" (401|403) ',
        "severite": "HAUTE",
        "explication": "Tentatives d'authentification répétées échouées — attaque brute-force détectée.",
        "action":   "Implémentez un rate limiting. Bloquez les IPs après plusieurs échecs. Activez le MFA.",
    },
    {
        "id":       "ATK-009",
        "nom":      "Brute-force SSH",
        "regex":    r"(?i)(Failed password|Invalid user|authentication failure|maximum authentication attempts)",
        "severite": "HAUTE",
        "explication": "Tentatives de connexion SSH échouées répétées — attaque brute-force sur SSH.",
        "action":   "Utilisez Fail2ban. Désactivez l'authentification par mot de passe. Utilisez uniquement des clés SSH.",
    },
    {
        "id":       "ATK-010",
        "nom":      "Spring4Shell (CVE-2022-22965)",
        "regex":    r"(?i)(class\.module\.classLoader|class\[module\]\[classLoader\])",
        "severite": "CRITIQUE",
        "explication": "Tentative d'exploitation Spring4Shell — vulnérabilité RCE critique dans Spring Framework.",
        "action":   "Mettez à jour Spring Framework vers 5.3.18+ ou 5.2.20+. Appliquez les patches immédiatement.",
    },
]


# ─────────────────────────────────────────────
# DÉTECTION DU FORMAT
# ─────────────────────────────────────────────

def detecter_format(lignes: list) -> str:
    """Détecte automatiquement le format du log."""
    echantillon = "\n".join(lignes[:30])

    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\[.*\].*".*" \d{3}', echantillon):
        if "nginx" in echantillon.lower():
            return "nginx"
        return "apache"
    if re.search(r'\w{3}\s+\d+\s+\d+:\d+:\d+.*sshd', echantillon):
        return "ssh"
    if re.search(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\w+', echantillon):
        return "windows"
    return "brut"


# ─────────────────────────────────────────────
# ANALYSE PRINCIPALE
# ─────────────────────────────────────────────

def analyser_logs_intelligent(texte: str) -> dict:
    """
    Analyse complète d'un fichier de log.
    Retourne un rapport complet avec résumé en français.
    """
    lignes = [l.strip() for l in texte.splitlines() if l.strip()]
    if not lignes:
        return {"erreur": "Fichier vide."}

    format_detecte = detecter_format(lignes)
    pattern        = FORMATS.get(format_detecte, FORMATS["apache"])

    # Parser les lignes
    entrees = []
    for ligne in lignes:
        m = re.match(pattern, ligne)
        if m:
            d = m.groupdict()
            entrees.append({
                "ip":      d.get("ip", ""),
                "date":    d.get("date", ""),
                "url":     d.get("url", d.get("message", "")),
                "code":    d.get("code", ""),
                "methode": d.get("methode", ""),
                "ua":      d.get("ua", ""),
                "ligne":   ligne,
            })
        else:
            ip_m = re.search(r'\d{1,3}(?:\.\d{1,3}){3}', ligne)
            entrees.append({
                "ip":    ip_m.group(0) if ip_m else "",
                "url":   ligne,
                "ligne": ligne,
                "code":  "", "date": "", "methode": "", "ua": "",
            })

    # Détecter les attaques
    alertes        = []
    ip_alertes     = defaultdict(list)
    patterns_count = Counter()

    for entree in entrees:
        texte_complet = entree["ligne"] + " " + entree.get("ua", "")
        for sig in SIGNATURES:
            if re.search(sig["regex"], texte_complet):
                alerte = {
                    "id":          sig["id"],
                    "nom":         sig["nom"],
                    "severite":    sig["severite"],
                    "explication": sig["explication"],
                    "action":      sig["action"],
                    "ip":          entree.get("ip", ""),
                    "url":         entree.get("url", "")[:200],
                    "date":        entree.get("date", ""),
                    "ligne":       entree.get("ligne", "")[:200],
                }
                alertes.append(alerte)
                if entree.get("ip"):
                    ip_alertes[entree["ip"]].append(alerte)
                patterns_count[sig["nom"]] += 1

    # Détecter le brute-force par corrélation temporelle
    ip_echecs = defaultdict(int)
    for e in entrees:
        if e.get("code") in ("401", "403", "400"):
            ip_echecs[e["ip"]] += 1

    ips_bruteforce = []
    for ip, nb in ip_echecs.items():
        if nb >= 10:
            ips_bruteforce.append({
                "ip":        ip,
                "nb_echecs": nb,
                "severite":  "CRITIQUE" if nb >= 50 else "HAUTE",
            })
    ips_bruteforce.sort(key=lambda x: x["nb_echecs"], reverse=True)

    # Top IPs
    toutes_ips = [e["ip"] for e in entrees if e.get("ip")]
    top_ips    = Counter(toutes_ips).most_common(10)

    # IOC — IPs malveillantes
    ips_malveillantes = []
    for ip, nb_alertes in sorted(ip_alertes.items(),
                                  key=lambda x: len(x[1]), reverse=True)[:10]:
        types = list(set(a["nom"] for a in nb_alertes))
        max_sev = (
            "CRITIQUE" if any(a["severite"] == "CRITIQUE" for a in nb_alertes)
            else "HAUTE"
        )
        ips_malveillantes.append({
            "ip":        ip,
            "nb_alertes":len(nb_alertes),
            "types":     types,
            "severite":  max_sev,
        })

    # Score de danger
    sev_count = Counter(a["severite"] for a in alertes)
    score = min(
        sev_count.get("CRITIQUE", 0) * 25 +
        sev_count.get("HAUTE",    0) * 15 +
        sev_count.get("MOYENNE",  0) * 5  +
        len(ips_bruteforce) * 10,
        100
    )

    if score >= 75:   niveau, couleur = "CRITIQUE", "red"
    elif score >= 40: niveau, couleur = "ÉLEVÉ",    "orange"
    elif score >= 15: niveau, couleur = "MODÉRÉ",   "yellow"
    else:             niveau, couleur = "FAIBLE",   "green"

    # Résumé en français
    resume = _generer_resume(
        lignes, entrees, alertes, ips_bruteforce,
        ips_malveillantes, score, niveau, format_detecte
    )

    # Recommandations uniques
    recommandations = []
    actions_vues    = set()
    for a in alertes:
        if a["action"] not in actions_vues:
            actions_vues.add(a["action"])
            recommandations.append({
                "severite": a["severite"],
                "nom":      a["nom"],
                "action":   a["action"],
            })

    return {
        "format":          format_detecte,
        "nb_lignes":       len(lignes),
        "nb_entrees":      len(entrees),
        "nb_alertes":      len(alertes),
        "alertes":         alertes[:50],
        "patterns_count":  dict(patterns_count.most_common(10)),
        "ips_malveillantes":ips_malveillantes,
        "ips_bruteforce":  ips_bruteforce,
        "top_ips":         [{"ip":ip,"nb":nb} for ip,nb in top_ips],
        "sev_count":       dict(sev_count),
        "score":           score,
        "niveau":          niveau,
        "couleur":         couleur,
        "resume":          resume,
        "recommandations": recommandations,
        "date_analyse":    datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S"),
    }


def _generer_resume(lignes, entrees, alertes, bruteforce,
                    ips_mal, score, niveau, format_log) -> str:
    """Génère un résumé en français clair et actionnable."""

    formats_fr = {
        "apache": "Apache", "nginx": "Nginx",
        "ssh": "SSH (auth.log)", "windows": "Windows Event Log",
        "brut": "format brut"
    }

    resume = f"Analyse de {len(lignes):,} lignes de log "
    resume += f"({formats_fr.get(format_log, format_log)}).\n\n"

    if not alertes:
        resume += "✅ Aucune activité suspecte détectée dans ce fichier de log.\n"
        resume += "L'infrastructure semble sécurisée sur la période analysée."
        return resume

    # Attaques détectées
    types_attaques = list(set(a["nom"] for a in alertes))
    resume += f"⚠️ {len(alertes)} événement(s) suspect(s) détecté(s) "
    resume += f"impliquant {len(ips_mal)} IP(s) hostile(s).\n\n"

    resume += f"Types d'attaques détectées : {', '.join(types_attaques[:3])}"
    if len(types_attaques) > 3:
        resume += f" et {len(types_attaques)-3} autre(s)"
    resume += ".\n\n"

    # Brute-force
    if bruteforce:
        pire = bruteforce[0]
        resume += f"🔨 Brute-force détecté : l'IP {pire['ip']} "
        resume += f"a effectué {pire['nb_echecs']} tentatives d'authentification échouées.\n\n"

    # IP la plus active
    if ips_mal:
        top = ips_mal[0]
        resume += f"🎯 IP la plus hostile : {top['ip']} "
        resume += f"avec {top['nb_alertes']} alerte(s) "
        resume += f"({', '.join(top['types'][:2])}).\n\n"

    # Conclusion
    if niveau == "CRITIQUE":
        resume += "🚨 NIVEAU CRITIQUE — Votre infrastructure est activement attaquée. "
        resume += "Bloquez les IPs malveillantes immédiatement et analysez les dégâts potentiels."
    elif niveau == "ÉLEVÉ":
        resume += "⚠️ NIVEAU ÉLEVÉ — Des attaques sérieuses ont été détectées. "
        resume += "Appliquez les recommandations ci-dessous rapidement."
    elif niveau == "MODÉRÉ":
        resume += "⚡ NIVEAU MODÉRÉ — Activité suspecte détectée. "
        resume += "Surveillez l'évolution et renforcez les protections."
    else:
        resume += "✅ NIVEAU FAIBLE — Activité mineure détectée. Restez vigilant."

    return resume
