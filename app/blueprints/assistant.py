"""
PySecOps — Blueprint Assistant Cybersécurité
Mini chatbot local avec base de connaissances cybersécurité.
"""
from flask import Blueprint, render_template, request, jsonify
from app.utils.db_utils import enregistrer
import re

assistant_bp = Blueprint('assistant', __name__)

# ── Base de connaissances cybersécurité
CONNAISSANCES = {
    # Attaques
    r"xss|cross.site.script": {
        "titre": "XSS — Cross-Site Scripting",
        "reponse": (
            "Le XSS (Cross-Site Scripting) est une attaque qui injecte du code JavaScript "
            "malveillant dans une page web. Quand un utilisateur visite la page, le script "
            "s'exécute dans son navigateur et peut voler ses cookies, ses tokens de session "
            "ou rediriger vers un site malveillant.\n\n"
            "🛡 Protection : échapper les entrées utilisateur, utiliser une CSP (Content "
            "Security Policy), valider côté serveur, utiliser httpOnly sur les cookies."
        ),
        "categorie": "Attaque Web",
        "severite":  "HAUTE",
    },
    r"sql.inject|sqli": {
        "titre": "Injection SQL",
        "reponse": (
            "L'injection SQL consiste à insérer du code SQL dans un champ de formulaire "
            "pour manipuler la base de données. Un attaquant peut lire, modifier ou "
            "supprimer des données, voire prendre le contrôle du serveur.\n\n"
            "🛡 Protection : utiliser des requêtes préparées (prepared statements), "
            "un ORM, valider et assainir toutes les entrées utilisateur."
        ),
        "categorie": "Attaque Web",
        "severite":  "CRITIQUE",
    },
    r"csrf|cross.site.request": {
        "titre": "CSRF — Cross-Site Request Forgery",
        "reponse": (
            "Le CSRF force un utilisateur connecté à effectuer une action non voulue "
            "(virement, changement de mot de passe) à son insu, en exploitant sa session active.\n\n"
            "🛡 Protection : tokens CSRF sur chaque formulaire, vérifier l'en-tête Referer, "
            "utiliser SameSite=Strict sur les cookies."
        ),
        "categorie": "Attaque Web",
        "severite":  "HAUTE",
    },
    r"ransomware|rançon": {
        "titre": "Ransomware",
        "reponse": (
            "Un ransomware est un malware qui chiffre vos fichiers et réclame une rançon "
            "pour les déchiffrer. Il se propage souvent par email (phishing), clés USB "
            "infectées ou vulnérabilités non patchées.\n\n"
            "🛡 Protection : sauvegardes régulières hors ligne (règle 3-2-1), mises à jour "
            "système, ne jamais ouvrir les pièces jointes suspectes, EDR sur les postes."
        ),
        "categorie": "Malware",
        "severite":  "CRITIQUE",
    },
    r"phishing|hameçon": {
        "titre": "Phishing",
        "reponse": (
            "Le phishing est une tentative de tromper l'utilisateur pour lui voler "
            "ses identifiants ou l'inciter à télécharger un malware, via un email ou "
            "site qui imite une organisation légitime.\n\n"
            "🛡 Protection : vérifier l'expéditeur, ne jamais cliquer un lien suspect, "
            "activer le MFA, utiliser un filtre anti-phishing, former les utilisateurs."
        ),
        "categorie": "Ingénierie sociale",
        "severite":  "HAUTE",
    },
    r"ddos|déni.de.service|denial.of.service": {
        "titre": "DDoS — Distributed Denial of Service",
        "reponse": (
            "Une attaque DDoS surcharge un serveur avec des milliers de requêtes simultanées "
            "provenant de machines infectées (botnet) pour le rendre indisponible.\n\n"
            "🛡 Protection : CDN (Cloudflare, AWS Shield), rate limiting, filtrage IP, "
            "architecture distribuée et auto-scaling."
        ),
        "categorie": "Attaque réseau",
        "severite":  "HAUTE",
    },
    r"mitm|man.in.the.middle|homme.du.milieu": {
        "titre": "MITM — Man in the Middle",
        "reponse": (
            "L'attaque MITM intercepte la communication entre deux parties à leur insu. "
            "L'attaquant peut lire, modifier ou injecter des données dans la communication.\n\n"
            "🛡 Protection : utiliser HTTPS/TLS, certificats valides, HSTS, éviter les "
            "WiFi publics sans VPN, vérifier les certificats."
        ),
        "categorie": "Attaque réseau",
        "severite":  "HAUTE",
    },
    # Cryptographie
    r"sha256|pourquoi sha": {
        "titre": "SHA-256 — Secure Hash Algorithm",
        "reponse": (
            "SHA-256 est un algorithme de hachage cryptographique qui produit une empreinte "
            "de 256 bits (64 caractères hex). Il est considéré comme sûr car :\n"
            "• Il est irréversible (one-way)\n"
            "• Une modification minime du message change totalement le hash\n"
            "• Résistant aux collisions\n\n"
            "✅ Utilisations : signatures numériques, intégrité de fichiers, JWT, "
            "certificats TLS, blockchains.\n"
            "⚠ Ne pas utiliser pour hacher les mots de passe — préférer bcrypt ou Argon2."
        ),
        "categorie": "Cryptographie",
        "severite":  "INFO",
    },
    r"md5|pourquoi pas md5": {
        "titre": "MD5 — Pourquoi l'éviter ?",
        "reponse": (
            "MD5 est un algorithme de hachage obsolète et vulnérable depuis les années 2000. "
            "Ses faiblesses :\n"
            "• Vulnérable aux collisions (deux fichiers différents, même hash)\n"
            "• Des tables arc-en-ciel (rainbow tables) permettent de retrouver le texte original\n"
            "• Très rapide → facilement bruteforceable\n\n"
            "❌ Ne jamais utiliser MD5 pour les mots de passe, signatures ou certificats.\n"
            "✅ Acceptable uniquement pour vérifier l'intégrité d'un fichier non critique."
        ),
        "categorie": "Cryptographie",
        "severite":  "INFO",
    },
    r"aes|chiffrement symétrique": {
        "titre": "AES — Advanced Encryption Standard",
        "reponse": (
            "AES est le standard de chiffrement symétrique le plus utilisé au monde. "
            "Il chiffre les données avec une clé secrète partagée.\n\n"
            "• AES-128 : 128 bits de clé — sécurisé pour usage courant\n"
            "• AES-256 : 256 bits de clé — standard gouvernemental / militaire\n\n"
            "Mode recommandé : AES-GCM (authentifié + chiffré)\n"
            "Utilisé dans : TLS, VPN, disques durs chiffrés (BitLocker, FileVault), "
            "WhatsApp, Signal."
        ),
        "categorie": "Cryptographie",
        "severite":  "INFO",
    },
    r"rsa": {
        "titre": "RSA — Chiffrement asymétrique",
        "reponse": (
            "RSA est un algorithme de chiffrement asymétrique. Il utilise deux clés :\n"
            "• Clé publique : pour chiffrer ou vérifier une signature\n"
            "• Clé privée : pour déchiffrer ou signer\n\n"
            "Taille recommandée : 2048 bits minimum, 4096 bits pour les usages critiques.\n"
            "Utilisé dans : certificats TLS/SSL, SSH, signatures numériques.\n"
            "⚠ RSA seul ne suffit pas pour les échanges — souvent combiné avec AES "
            "(RSA échange la clé, AES chiffre les données)."
        ),
        "categorie": "Cryptographie",
        "severite":  "INFO",
    },
    # Mots de passe
    r"mot de passe fort|password fort|mdp fort": {
        "titre": "Créer un mot de passe fort",
        "reponse": (
            "Un mot de passe fort doit respecter ces critères :\n\n"
            "✅ Au moins 16 caractères\n"
            "✅ Majuscules + minuscules + chiffres + symboles\n"
            "✅ Pas de mot du dictionnaire\n"
            "✅ Pas de suites (123, azerty, abc)\n"
            "✅ Unique par site/service\n\n"
            "💡 Méthode : utilisez une phrase mémorable transformée :\n"
            "  'Mon chat s'appelle Mimi en 2024!' → 'Mcs@M1m!_2024'\n\n"
            "🔑 Mieux : utilisez un gestionnaire de mots de passe "
            "(Bitwarden, 1Password, KeePass) qui génère et stocke des mots de passe "
            "aléatoires forts pour chaque site."
        ),
        "categorie": "Bonnes pratiques",
        "severite":  "INFO",
    },
    r"mfa|2fa|double authentification|authentification.*deux": {
        "titre": "MFA — Authentification Multi-Facteurs",
        "reponse": (
            "Le MFA (ou 2FA) ajoute une seconde vérification après le mot de passe. "
            "Même si votre mot de passe est compromis, l'attaquant ne peut pas accéder "
            "au compte sans le second facteur.\n\n"
            "Types de facteurs :\n"
            "• Ce que vous savez : mot de passe, PIN\n"
            "• Ce que vous avez : smartphone (Google Auth, Authy), clé FIDO2\n"
            "• Ce que vous êtes : empreinte digitale, Face ID\n\n"
            "✅ Activez le MFA sur tous vos comptes importants : email, banque, GitHub, etc."
        ),
        "categorie": "Bonnes pratiques",
        "severite":  "INFO",
    },
    r"vpn": {
        "titre": "VPN — Virtual Private Network",
        "reponse": (
            "Un VPN chiffre votre connexion internet et masque votre adresse IP réelle "
            "en la remplaçant par celle du serveur VPN.\n\n"
            "✅ Utile pour :\n"
            "• Sécuriser les connexions WiFi publiques\n"
            "• Accéder à un réseau d'entreprise à distance\n"
            "• Contourner les restrictions géographiques\n\n"
            "⚠ Un VPN ne vous rend pas anonyme — votre fournisseur VPN peut voir votre trafic.\n"
            "Protocoles recommandés : WireGuard, OpenVPN.\n"
            "À éviter : VPN gratuits (revendent souvent vos données)."
        ),
        "categorie": "Réseau",
        "severite":  "INFO",
    },
    r"owasp|top 10": {
        "titre": "OWASP Top 10",
        "reponse": (
            "L'OWASP Top 10 liste les 10 risques de sécurité web les plus critiques :\n\n"
            "1. Broken Access Control\n"
            "2. Cryptographic Failures\n"
            "3. Injection (SQL, XSS...)\n"
            "4. Insecure Design\n"
            "5. Security Misconfiguration\n"
            "6. Vulnerable Components\n"
            "7. Auth & Session Failures\n"
            "8. Integrity Failures (SSTI, CI/CD)\n"
            "9. Logging & Monitoring Failures\n"
            "10. SSRF — Server-Side Request Forgery\n\n"
            "📖 Source officielle : owasp.org/Top10"
        ),
        "categorie": "Standards",
        "severite":  "INFO",
    },
    r"pentest|test.*intrusion|penetration": {
        "titre": "Pentest — Test d'intrusion",
        "reponse": (
            "Un pentest (test d'intrusion) est une simulation d'attaque autorisée sur un "
            "système pour identifier ses vulnérabilités avant qu'un vrai attaquant ne le fasse.\n\n"
            "Phases d'un pentest :\n"
            "1. Reconnaissance — collecte d'informations (OSINT)\n"
            "2. Scanning — cartographie des services\n"
            "3. Exploitation — tentatives d'intrusion\n"
            "4. Post-exploitation — élévation de privilèges\n"
            "5. Rapport — documentation des failles et recommandations\n\n"
            "⚠ Un pentest doit toujours être réalisé avec autorisation écrite."
        ),
        "categorie": "Métier",
        "severite":  "INFO",
    },
    r"firewall|pare.feu": {
        "titre": "Firewall — Pare-feu",
        "reponse": (
            "Un firewall filtre le trafic réseau selon des règles définies — il autorise "
            "ou bloque les connexions entrantes et sortantes.\n\n"
            "Types :\n"
            "• Stateless : filtre paquet par paquet (port, IP)\n"
            "• Stateful : suit l'état des connexions (plus intelligent)\n"
            "• Next-Gen (NGFW) : inspection applicative, IPS intégré\n"
            "• WAF : spécialisé pour les applications web\n\n"
            "✅ Règle de base : bloquer tout par défaut, n'autoriser que ce qui est nécessaire."
        ),
        "categorie": "Réseau",
        "severite":  "INFO",
    },
    r"zero.day|0day": {
        "titre": "Zero-Day",
        "reponse": (
            "Une vulnérabilité zero-day est une faille de sécurité inconnue du fabricant "
            "et pour laquelle aucun patch n'existe encore. Elle est particulièrement "
            "dangereuse car les systèmes n'ont aucune défense.\n\n"
            "Cycle de vie :\n"
            "1. Découverte par un chercheur ou attaquant\n"
            "2. Exploitation silencieuse (attaque)\n"
            "3. Découverte par le fabricant\n"
            "4. Publication du patch\n\n"
            "🛡 Protection : architecture de défense en profondeur, EDR, "
            "segmentation réseau, surveillance comportementale."
        ),
        "categorie": "Vulnérabilités",
        "severite":  "CRITIQUE",
    },
    r"hash|qu.*est.*hash|qu.*est.ce.*hash": {
        "titre": "Hash — Qu'est-ce que c'est ?",
        "reponse": (
            "Un hash est une empreinte numérique de taille fixe produite par une fonction "
            "mathématique irréversible appliquée à n'importe quelle donnée.\n\n"
            "Propriétés :\n"
            "• Déterministe : même entrée → même hash\n"
            "• Irréversible : impossible de retrouver l'original\n"
            "• Sensible : 1 bit changé → hash complètement différent\n"
            "• Taille fixe : peu importe la taille de l'entrée\n\n"
            "Exemples :\n"
            "• MD5 (32 hex) — obsolète\n"
            "• SHA1 (40 hex) — faible\n"
            "• SHA256 (64 hex) — standard actuel\n"
            "• bcrypt — pour les mots de passe"
        ),
        "categorie": "Cryptographie",
        "severite":  "INFO",
    },
}

REPONSE_DEFAUT = {
    "titre":     "Je ne sais pas encore répondre à ça",
    "reponse": (
        "Je suis un assistant spécialisé en cybersécurité. "
        "Je peux répondre à des questions sur :\n\n"
        "🔐 Cryptographie : hash, AES, RSA, SHA256, MD5\n"
        "🌐 Attaques web : XSS, injection SQL, CSRF, SSRF\n"
        "🦠 Malware : ransomware, phishing, DDoS, MITM\n"
        "🛡 Bonnes pratiques : mots de passe, MFA, VPN, firewall\n"
        "🔍 Pentest : phases, outils, méthodologie\n"
        "📋 Standards : OWASP Top 10, zero-day\n\n"
        "Essayez par exemple : 'Qu'est-ce que le XSS ?'"
    ),
    "categorie": "Aide",
    "severite":  "INFO",
}


def repondre(question: str) -> dict:
    """
    Cherche une réponse dans la base de connaissances.
    Retourne la meilleure correspondance ou la réponse par défaut.
    """
    q = question.lower().strip()

    for pattern, reponse in CONNAISSANCES.items():
        if re.search(pattern, q, re.IGNORECASE):
            return reponse

    return REPONSE_DEFAUT


@assistant_bp.route('/assistant')
def assistant():
    return render_template('assistant.html', active='assistant')


@assistant_bp.route('/api/assistant', methods=['POST'])
def api_assistant():
    question = request.json.get('question', '').strip()
    if not question:
        return jsonify({"erreur": "Question vide."})
    reponse = repondre(question)
    enregistrer("assistant", question[:50])
    return jsonify(reponse)
