"""
PySecOps — Utilitaires Crypto & SecOps
Toute la logique métier, séparée des routes Flask.
"""

import hashlib
import re
import secrets
import string
import uuid
import base64
import binascii
import urllib.parse
import math
from typing import Optional

# ─────────────────────────────────────────────
# 1. VÉRIFICATEUR DE FUITE (Have I Been Pwned)
# ─────────────────────────────────────────────

def verifier_fuite_password(password: str) -> dict:
    """
    Vérifie si un mot de passe a fuité via l'API HaveIBeenPwned (k-anonymity).
    Le mot de passe n'est JAMAIS envoyé — seulement les 5 premiers caractères du hash SHA1.
    """
    import requests

    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
            headers={"Add-Padding": "true"}
        )
        r.raise_for_status()
    except Exception as e:
        return {"erreur": f"API indisponible : {e}"}

    # Chercher le suffixe dans la réponse
    count = 0
    for line in r.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            count = int(parts[1])
            break

    if count == 0:
        niveau = "SÉCURISÉ"
        couleur = "green"
        message = "Ce mot de passe n'a pas été trouvé dans les bases de données connues."
    elif count < 100:
        niveau = "FAIBLE RISQUE"
        couleur = "orange"
        message = f"Ce mot de passe a fuité {count} fois. Changez-le dès que possible."
    elif count < 10000:
        niveau = "DANGEREUX"
        couleur = "red"
        message = f"Ce mot de passe a fuité {count} fois. Ne l'utilisez plus jamais."
    else:
        niveau = "CRITIQUE"
        couleur = "red"
        message = f"Ce mot de passe a fuité {count:,} fois. Il est dans toutes les attaques par dictionnaire."

    return {
        "count": count,
        "niveau": niveau,
        "couleur": couleur,
        "message": message,
        "sha1_prefix": prefix,
    }


# ─────────────────────────────────────────────
# 2. DÉTECTEUR DE TYPE DE HASH
# ─────────────────────────────────────────────

HASH_SIGNATURES = [
    {"nom": "MD5",         "longueur": 32,  "regex": r"^[a-f0-9]{32}$",          "securite": "FAIBLE",  "usage": "Vérification d'intégrité basique (obsolète pour mots de passe)"},
    {"nom": "SHA1",        "longueur": 40,  "regex": r"^[a-f0-9]{40}$",          "securite": "FAIBLE",  "usage": "Git commits, certificats anciens (vulnérable aux collisions)"},
    {"nom": "SHA256",      "longueur": 64,  "regex": r"^[a-f0-9]{64}$",          "securite": "FORT",    "usage": "Hachage sécurisé, JWT, signatures numériques"},
    {"nom": "SHA512",      "longueur": 128, "regex": r"^[a-f0-9]{128}$",         "securite": "TRÈS FORT","usage": "Hachage haute sécurité, archivage long terme"},
    {"nom": "SHA384",      "longueur": 96,  "regex": r"^[a-f0-9]{96}$",          "securite": "FORT",    "usage": "Certificats TLS, signatures"},
    {"nom": "NTLM",        "longueur": 32,  "regex": r"^[A-F0-9]{32}$",          "securite": "FAIBLE",  "usage": "Authentification Windows (vulnérable au Pass-the-Hash)"},
    {"nom": "bcrypt",      "longueur": None,"regex": r"^\$2[aby]\$\d{2}\$.{53}$","securite": "TRÈS FORT","usage": "Stockage sécurisé de mots de passe"},
    {"nom": "Argon2",      "longueur": None,"regex": r"^\$argon2",               "securite": "TRÈS FORT","usage": "Standard moderne de hachage de mots de passe (gagnant PHC)"},
    {"nom": "MD5 (Unix)",  "longueur": None,"regex": r"^\$1\$",                  "securite": "FAIBLE",  "usage": "Anciens systèmes Unix (obsolète)"},
    {"nom": "SHA256 (Unix)","longueur": None,"regex": r"^\$5\$",                 "securite": "MOYEN",   "usage": "Systèmes Unix modernes"},
    {"nom": "SHA512 (Unix)","longueur": None,"regex": r"^\$6\$",                 "securite": "FORT",    "usage": "Linux /etc/shadow"},
    {"nom": "CRC32",       "longueur": 8,   "regex": r"^[a-f0-9]{8}$",           "securite": "TRÈS FAIBLE","usage": "Vérification d'intégrité réseau uniquement (pas cryptographique)"},
    {"nom": "MySQL 4.x",   "longueur": 16,  "regex": r"^[a-f0-9]{16}$",          "securite": "TRÈS FAIBLE","usage": "Ancien MySQL (ne jamais utiliser)"},
]

def detecter_hash(valeur: str) -> dict:
    """Détecte automatiquement le type d'un hash."""
    valeur = valeur.strip()
    candidats = []

    for sig in HASH_SIGNATURES:
        if re.match(sig["regex"], valeur, re.IGNORECASE):
            candidats.append(sig)

    if not candidats:
        return {
            "detecte": False,
            "message": "Format non reconnu. Ce n'est peut-être pas un hash valide.",
        }

    # Prendre le candidat le plus précis (regex stricte > longueur)
    principal = candidats[0]
    return {
        "detecte": True,
        "type": principal["nom"],
        "securite": principal["securite"],
        "usage": principal["usage"],
        "longueur": len(valeur),
        "candidats": [c["nom"] for c in candidats],
        "ambigue": len(candidats) > 1,
    }


# ─────────────────────────────────────────────
# 3. GÉNÉRATEUR DE CLÉS ET SECRETS
# ─────────────────────────────────────────────

def generer_secret(type_secret: str, longueur: int = 32) -> dict:
    """Génère un secret selon le type demandé."""

    generateurs = {
        "aes128":   lambda: secrets.token_hex(16).upper(),
        "aes256":   lambda: secrets.token_hex(32).upper(),
        "token":    lambda: secrets.token_urlsafe(longueur),
        "uuid":     lambda: str(uuid.uuid4()),
        "flask":    lambda: secrets.token_hex(32),
        "django":   lambda: ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(50)),
        "apikey":   lambda: secrets.token_urlsafe(32),
        "jwt":      lambda: secrets.token_hex(64),
        "mdp":      lambda: _generer_mdp_fort(longueur),
    }

    descriptions = {
        "aes128":   "Clé AES-128 bits (16 octets hex)",
        "aes256":   "Clé AES-256 bits (32 octets hex)",
        "token":    "Token sécurisé URL-safe",
        "uuid":     "UUID v4 aléatoire",
        "flask":    "SECRET_KEY Flask",
        "django":   "SECRET_KEY Django",
        "apikey":   "API Key sécurisée",
        "jwt":      "Secret JWT (512 bits)",
        "mdp":      "Mot de passe fort",
    }

    if type_secret not in generateurs:
        return {"erreur": "Type de secret inconnu."}

    valeur = generateurs[type_secret]()
    entropie = _calculer_entropie(valeur)

    return {
        "type": type_secret,
        "description": descriptions[type_secret],
        "valeur": valeur,
        "longueur": len(valeur),
        "entropie_bits": round(entropie, 1),
        "force": "EXCELLENT" if entropie > 128 else ("FORT" if entropie > 64 else "MOYEN"),
    }

def _generer_mdp_fort(longueur: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        mdp = ''.join(secrets.choice(alphabet) for _ in range(longueur))
        if (any(c.isupper() for c in mdp) and
            any(c.islower() for c in mdp) and
            any(c.isdigit() for c in mdp) and
            any(c in string.punctuation for c in mdp)):
            return mdp

def _calculer_entropie(valeur: str) -> float:
    """Calcule l'entropie de Shannon d'une chaîne."""
    if not valeur:
        return 0.0
    freq = {}
    for c in valeur:
        freq[c] = freq.get(c, 0) + 1
    n = len(valeur)
    return -sum((f/n) * math.log2(f/n) for f in freq.values()) * n


# ─────────────────────────────────────────────
# 5. ANALYSE AVANCÉE DE MOT DE PASSE
# ─────────────────────────────────────────────

MOTS_COMMUNS = {
    "password","123456","azerty","qwerty","admin","letmein",
    "welcome","monkey","dragon","master","superman","batman",
    "iloveyou","sunshine","princess","football","baseball",
    "abc123","password1","pass","test","login","root","user",
}

SUITES_FAIBLES = ["abc","bcd","cde","123","234","345","456","789","qwe","asd","zxc"]

def analyser_mot_de_passe(mdp: str) -> dict:
    """Analyse complète d'un mot de passe avec score et conseils."""
    if not mdp:
        return {"erreur": "Mot de passe vide."}

    criteres = {}
    conseils = []
    score = 0

    # Longueur
    criteres["Longueur ≥ 8"]  = len(mdp) >= 8
    criteres["Longueur ≥ 12"] = len(mdp) >= 12
    criteres["Longueur ≥ 16"] = len(mdp) >= 16
    if len(mdp) < 8:
        conseils.append("❌ Trop court — utilisez au minimum 12 caractères")
    elif len(mdp) < 12:
        conseils.append("⚠ Longueur acceptable mais 16+ est recommandé")

    # Composition
    a_maj    = bool(re.search(r'[A-Z]', mdp))
    a_min    = bool(re.search(r'[a-z]', mdp))
    a_chiff  = bool(re.search(r'\d', mdp))
    a_symb   = bool(re.search(r'[!@#$%^&*(),.?\":{}|<>\-_=+\[\];\'\\]', mdp))

    criteres["Majuscule"]  = a_maj
    criteres["Minuscule"]  = a_min
    criteres["Chiffre"]    = a_chiff
    criteres["Symbole"]    = a_symb

    if not a_maj:   conseils.append("❌ Ajoutez des majuscules (A-Z)")
    if not a_min:   conseils.append("❌ Ajoutez des minuscules (a-z)")
    if not a_chiff: conseils.append("❌ Ajoutez des chiffres (0-9)")
    if not a_symb:  conseils.append("❌ Ajoutez des symboles (!@#$...)")

    # Mots communs
    est_commun = mdp.lower() in MOTS_COMMUNS
    criteres["Pas un mot commun"] = not est_commun
    if est_commun:
        conseils.append("🚨 Ce mot de passe est dans tous les dictionnaires d'attaque")

    # Répétitions
    a_repetition = bool(re.search(r'(.)\1{2,}', mdp))
    criteres["Pas de répétitions"] = not a_repetition
    if a_repetition:
        conseils.append("⚠ Évitez les répétitions (aaa, 111...)")

    # Suites faibles
    mdp_lower = mdp.lower()
    a_suite = any(s in mdp_lower for s in SUITES_FAIBLES)
    criteres["Pas de suite simple"] = not a_suite
    if a_suite:
        conseils.append("⚠ Évitez les suites de touches (azerty, 123...)")

    # Score global sur 10
    poids = {
        "Longueur ≥ 8": 1, "Longueur ≥ 12": 1, "Longueur ≥ 16": 1,
        "Majuscule": 1, "Minuscule": 1, "Chiffre": 1, "Symbole": 2,
        "Pas un mot commun": 1, "Pas de répétitions": 0.5, "Pas de suite simple": 0.5,
    }
    score = sum(poids.get(k, 0) for k, v in criteres.items() if v)
    score_max = sum(poids.values())
    score_pct = int((score / score_max) * 100)

    if score_pct >= 80:
        niveau = "FORT"
        couleur = "green"
    elif score_pct >= 50:
        niveau = "MOYEN"
        couleur = "orange"
    else:
        niveau = "FAIBLE"
        couleur = "red"

    # Temps de cassage estimé
    charset = 0
    if a_min:   charset += 26
    if a_maj:   charset += 26
    if a_chiff: charset += 10
    if a_symb:  charset += 32
    charset = max(charset, 26)

    combinaisons = charset ** len(mdp)
    vitesse = 1e10  # 10 milliards de tentatives/seconde (GPU)
    secondes = combinaisons / vitesse / 2

    temps_cassage = _formater_duree(secondes)

    if not conseils:
        conseils.append("✅ Excellent mot de passe ! Changez-le tous les 6 mois.")

    return {
        "criteres": criteres,
        "score": score_pct,
        "niveau": niveau,
        "couleur": couleur,
        "conseils": conseils,
        "temps_cassage": temps_cassage,
        "longueur": len(mdp),
        "entropie": round(_calculer_entropie(mdp), 1),
    }

def _formater_duree(secondes: float) -> str:
    if secondes < 1:      return "moins d'une seconde"
    if secondes < 60:     return f"{int(secondes)} secondes"
    if secondes < 3600:   return f"{int(secondes/60)} minutes"
    if secondes < 86400:  return f"{int(secondes/3600)} heures"
    if secondes < 31536000: return f"{int(secondes/86400)} jours"
    if secondes < 3.15e9: return f"{int(secondes/31536000)} ans"
    return "plusieurs millénaires"


# ─────────────────────────────────────────────
# 6. ENCODEUR / DÉCODEUR MULTI-FORMAT
# ─────────────────────────────────────────────

def convertir(texte: str, format_: str, sens: str) -> dict:
    """Encode ou décode un texte dans un format donné."""
    try:
        if format_ == "base64":
            if sens == "encode":
                r = base64.b64encode(texte.encode()).decode()
            else:
                r = base64.b64decode(texte.encode()).decode()

        elif format_ == "hex":
            if sens == "encode":
                r = texte.encode().hex()
            else:
                r = bytes.fromhex(texte).decode()

        elif format_ == "url":
            if sens == "encode":
                r = urllib.parse.quote(texte)
            else:
                r = urllib.parse.unquote(texte)

        elif format_ == "rot13":
            # Bidirectionnel par nature
            r = texte.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))

        elif format_ == "binaire":
            if sens == "encode":
                r = ' '.join(format(ord(c), '08b') for c in texte)
            else:
                bits = texte.replace(' ', '')
                r = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))

        elif format_ == "morse":
            MORSE = {
                'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
                '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',
                ' ': '/'
            }
            MORSE_INV = {v: k for k, v in MORSE.items()}
            if sens == "encode":
                r = ' '.join(MORSE.get(c.upper(), '?') for c in texte)
            else:
                r = ''.join(MORSE_INV.get(c, '?') for c in texte.split(' '))

        elif format_ == "cesar":
            decalage = 13  # César 13 = ROT13
            if sens == "encode":
                r = ''.join(chr((ord(c) - 65 + decalage) % 26 + 65) if c.isupper()
                            else chr((ord(c) - 97 + decalage) % 26 + 97) if c.islower()
                            else c for c in texte)
            else:
                r = ''.join(chr((ord(c) - 65 - decalage) % 26 + 65) if c.isupper()
                            else chr((ord(c) - 97 - decalage) % 26 + 97) if c.islower()
                            else c for c in texte)
        else:
            return {"erreur": f"Format '{format_}' inconnu."}

        return {"resultat": r, "format": format_, "sens": sens, "longueur": len(r)}

    except Exception as e:
        return {"erreur": f"Erreur de conversion : {e}"}


# ─────────────────────────────────────────────
# 10. DÉTECTEUR DE PHISHING
# ─────────────────────────────────────────────

MARQUES_CONNUES = [
    "google","facebook","apple","microsoft","amazon","paypal",
    "netflix","instagram","twitter","linkedin","whatsapp","telegram",
    "orange","sfr","bouygues","laposte","impots","caf","ameli",
    "credit-agricole","bnp","societe-generale","lcl","caisse-epargne",
]

MOTS_SUSPECTS = [
    "verify","confirm","update","secure","login","account","suspended",
    "urgent","alert","limited","free","prize","winner","click","now",
    "verify-account","reset-password","unlock","unusual-activity",
]

TLD_SUSPECTS = [".xyz",".top",".win",".loan",".click",".online",".site",".tk",".ml",".cf",".ga"]

def analyser_phishing(url: str) -> dict:
    """Analyse une URL pour détecter des signes de phishing."""
    import urllib.parse as up

    alertes = []
    score = 0

    try:
        parsed = up.urlparse(url if "://" in url else "http://" + url)
        domaine = parsed.netloc.lower()
        chemin = parsed.path.lower()
        url_complete = url.lower()
    except Exception:
        return {"erreur": "URL invalide."}

    # 1. HTTP sans HTTPS
    if url.startswith("http://"):
        alertes.append({"type": "HAUTE", "msg": "Connexion non chiffrée (HTTP au lieu de HTTPS)"})
        score += 20

    # 2. TLD suspect
    for tld in TLD_SUSPECTS:
        if domaine.endswith(tld):
            alertes.append({"type": "HAUTE", "msg": f"Extension de domaine suspecte : {tld}"})
            score += 25

    # 3. IP dans l'URL
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domaine):
        alertes.append({"type": "CRITIQUE", "msg": "URL contient une adresse IP directe (très suspect)"})
        score += 40

    # 4. Imitation de marque connue
    for marque in MARQUES_CONNUES:
        if marque in domaine and not domaine.endswith(f".com") and marque not in domaine.split('.')[0]:
            alertes.append({"type": "HAUTE", "msg": f"Imitation potentielle de la marque : {marque}"})
            score += 30

    # 5. Trop de sous-domaines
    sous_domaines = domaine.split('.')
    if len(sous_domaines) > 4:
        alertes.append({"type": "MOYENNE", "msg": f"URL avec {len(sous_domaines)} niveaux de sous-domaine (suspect)"})
        score += 15

    # 6. Mots suspects dans l'URL
    for mot in MOTS_SUSPECTS:
        if mot in url_complete:
            alertes.append({"type": "MOYENNE", "msg": f"Mot suspect dans l'URL : '{mot}'"})
            score += 10

    # 7. URL raccourcies connues
    raccourcisseurs = ["bit.ly","tinyurl","t.co","goo.gl","ow.ly","buff.ly","rebrand.ly","short.io"]
    if any(r in domaine for r in raccourcisseurs):
        alertes.append({"type": "MOYENNE", "msg": "URL raccourcie — destination inconnue avant le clic"})
        score += 20

    # 8. Tirets excessifs
    if domaine.count('-') >= 3:
        alertes.append({"type": "BASSE", "msg": f"Domaine avec {domaine.count('-')} tirets (technique d'imitation courante)"})
        score += 10

    score = min(score, 100)

    if score >= 70:    niveau, couleur = "CRITIQUE", "red"
    elif score >= 40:  niveau, couleur = "SUSPECT", "orange"
    elif score >= 20:  niveau, couleur = "À SURVEILLER", "yellow"
    else:              niveau, couleur = "PROBABLE LÉGITIMITÉ", "green"

    return {
        "url": url,
        "domaine": domaine,
        "score": score,
        "niveau": niveau,
        "couleur": couleur,
        "alertes": alertes,
        "nb_alertes": len(alertes),
    }
