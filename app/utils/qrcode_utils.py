"""
PySecOps — Utilitaires QR Code
Génération de QR codes pour URL, WiFi, texte, contact.
"""
import qrcode
import qrcode.constants
import base64
import io
from typing import Optional


def generer_qr(type_qr: str, donnees: dict) -> dict:
    """
    Génère un QR code selon le type demandé.
    Retourne l'image en base64 et le contenu encodé.
    """
    contenu = _construire_contenu(type_qr, donnees)
    if contenu.startswith("ERREUR:"):
        return {"erreur": contenu[7:]}

    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=8,
            border=3,
        )
        qr.add_data(contenu)
        qr.make(fit=True)

        img = qr.make_image(fill_color="#0d1117", back_color="#ffffff")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        img_b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        return {
            "image_b64": img_b64,
            "contenu":   contenu,
            "type":      type_qr,
            "taille":    len(contenu),
        }
    except Exception as e:
        return {"erreur": f"Erreur de génération : {e}"}


def _construire_contenu(type_qr: str, d: dict) -> str:
    """Construit le contenu à encoder selon le type de QR."""

    if type_qr == "url":
        url = d.get("url", "").strip()
        if not url:
            return "ERREUR:URL vide."
        if not url.startswith("http"):
            url = "https://" + url
        return url

    elif type_qr == "texte":
        texte = d.get("texte", "").strip()
        if not texte:
            return "ERREUR:Texte vide."
        return texte

    elif type_qr == "wifi":
        ssid     = d.get("ssid", "").strip()
        password = d.get("password", "").strip()
        security = d.get("security", "WPA").upper()
        if not ssid:
            return "ERREUR:Nom du réseau (SSID) vide."
        # Format standard WiFi QR
        return f"WIFI:T:{security};S:{ssid};P:{password};;"

    elif type_qr == "email":
        email   = d.get("email", "").strip()
        sujet   = d.get("sujet", "").strip()
        message = d.get("message", "").strip()
        if not email:
            return "ERREUR:Adresse email vide."
        return f"mailto:{email}?subject={sujet}&body={message}"

    elif type_qr == "tel":
        numero = d.get("numero", "").strip()
        if not numero:
            return "ERREUR:Numéro de téléphone vide."
        return f"tel:{numero}"

    elif type_qr == "contact":
        nom    = d.get("nom", "").strip()
        tel    = d.get("tel", "").strip()
        email  = d.get("email", "").strip()
        org    = d.get("org", "").strip()
        if not nom:
            return "ERREUR:Nom du contact vide."
        # Format vCard
        return (
            f"BEGIN:VCARD\nVERSION:3.0\n"
            f"FN:{nom}\nTEL:{tel}\n"
            f"EMAIL:{email}\nORG:{org}\n"
            f"END:VCARD"
        )

    return "ERREUR:Type de QR inconnu."


def analyser_contenu_qr(contenu: str) -> dict:
    """
    Analyse le contenu d'un QR code scanné
    et détermine son type + niveau de risque.
    """
    import re

    contenu = contenu.strip()
    alertes = []
    type_detecte = "Texte brut"
    details = {}

    # Détection du type
    if contenu.startswith("http://") or contenu.startswith("https://"):
        type_detecte = "URL"
        details["url"] = contenu
        if contenu.startswith("http://"):
            alertes.append({"type": "MOYENNE", "msg": "URL non chiffrée (HTTP)"})

        # Vérification domaines suspects
        tlds_suspects = [".xyz",".top",".tk",".ml",".cf",".ga",".win",".loan"]
        for tld in tlds_suspects:
            if tld in contenu.lower():
                alertes.append({"type": "HAUTE", "msg": f"Extension suspecte : {tld}"})

        # IPs dans l'URL
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', contenu):
            alertes.append({"type": "CRITIQUE", "msg": "URL pointe vers une adresse IP directe"})

    elif contenu.startswith("WIFI:"):
        type_detecte = "Réseau WiFi"
        ssid_match = re.search(r'S:([^;]+)', contenu)
        sec_match  = re.search(r'T:([^;]+)', contenu)
        pwd_match  = re.search(r'P:([^;]+)', contenu)
        details = {
            "ssid":     ssid_match.group(1) if ssid_match else "—",
            "security": sec_match.group(1)  if sec_match  else "—",
            "password": pwd_match.group(1)  if pwd_match  else "(vide)",
        }
        if details.get("security") in ("nopass", "NOPASS", ""):
            alertes.append({"type": "HAUTE", "msg": "Réseau WiFi ouvert (sans mot de passe)"})
        if details.get("security") == "WEP":
            alertes.append({"type": "HAUTE", "msg": "Sécurité WEP obsolète et vulnérable"})

    elif contenu.startswith("BEGIN:VCARD"):
        type_detecte = "Contact (vCard)"

    elif contenu.startswith("mailto:"):
        type_detecte = "Email"

    elif contenu.startswith("tel:"):
        type_detecte = "Téléphone"
        details["numero"] = contenu[4:]

    # Score de risque
    score = sum(
        30 if a["type"] == "CRITIQUE" else
        20 if a["type"] == "HAUTE" else
        10
        for a in alertes
    )
    score = min(score, 100)

    if score >= 50:   niveau, couleur = "SUSPECT",   "red"
    elif score >= 20: niveau, couleur = "À VÉRIFIER", "orange"
    else:             niveau, couleur = "NORMAL",     "green"

    return {
        "contenu":      contenu[:200],
        "type":         type_detecte,
        "details":      details,
        "alertes":      alertes,
        "score":        score,
        "niveau":       niveau,
        "couleur":      couleur,
        "longueur":     len(contenu),
    }
