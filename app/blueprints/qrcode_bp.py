"""
PySecOps — Blueprint QR Code
Génération et analyse de QR codes.
"""
from flask import Blueprint, render_template, request
from app.utils.qrcode_utils import generer_qr, analyser_contenu_qr
from app.utils.db_utils import enregistrer

qrcode_bp = Blueprint('qrcode', __name__)


@qrcode_bp.route('/secops/qrcode', methods=['GET', 'POST'])
def qrcode():
    resultat  = None
    analyse   = None
    erreur    = None
    action    = None

    if request.method == 'POST':
        action = request.form.get('action', 'generer')

        if action == 'generer':
            type_qr = request.form.get('type_qr', 'url')
            donnees = {
                'url':      request.form.get('url', ''),
                'texte':    request.form.get('texte', ''),
                'ssid':     request.form.get('ssid', ''),
                'password': request.form.get('wifi_password', ''),
                'security': request.form.get('security', 'WPA'),
                'email':    request.form.get('email', ''),
                'sujet':    request.form.get('sujet', ''),
                'message':  request.form.get('message', ''),
                'numero':   request.form.get('numero', ''),
                'nom':      request.form.get('nom', ''),
                'tel':      request.form.get('tel', ''),
                'org':      request.form.get('org', ''),
            }
            resultat = generer_qr(type_qr, donnees)
            if not resultat.get('erreur'):
                enregistrer("qrcode", type_qr)

        elif action == 'analyser':
            contenu = request.form.get('contenu_qr', '').strip()
            if not contenu:
                erreur = "Collez le contenu d'un QR code à analyser."
            else:
                analyse = analyser_contenu_qr(contenu)
                enregistrer("qrcode", "analyse")

    return render_template(
        'secops/qrcode.html',
        active='secops',
        resultat=resultat,
        analyse=analyse,
        erreur=erreur,
        action=action,
    )
