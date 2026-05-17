"""
PySecOps — Blueprint Crypto & SecOps
Route handler uniquement. Toute la logique est dans utils/secops_utils.py
"""
from flask import Blueprint, render_template, request, jsonify
from app.utils.secops_utils import (
    verifier_fuite_password,
    detecter_hash,
    generer_secret,
    analyser_mot_de_passe,
    convertir,
    analyser_phishing,
)

secops_bp = Blueprint('secops', __name__)

@secops_bp.route('/secops')
def secops():
    return render_template('secops/index.html', active='secops')

# ── 1. FUITE MOT DE PASSE
@secops_bp.route('/secops/fuite', methods=['GET', 'POST'])
def fuite():
    resultat = None
    if request.method == 'POST':
        mdp = request.form.get('password', '').strip()
        if mdp:
            resultat = verifier_fuite_password(mdp)
    return render_template('secops/fuite.html', active='secops', resultat=resultat)

# ── 2. DÉTECTEUR DE HASH
@secops_bp.route('/secops/hash-detect', methods=['GET', 'POST'])
def hash_detect():
    resultat = None
    if request.method == 'POST':
        valeur = request.form.get('hash_valeur', '').strip()
        if valeur:
            resultat = detecter_hash(valeur)
    return render_template('secops/hash_detect.html', active='secops', resultat=resultat)

# ── 3. GÉNÉRATEUR DE SECRETS
@secops_bp.route('/secops/keygen', methods=['GET', 'POST'])
def keygen():
    resultat = None
    if request.method == 'POST':
        type_secret = request.form.get('type_secret', 'token')
        longueur = int(request.form.get('longueur', 32))
        resultat = generer_secret(type_secret, longueur)
    return render_template('secops/keygen.html', active='secops', resultat=resultat)

# ── API JSON pour régénération instantanée (bouton "régénérer")
@secops_bp.route('/api/keygen')
def api_keygen():
    type_secret = request.args.get('type', 'token')
    longueur = int(request.args.get('longueur', 32))
    return jsonify(generer_secret(type_secret, longueur))

# ── 5. ANALYSE MOT DE PASSE
@secops_bp.route('/secops/password-check', methods=['GET', 'POST'])
def password_check():
    resultat = None
    if request.method == 'POST':
        mdp = request.form.get('mdp', '')
        resultat = analyser_mot_de_passe(mdp)
    return render_template('secops/password_check.html', active='secops', resultat=resultat)

# ── API JSON temps réel (appel depuis JS à chaque frappe)
@secops_bp.route('/api/password-check')
def api_password_check():
    mdp = request.args.get('mdp', '')
    return jsonify(analyser_mot_de_passe(mdp))

# ── 6. ENCODEUR MULTI-FORMAT
@secops_bp.route('/secops/encoder', methods=['GET', 'POST'])
def encoder():
    resultat = None
    if request.method == 'POST':
        texte   = request.form.get('texte', '')
        format_ = request.form.get('format', 'base64')
        sens    = request.form.get('sens', 'encode')
        if texte:
            resultat = convertir(texte, format_, sens)
    return render_template('secops/encoder.html', active='secops', resultat=resultat)

# ── 10. DÉTECTEUR PHISHING
@secops_bp.route('/secops/phishing', methods=['GET', 'POST'])
def phishing():
    resultat = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            resultat = analyser_phishing(url)
    return render_template('secops/phishing.html', active='secops', resultat=resultat)


# ── 7. SCANNER SSL/TLS
from app.utils.secops_utils import analyser_ssl, analyser_integrite

@secops_bp.route('/secops/ssl', methods=['GET', 'POST'])
def ssl_scan():
    resultat = None
    if request.method == 'POST':
        domaine = request.form.get('domaine', '').strip()
        if domaine:
            resultat = analyser_ssl(domaine)
    return render_template('secops/ssl.html', active='secops', resultat=resultat)


# ── 8. INTÉGRITÉ DE FICHIER
@secops_bp.route('/secops/integrity', methods=['GET', 'POST'])
def integrity():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        fichier   = request.files.get('fichier')
        hash_ref  = request.form.get('hash_ref', '').strip()
        if not fichier or fichier.filename == '':
            erreur = "Aucun fichier sélectionné."
        else:
            try:
                contenu = fichier.read()
                resultat = analyser_integrite(contenu, fichier.filename, hash_ref)
            except Exception as e:
                erreur = f"Erreur lors de la lecture : {e}"
    return render_template('secops/integrity.html', active='secops', resultat=resultat, erreur=erreur)
