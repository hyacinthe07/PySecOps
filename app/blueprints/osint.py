"""
PySecOps — Blueprint OSINT Engine
"""
from flask import Blueprint, render_template, request
from app.utils.osint_utils import (
    harvester_emails, generer_dorks,
    shodan_lookup, fingerprint_avance
)
from app.utils.db_utils import enregistrer

osint_bp = Blueprint('osint', __name__)


@osint_bp.route('/osint')
def osint():
    return render_template('osint/index.html', active='osint')


@osint_bp.route('/osint/emails', methods=['GET', 'POST'])
def emails():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        domaine = request.form.get('domaine', '').strip()
        if not domaine:
            erreur = "Entrez un nom de domaine."
        else:
            resultat = harvester_emails(domaine)
            enregistrer("osint_emails", domaine)
    return render_template(
        'osint/emails.html', active='osint',
        resultat=resultat, erreur=erreur
    )


@osint_bp.route('/osint/dorks', methods=['GET', 'POST'])
def dorks():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        domaine = request.form.get('domaine', '').strip()
        if not domaine:
            erreur = "Entrez un nom de domaine."
        else:
            resultat = generer_dorks(domaine)
            enregistrer("osint_dorks", domaine)
    return render_template(
        'osint/dorks.html', active='osint',
        resultat=resultat, erreur=erreur
    )


@osint_bp.route('/osint/shodan', methods=['GET', 'POST'])
def shodan():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        cible   = request.form.get('cible', '').strip()
        api_key = request.form.get('api_key', '').strip()
        if not cible:
            erreur = "Entrez une IP ou un domaine."
        else:
            resultat = shodan_lookup(cible, api_key)
            if "erreur" in resultat:
                erreur   = resultat["erreur"]
                resultat = None
            else:
                enregistrer("osint_shodan", cible)
    return render_template(
        'osint/shodan.html', active='osint',
        resultat=resultat, erreur=erreur
    )


@osint_bp.route('/osint/fingerprint', methods=['GET', 'POST'])
def fingerprint():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            erreur = "Entrez une URL."
        else:
            resultat = fingerprint_avance(url)
            if "erreur" in resultat:
                erreur   = resultat["erreur"]
                resultat = None
            else:
                enregistrer("osint_fp", url)
    return render_template(
        'osint/fingerprint.html', active='osint',
        resultat=resultat, erreur=erreur
    )
