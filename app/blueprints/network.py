"""
PySecOps — Blueprint Network Intelligence
Routes pour WHOIS, DNS et IP Intelligence.
"""
from flask import Blueprint, render_template, request
from app.utils.network_utils import analyser_whois, analyser_dns, analyser_ip

network_bp = Blueprint('network', __name__)


@network_bp.route('/whois', methods=['GET', 'POST'])
def whois():
    whois_data = None
    dns_data   = None
    erreur     = None

    if request.method == 'POST':
        domaine = request.form.get('domaine', '').strip()
        if not domaine:
            erreur = "Veuillez entrer un nom de domaine."
        else:
            whois_data = analyser_whois(domaine)
            dns_data   = analyser_dns(domaine)
            if "erreur" in whois_data and "erreur" in dns_data:
                erreur = whois_data["erreur"]
                whois_data = None
                dns_data   = None

    return render_template(
        'network/whois.html',
        active='whois',
        whois_data=whois_data,
        dns_data=dns_data,
        erreur=erreur
    )


@network_bp.route('/ip-intel', methods=['GET', 'POST'])
def ip_intel():
    resultat = None
    erreur   = None

    if request.method == 'POST':
        cible = request.form.get('cible', '').strip()
        if not cible:
            erreur = "Veuillez entrer une adresse IP ou un nom de domaine."
        else:
            resultat = analyser_ip(cible)
            if "erreur" in resultat:
                erreur   = resultat["erreur"]
                resultat = None

    return render_template(
        'network/ip_intel.html',
        active='ip_intel',
        resultat=resultat,
        erreur=erreur
    )
