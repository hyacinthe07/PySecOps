"""
PySecOps — Blueprint Deep Recon Engine
"""
from flask import Blueprint, render_template, request, Response, stream_with_context
from app.utils.recon_utils import (
    scan_complet, enumerer_subdomains,
    scanner_secrets, detecter_technologies, chercher_cves
)
from app.utils.db_utils import enregistrer
import json

recon_bp = Blueprint('recon', __name__)


@recon_bp.route('/recon')
def recon():
    return render_template('recon/index.html', active='recon')


@recon_bp.route('/recon/scan', methods=['GET', 'POST'])
def deep_scan():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        cible = request.form.get('cible', '').strip()
        if not cible:
            erreur = "Entrez une cible (IP ou domaine)."
        else:
            resultat = scan_complet(cible)
            if "erreur" in resultat:
                erreur   = resultat["erreur"]
                resultat = None
            else:
                enregistrer("recon_scan", cible)
    return render_template(
        'recon/scan.html', active='recon',
        resultat=resultat, erreur=erreur
    )


@recon_bp.route('/recon/subdomains', methods=['GET', 'POST'])
def subdomains():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        domaine = request.form.get('domaine', '').strip()
        if not domaine:
            erreur = "Entrez un nom de domaine."
        else:
            resultat = enumerer_subdomains(domaine)
            enregistrer("recon_sub", domaine)
    return render_template(
        'recon/subdomains.html', active='recon',
        resultat=resultat, erreur=erreur
    )


@recon_bp.route('/recon/secrets', methods=['GET', 'POST'])
def secrets():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            erreur = "Entrez une URL."
        else:
            if not url.startswith('http'):
                url = 'http://' + url
            resultat = {
                "url":     url,
                "secrets": scanner_secrets(url),
            }
            enregistrer("recon_secrets", url)
    return render_template(
        'recon/secrets.html', active='recon',
        resultat=resultat, erreur=erreur
    )


@recon_bp.route('/recon/cve', methods=['GET', 'POST'])
def cve_lookup():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip()
        nb      = int(request.form.get('nb', 10))
        if not keyword:
            erreur = "Entrez un service ou une version."
        else:
            cves = chercher_cves(keyword, max_results=nb)
            resultat = {"keyword": keyword, "cves": cves, "total": len(cves)}
            enregistrer("recon_cve", keyword)
    return render_template(
        'recon/cve.html', active='recon',
        resultat=resultat, erreur=erreur
    )
