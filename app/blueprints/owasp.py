from flask import Blueprint, render_template, request
from app.utils.vuln_scanner_actif import scanner_vulnerabilites
from app.utils.db_utils import enregistrer

owasp_bp = Blueprint('owasp', __name__)

@owasp_bp.route('/owasp', methods=['GET', 'POST'])
def owasp():
    audit  = None
    erreur = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            erreur = "Entrez une URL."
        else:
            if not url.startswith('http'):
                url = 'http://' + url
            audit = scanner_vulnerabilites(url)
            enregistrer("owasp", url)
    return render_template('owasp.html', active='owasp',
                           audit=audit, erreur=erreur)
