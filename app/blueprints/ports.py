from flask import Blueprint, render_template, request
from app.utils.vuln_scanner_actif import scan_ports_complet
from app.utils.db_utils import enregistrer

ports_bp = Blueprint('ports', __name__)

@ports_bp.route('/ports', methods=['GET', 'POST'])
def ports():
    resultats = None
    erreur    = None
    if request.method == 'POST':
        ip         = request.form.get('ip', '').strip()
        port_range = int(request.form.get('port_range', 1024))
        if not ip:
            erreur = "Entrez une IP ou un nom de domaine."
        else:
            resultats = scan_ports_complet(ip, port_range)
            if "erreur" in resultats:
                erreur    = resultats["erreur"]
                resultats = None
            else:
                enregistrer("ports", ip)
    return render_template('scanner.html', active='ports',
                           resultats=resultats, erreur=erreur)
