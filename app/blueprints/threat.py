from flask import Blueprint, render_template, request
from app.utils.threat_utils import analyser_threat
from app.utils.db_utils import enregistrer

threat_bp = Blueprint('threat', __name__)

@threat_bp.route('/threat', methods=['GET', 'POST'])
def threat():
    resultat = None
    erreur   = None
    if request.method == 'POST':
        cible = request.form.get('cible', '').strip()
        if not cible:
            erreur = "Entrez une IP ou un domaine."
        else:
            resultat = analyser_threat(cible)
            if "erreur" in resultat:
                erreur   = resultat["erreur"]
                resultat = None
            else:
                enregistrer("threat", cible)
    return render_template(
        'threat/index.html', active='threat',
        resultat=resultat, erreur=erreur
    )
