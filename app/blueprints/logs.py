from flask import Blueprint, render_template, request
from app.utils.log_analyzer_intelligent import analyser_logs_intelligent
from app.utils.db_utils import enregistrer

logs_bp = Blueprint('logs', __name__)


@logs_bp.route('/logs', methods=['GET', 'POST'])
def logs():
    analyse = None
    erreur  = None

    if request.method == 'POST':
        fichier = request.files.get('logfile')
        if not fichier or fichier.filename == '':
            erreur = "Aucun fichier sélectionné."
        else:
            try:
                texte = fichier.read().decode('utf-8', errors='ignore')
                if not texte.strip():
                    erreur = "Fichier vide."
                else:
                    analyse = analyser_logs_intelligent(texte)
                    if "erreur" in analyse:
                        erreur  = analyse["erreur"]
                        analyse = None
                    else:
                        enregistrer("logs", fichier.filename)
            except Exception as e:
                erreur = f"Erreur : {e}"

    return render_template(
        'logs.html', active='logs',
        analyse=analyse, erreur=erreur
    )
