"""
PySecOps — Blueprint IDS / Forensique
"""
from flask import Blueprint, render_template, request
from app.utils.ids_utils import analyser_complet
from app.utils.db_utils import enregistrer

ids_bp = Blueprint('ids', __name__)


@ids_bp.route('/ids', methods=['GET', 'POST'])
def ids():
    resultat = None
    erreur   = None

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
                    resultat = analyser_complet(texte)
                    if "erreur" not in resultat:
                        enregistrer("ids", fichier.filename)
            except Exception as e:
                erreur = f"Erreur : {e}"

    return render_template(
        'ids/index.html',
        active='ids',
        resultat=resultat,
        erreur=erreur
    )
