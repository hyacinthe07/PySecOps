"""
PySecOps — Blueprint Import Nmap XML
"""
from flask import Blueprint, render_template, request
from app.utils.nmap_analyzer import analyser_nmap_complet
from app.utils.db_utils import enregistrer

nmap_bp = Blueprint('nmap', __name__)


@nmap_bp.route('/nmap-import', methods=['GET', 'POST'])
def nmap_import():
    resultat = None
    erreur   = None

    if request.method == 'POST':
        fichier = request.files.get('nmap_xml')
        if not fichier or fichier.filename == '':
            erreur = "Aucun fichier sélectionné."
        elif not fichier.filename.endswith('.xml'):
            erreur = "Le fichier doit être au format XML (.xml)."
        else:
            try:
                contenu = fichier.read().decode('utf-8', errors='ignore')
                if not contenu.strip():
                    erreur = "Fichier vide."
                else:
                    resultat = analyser_nmap_complet(contenu)
                    if "erreur" in resultat:
                        erreur   = resultat["erreur"]
                        resultat = None
                    else:
                        enregistrer("nmap_import", fichier.filename)
            except Exception as e:
                erreur = f"Erreur lors de l'analyse : {e}"

    return render_template(
        'nmap/index.html',
        active='nmap',
        resultat=resultat,
        erreur=erreur
    )
