"""
PySecOps — Blueprint Rapport d'audit PTES
"""
from flask import Blueprint, render_template, request, send_file, abort
from app.utils.rapport_audit import generer_rapport_ptes
from app.utils.db_utils import enregistrer
import io
import datetime
import json

audit_bp = Blueprint('audit', __name__)


@audit_bp.route('/audit', methods=['GET', 'POST'])
def audit():
    """Interface de création du rapport d'audit PTES."""
    return render_template('audit/index.html', active='audit')


@audit_bp.route('/audit/generer', methods=['POST'])
def generer():
    """Génère le rapport PDF PTES depuis le formulaire."""
    try:
        meta = {
            "titre":    request.form.get("titre",    "Audit de sécurité"),
            "cible":    request.form.get("cible",    "—"),
            "client":   request.form.get("client",   "Confidentiel"),
            "auditeur": request.form.get("auditeur", "Hyacinthe — PySecOps"),
        }

        # Récupérer les findings depuis le formulaire
        findings = []
        nb = int(request.form.get("nb_findings", 0))

        for i in range(1, nb + 1):
            f = {
                "id":          request.form.get(f"f{i}_id",          f"VULN-{i:03d}"),
                "titre":       request.form.get(f"f{i}_titre",        ""),
                "severite":    request.form.get(f"f{i}_severite",     "MOYENNE"),
                "cvss":        request.form.get(f"f{i}_cvss",         "0.0"),
                "categorie":   request.form.get(f"f{i}_categorie",    ""),
                "composant":   request.form.get(f"f{i}_composant",    ""),
                "localisation":request.form.get(f"f{i}_localisation", ""),
                "description": request.form.get(f"f{i}_description",  ""),
                "evidence":    request.form.get(f"f{i}_evidence",     ""),
                "impact":      request.form.get(f"f{i}_impact",       ""),
                "remediation": request.form.get(f"f{i}_remediation",  ""),
            }
            if f["titre"]:
                findings.append(f)

        if not findings:
            return render_template(
                'audit/index.html', active='audit',
                erreur="Ajoutez au moins une vulnérabilité."
            )

        pdf = generer_rapport_ptes(meta, findings)
        enregistrer("audit", meta["cible"])

        buffer = io.BytesIO(pdf)
        buffer.seek(0)
        date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"pysecops_audit_{date}.pdf"
        )

    except Exception as e:
        return render_template(
            'audit/index.html', active='audit',
            erreur=f"Erreur génération PDF : {e}"
        )
