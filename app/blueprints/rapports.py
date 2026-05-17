"""
PySecOps — Blueprint Rapports PDF
Reçoit les données via POST et retourne un PDF téléchargeable.
"""
from flask import Blueprint, request, send_file, abort
from app.utils.pdf_utils import (
    rapport_ssl, rapport_owasp, rapport_ports,
    rapport_whois, rapport_ip
)
import io
import datetime

rapports_bp = Blueprint('rapports', __name__)


def _pdf_response(pdf_bytes: bytes, nom: str):
    """Retourne une réponse Flask avec le PDF en téléchargement."""
    buffer = io.BytesIO(pdf_bytes)
    buffer.seek(0)
    date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"pysecops_{nom}_{date}.pdf"
    )


@rapports_bp.route('/rapport/ssl', methods=['POST'])
def pdf_ssl():
    import json
    data = json.loads(request.form.get('data', '{}'))
    if not data:
        abort(400)
    return _pdf_response(rapport_ssl(data), "ssl")


@rapports_bp.route('/rapport/owasp', methods=['POST'])
def pdf_owasp():
    import json
    data = json.loads(request.form.get('data', '{}'))
    if not data:
        abort(400)
    return _pdf_response(rapport_owasp(data), "owasp")


@rapports_bp.route('/rapport/ports', methods=['POST'])
def pdf_ports():
    import json
    data = json.loads(request.form.get('data', '{}'))
    if not data:
        abort(400)
    return _pdf_response(rapport_ports(data), "ports")


@rapports_bp.route('/rapport/whois', methods=['POST'])
def pdf_whois():
    import json
    whois_data = json.loads(request.form.get('whois_data', '{}'))
    dns_data   = json.loads(request.form.get('dns_data',   '{}'))
    if not whois_data:
        abort(400)
    return _pdf_response(rapport_whois(whois_data, dns_data), "whois_dns")


@rapports_bp.route('/rapport/ip', methods=['POST'])
def pdf_ip():
    import json
    data = json.loads(request.form.get('data', '{}'))
    if not data:
        abort(400)
    return _pdf_response(rapport_ip(data), "ip_intel")
