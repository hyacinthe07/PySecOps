from flask import Blueprint, render_template, request
from app.utils.db_utils import enregistrer as incrementer
import re
from collections import Counter

logs_bp = Blueprint('logs', __name__)

SIGNATURES = {
    'critique': ['etc/passwd','cmd=','exec(','base64_decode','union select','<script>','/bin/sh'],
    'elevated':  ['wp-admin','phpmyadmin','admin','login','.env','backup','config'],
    'normal':    ['404','401','403','../','passwd'],
}

def analyser_logs(texte: str) -> dict:
    lignes = texte.splitlines()
    toutes_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', texte)
    ip_requetes = Counter(toutes_ips)
    ip_alertes = {}

    for ligne in lignes:
        m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ligne)
        if not m:
            continue
        ip = m.group(0)
        ll = ligne.lower()
        if ip not in ip_alertes:
            ip_alertes[ip] = {'critique': 0, 'elevated': 0, 'normal': 0}
        for niveau, mots in SIGNATURES.items():
            if any(mot in ll for mot in mots):
                ip_alertes[ip][niveau] += 1

    resultats = []
    for ip, total in ip_requetes.most_common(10):
        a = ip_alertes.get(ip, {'critique': 0, 'elevated': 0, 'normal': 0})
        if a['critique'] > 0:
            statut = 'CRITIQUE'
        elif a['elevated'] > 2:
            statut = 'ÉLEVÉ'
        elif sum(a.values()) > 0:
            statut = 'SUSPECT'
        else:
            statut = 'NORMAL'
        resultats.append({
            'ip':       ip,
            'total':    total,
            'critique': a['critique'],
            'elevated': a['elevated'],
            'statut':   statut,
        })

    return {
        'resultats':       resultats,
        'total_lignes':    len(lignes),
        'total_ips':       len(ip_requetes),
        'total_requetes':  len(toutes_ips),
    }


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
                    erreur = "Le fichier est vide."
                else:
                    analyse = analyser_logs(texte)
                    incrementer("logs", fichier.filename)
            except Exception as e:
                erreur = f"Erreur lors de la lecture : {e}"

    return render_template(
        'logs.html',
        active='logs',
        analyse=analyse,
        erreur=erreur
    )
