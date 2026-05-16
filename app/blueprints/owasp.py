from flask import Blueprint, render_template, request
import requests as req
import urllib3
urllib3.disable_warnings()

owasp_bp = Blueprint('owasp', __name__)

CHECKS = [
    {'nom':'Divulgation serveur',          'header':'Server',                      'present':False,'severite':'HAUTE',   'conseil':'Masquez la version du serveur dans la config Apache/Nginx.'},
    {'nom':'Technologie exposée',          'header':'X-Powered-By',                'present':False,'severite':'HAUTE',   'conseil':'Supprimez X-Powered-By dans votre config serveur.'},
    {'nom':'HSTS (Force HTTPS)',           'header':'Strict-Transport-Security',   'present':True, 'severite':'HAUTE',   'conseil':'Ajoutez : Strict-Transport-Security: max-age=31536000; includeSubDomains'},
    {'nom':'Content Security Policy',     'header':'Content-Security-Policy',     'present':True, 'severite':'HAUTE',   'conseil':'Définissez une politique CSP pour bloquer les injections XSS.'},
    {'nom':'Clickjacking (X-Frame)',       'header':'X-Frame-Options',             'present':True, 'severite':'MOYENNE', 'conseil':'Ajoutez : X-Frame-Options: DENY'},
    {'nom':'MIME Sniffing',               'header':'X-Content-Type-Options',      'present':True, 'severite':'MOYENNE', 'conseil':'Ajoutez : X-Content-Type-Options: nosniff'},
    {'nom':'Referrer Policy',             'header':'Referrer-Policy',             'present':True, 'severite':'MOYENNE', 'conseil':'Ajoutez : Referrer-Policy: strict-origin-when-cross-origin'},
    {'nom':'Permissions Policy',          'header':'Permissions-Policy',          'present':True, 'severite':'MOYENNE', 'conseil':'Restreignez caméra, micro, localisation.'},
    {'nom':'CORS trop permissif',         'header':'Access-Control-Allow-Origin', 'present':False,'severite':'MOYENNE', 'conseil':'Évitez Access-Control-Allow-Origin: * en production.'},
    {'nom':'Cache-Control',              'header':'Cache-Control',               'present':True, 'severite':'BASSE',   'conseil':'Ajoutez Cache-Control: no-store pour les pages sensibles.'},
    {'nom':'X-XSS-Protection (obsolète)','header':'X-XSS-Protection',            'present':True, 'severite':'BASSE',   'conseil':'Préférez CSP à ce header obsolète.'},
    {'nom':'Expect-CT',                  'header':'Expect-CT',                   'present':True, 'severite':'BASSE',   'conseil':'Ajoutez Expect-CT pour prévenir les certificats frauduleux.'},
]

def auditer(url):
    r = req.get(url, timeout=10, verify=False, allow_redirects=True)
    h = r.headers
    resultats = []
    stats = {'haute':0,'moyenne':0,'basse':0,'ok':0}
    for c in CHECKS:
        valeur = h.get(c['header'])
        vulnerable = not valeur if c['present'] else bool(valeur)
        if vulnerable:
            stats[c['severite'].lower()] += 1
        else:
            stats['ok'] += 1
        resultats.append({'nom':c['nom'],'statut':'VULNÉRABLE' if vulnerable else 'OK',
                          'severite':c['severite'] if vulnerable else '—',
                          'valeur':valeur or '(absent)','conseil':c['conseil'] if vulnerable else ''})
    return {'url':url,'status':r.status_code,'resultats':resultats,'stats':stats}

@owasp_bp.route('/owasp', methods=['GET', 'POST'])
def owasp():
    audit = None
    erreur = None
    if request.method == 'POST':
        url = request.form.get('url','').strip()
        if not url:
            erreur = 'Entrez une URL.'
        else:
            if not url.startswith('http'):
                url = 'http://' + url
            try:
                audit = auditer(url)
            except req.exceptions.Timeout:
                erreur = 'Timeout — la cible ne répond pas.'
            except req.exceptions.ConnectionError:
                erreur = 'Impossible de se connecter.'
            except Exception as e:
                erreur = f'Erreur : {e}'
    return render_template('owasp.html', active='owasp', audit=audit, erreur=erreur)
