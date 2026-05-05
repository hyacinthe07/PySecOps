from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

# Le design de ton site web
PAGE_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>PySecOps OWASP Scanner - by hyacinthe</title>
    <style>
        body { background-color: #1e1e1e; color: #d4d4d4; font-family: 'Courier New', Courier, monospace; text-align: center; padding: 40px; }
        h1 { color: #00ff00; }
        .signature { color: #ff00ff; margin-bottom: 30px; }
        input[type="text"] { padding: 10px; width: 350px; background: #333; color: #0f0; border: 1px solid #0f0; font-family: monospace; }
        button { padding: 10px 20px; background: #0f0; color: #000; border: none; font-family: monospace; font-weight: bold; cursor: pointer; }
        button:hover { background: #0c0; }
        .rapport { margin-top: 30px; text-align: left; display: inline-block; background: #252526; padding: 20px; border-left: 3px solid #0f0; max-width: 800px; width: 100%; box-sizing: border-box; }
        .ligne { border-bottom: 1px solid #444; padding: 8px 0; }
        .haute { color: #ff4444; font-weight: bold; }
        .moyenne { color: #ffaa00; font-weight: bold; }
        .basse { color: #4488ff; font-weight: bold; }
        .ok { color: #00ff00; }
    </style>
</head>
<body>
    <h1>⚡ PYSECOPS OWASP SCANNER ⚡</h1>
    <div class="signature">Analyse OWASP Top 10 - by hyacinthe</div>

    <form method="POST">
        <input type="text" name="url" placeholder="URL cible (ex: testphp.vulnweb.com)" required>
        <button type="submit">Audit OWASP</button>
    </form>

    {% if rapport %}
    <div class="rapport">
        <h3>Résultats pour : {{ cible }}</h3>
        {{ rapport|safe }}
    </div>
    {% endif %}
</body>
</html>
"""

def analyser_owasp(url):
    rapport_html = ""
    try:
        reponse = requests.get(url, timeout=8, verify=False)
        en_tetes = reponse.headers
        cookies = reponse.cookies
        
        # 1. Mauvaise configuration de sécurité (Divulgation)
        serveur = en_tetes.get("Server", "Masqué")
        rapport_html += f"<div class='ligne'>[Faille 5] <b>Divulgation Tech (Server) :</b> {'<span class=\"haute\">VULNÉRABLE - ' + serveur + '</span>' if serveur != 'Masqué' else '<span class=\"ok\">OK (Masqué)</span>'}</div>"

        techno = en_tetes.get("X-Powered-By", "Masqué")
        rapport_html += f"<div class='ligne'>[Faille 5] <b>Divulgation Tech (X-Powered-By) :</b> {'<span class=\"moyenne\">VULNÉRABLE - ' + techno + '</span>' if techno != 'Masqué' else '<span class=\"ok\">OK (Masqué)</span>'}</div>"

        # 2. Protection insuffisante de la couche transport (HSTS)
        hsts = en_tetes.get("Strict-Transport-Security")
        rapport_html += f"<div class='ligne'>[Faille 2] <b>Couche Transport (HSTS) :</b> {'<span class=\"haute\">MANQUANT (Risque Intercept)</span>' if not hsts else '<span class=\"ok\">OK (' + hsts + ')</span>'}</div>"

        # 3. Violation de gestion d'authentification et de session (Cookies)
        cookie_issues = []
        for c in cookies:
            if not c.secure: cookie_issues.append(f"{c.name} manque 'Secure'")
            if not c.has_nonstandard_attr('HttpOnly'): cookie_issues.append(f"{c.name} manque 'HttpOnly' (Risque XSS)")
            if not c.get_nonstandard_attr('SameSite'): cookie_issues.append(f"{c.name} manque 'SameSite' (Risque CSRF)")
        
        if cookie_issues:
            rapport_html += f"<div class='ligne'>[Faille 2 & 7] <b>Gestion Session (Cookies) :</b> <span class='haute'>{', '.join(cookie_issues)}</span></div>"
        elif not cookies:
            rapport_html += f"<div class='ligne'>[Faille 2] <b>Gestion Session :</b> <span class='moyenne'>Aucun cookie détecté (Possible stateless)</span></div>"
        else:
            rapport_html += f"<div class='ligne'>[Faille 2 & 7] <b>Gestion Session :</b> <span class='ok'>Cookies sécurisés</span></div>"

        # 4. Falsification de requêtes intersite (CSRF) - Indirect via X-Frame
        xfo = en_tetes.get("X-Frame-Options")
        rapport_html += f"<div class='ligne'>[Faille 8] <b>CSRF / Clickjacking (X-Frame) :</b> {'<span class=\"moyenne\">MANQUANT (Risque Clickjacking)</span>' if not xfo else '<span class=\"ok\">OK (' + xfo + ')</span>'}</div>"

        # 5. Cross-Site Scripting (XSS) - Indirect
        xss = en_tetes.get("X-XSS-Protection")
        rapport_html += f"<div class='ligne'>[Faille 3] <b>XSS (Protection) :</b> {'<span class=\"basse\">MANQUANT (Dépend du CSP)</span>' if not xss else '<span class=\"ok\">OK (' + xss + ')</span>'}</div>"

        # 6. Stockage cryptographique (Indicateur Content-Security-Policy)
        csp = en_tetes.get("Content-Security-Policy")
        rapport_html += f"<div class='ligne'>[Faille 3, 6, 9] <b>Policy Générale (CSP) :</b> {'<span class=\"haute\">MANQUANT (Faille XSS/Injection très probable)</span>' if not csp else '<span class=\"ok\">OK (Protège contre injections)</span>'}</div>"

        # 7. Référence directe non sécurisée / Injection (Impossible de tester passivement)
        rapport_html += f"<div class='ligne'>[Faille 1 & 4] <b>Injection (SQL/XSS) & Accès URL :</b> <span class='moyenne'>Nécessite un scanner actif (Burp Suite) pour tester</span></div>"

        # 8. Redirections non validées
        rapport_html += f"<div class='ligne'>[Faille 10] <b>Redirections :</b> <span class='moyenne'>Nécessite l'analyse des formulaires HTML</span></div>"

    except Exception as e:
        rapport_html = f"<div class='haute'>Erreur de connexion : {e}</div>"

    return rapport_html

# Désactiver l'avertissement SSL pour les tests (ne pas faire en prod !)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@app.route('/', methods=['GET', 'POST'])
def home():
    rapport = None
    cible = ""
    if request.method == 'POST':
        cible = request.form['url']
        if not cible.startswith("http"):
            cible = "http://" + cible
        rapport = analyser_owasp(cible)
    
    return render_template_string(PAGE_HTML, rapport=rapport, cible=cible)

if __name__ == '__main__':
   app.run(host="0.0.0.0", port=8080)
