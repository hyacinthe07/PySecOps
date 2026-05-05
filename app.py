from flask import Flask, request, render_template_string, redirect, url_for
import socket
import secrets
import string
import hashlib
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 # Limiter les uploads de logs à 1 Mo

# Le design complet du site (HTML/CSS)
LAYOUT_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>PySecOps Cloud - by hyacinthe</title>
    <style>
        body { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; display: flex; min-height: 100vh; }
        .sidebar { width: 220px; background-color: #1e1e1e; padding: 20px 0; border-right: 1px solid #333; }
        .sidebar h2 { color: #00ff00; text-align: center; font-family: 'Courier New', monospace; margin-bottom: 40px; }
        .sidebar a { display: block; padding: 15px 20px; color: #aaa; text-decoration: none; transition: 0.3s; }
        .sidebar a:hover, .sidebar a.active { background-color: #333; color: #00ff00; border-left: 4px solid #00ff00; }
        .content { flex: 1; padding: 40px; }
        .card { background-color: #1e1e1e; padding: 20px; border-radius: 8px; border: 1px solid #333; margin-bottom: 20px; }
        input[type="text"], input[type="file"] { padding: 10px; width: 60%; background: #2d2d2d; color: #0f0; border: 1px solid #444; border-radius: 4px; }
        button { padding: 10px 20px; background: #00ff00; color: #000; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
        button:hover { background: #00cc00; }
        .result-box { background: #000; padding: 20px; border-left: 4px solid #00ff00; margin-top: 20px; font-family: 'Courier New', monospace; white-space: pre-wrap; }
        .haute { color: #ff4444; } .moyenne { color: #ffaa00; } .ok { color: #00ff00; } .basse { color: #4488ff; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #444; padding: 10px; text-align: left; }
        th { background-color: #2d2d2d; color: #00bcd4; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>⚡ PySecOps</h2>
        <a href="/" class="{{ 'active' if active == 'home' else '' }}">🏠 Accueil</a>
        <a href="/ports" class="{{ 'active' if active == 'ports' else '' }}>📡 Scan Ports (Top 30)</a>
        <a href="/logs" class="{{ 'active' if active == 'logs' else '' }}">📋 Analyse Logs</a>
        <a href="/secops" class="{{ 'active' if active == 'secops' else '' }}">🔐 SecOps (Mdp/Hash)</a>
        <a href="/owasp" class="{{ 'active' if active == 'owasp' else '' }}">🛡️ Scan OWASP Web</a>
    </div>
    <div class="content">
        <h1>{{ titre }}</h1>
        <div class="card">{{ contenu|safe }}</div>
    </div>
</body>
</html>
"""

# --- ROUTE 1 : ACCUEIL ---
@app.route('/')
def home():
    return render_template_string(LAYOUT_HTML, active="home", titre="Tableau de bord PySecOps", contenu="<p style='color:#aaa'>Bienvenue sur PySecOps Cloud. Sélectionnez un module dans le menu de gauche.<br><br><span style='color:#ff00ff'>by hyacinthe</span></p>")

# --- ROUTE 2 : SCAN DE PORTS (TOP 30) ---
@app.route('/ports', methods=['GET', 'POST'])
def ports():
    contenu = """<form method="POST"><input type="text" name="ip" placeholder="Adresse IP (ex: 127.0.0.1)" required> <button type="submit">Scanner</button></form>"""
    if request.method == 'POST':
        ip = request.form['ip']
        top_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        resultat = f"[*] Scan des 30 ports les plus ciblés sur {ip}...\n"
        ouverts = 0
        for port in top_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                resultat += f"<span class='haute'>[+] Port {port}/tcp : OUVERT</span>\n"
                ouverts += 1
            s.close()
        resultat += f"\n[*] Scan terminé. {ouverts} port(s) ouvert(s) trouvé(s)."
        contenu += f"<div class='result-box'>{resultat}</div>"
    return render_template_string(LAYOUT_HTML, active="ports", titre="Scanner de Ports", contenu=contenu)

# --- ROUTE 3 : ANALYSE DE LOGS ---
@app.route('/logs', methods=['GET', 'POST'])
def logs():
    contenu = """<form method="POST" enctype="multipart/form-data"><input type="file" name="logfile" accept=".log,.txt" required> <button type="submit">Analyser</button></form>"""
    if request.method == 'POST':
        file = request.files['logfile']
        if file.filename != '':
            texte = file.read().decode('utf-8', errors='ignore')
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', texte)
            mots_suspects = ["404", "401", "403", "admin", "passwd", "../"]
            
            stats = {}
            for ip in ips:
                if ip in stats: stats[ip] += 1
                else: stats[ip] = 1
                
            top_ips = sorted(stats.items(), key=lambda x: x[1], reverse=True)[:5]
            
            tableau = "<table><tr><th>Adresse IP</th><th>Requêtes</th><th>Alertes</th><th>Statut</th></tr>"
            for ip, total in top_ips:
                alertes = sum(1 for mot in mots_suspects if mot in texte)
                statut = "<span class='haute'>DANGEREUX</span>" if alertes > 5 else "<span class='moyenne'>SUSPECT</span>" if alertes > 0 else "<span class='ok'>NORMAL</span>"
                tableau += f"<tr><td>{ip}</td><td>{total}</td><td>{alertes}</td><td>{statut}</td></tr>"
            tableau += "</table>"
            contenu += tableau
    return render_template_string(LAYOUT_HTML, active="logs", titre="Analyseur de Logs (Forensic)", contenu=contenu)

# --- ROUTE 4 : SECOPS (MOTS DE PASSE / HASH) ---
@app.route('/secops', methods=['GET', 'POST'])
def secops():
    contenu = """
    <form method="POST">
        <input type="text" name="action_mdp" placeholder="Tape 'gen' pour générer ou 'test' pour vérifier"> 
        <input type="text" name="valeur" placeholder="Mot de passe (si test)">
        <button type="submit">Exécuter</button>
    </form>
    <h3>Hachage SHA-256</h3>
    <form method="POST" action="/secops/hash">
        <input type="text" name="texte_hash" placeholder="Texte à hacher"> <button type="submit">Hacher</button>
    </form>
    """
    if request.method == 'POST':
        action = request.form.get('action_mdp', '').lower()
        valeur = request.form.get('valeur', '')
        if action == 'gen':
            alphabet = string.ascii_letters + string.digits + string.punctuation
            mdp = ''.join(secrets.choice(alphabet) for _ in range(16))
            contenu += f"<div class='result-box'>[+] Mot de passe sécurisé : <span class='ok'>{mdp}</span></div>"
        elif action == 'test' and valeur:
            score = sum([len(valeur)>=8, len(valeur)>=12, bool(re.search(r"[A-Z]", valeur)), bool(re.search(r"[a-z]", valeur)), bool(re.search(r"\d", valeur)), bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", valeur))])
            etat = "<span class='haute'>FAIBLE</span>" if score <= 2 else "<span class='moyenne'>MOYEN</span>" if score <= 4 else "<span class='ok'>FORT</span>"
            contenu += f"<div class='result-box'>[*] Score : {score}/6 - Statut : {etat}</div>"
    return render_template_string(LAYOUT_HTML, active="secops", titre="Outils SecOps", contenu=contenu)

@app.route('/secops/hash', methods=['POST'])
def secops_hash():
    texte = request.form.get('texte_hash', '')
    if texte:
        hash_hex = hashlib.sha256(texte.encode('utf-8')).hexdigest()
        resultat = f"[+] Texte : {texte}\n[+] Hash SHA-256 : <span class='ok'>{hash_hex}</span>"
    else:
        resultat = "[-] Aucun texte fourni."
    return render_template_string(LAYOUT_HTML, active="secops", titre="Outils SecOps", contenu=f"<div class='result-box'>{resultat}</div><br><a href='/secops'>Retour</a>")

# --- ROUTE 5 : OWASP WEB SCAN ---
@app.route('/owasp', methods=['GET', 'POST'])
def owasp():
    contenu = """<form method="POST"><input type="text" name="url" placeholder="URL cible (ex: http://testphp.vulnweb.com)" required> <button type="submit">Audit OWASP</button></form>"""
    if request.method == 'POST':
        url = request.form['url']
        if not url.startswith("http"): url = "http://" + url
        try:
            r = requests.get(url, timeout=8, verify=False)
            h = r.headers
            rapport = f"[*] Cible : {url}\n"
            rapport += f"[*] Serveur exposé : {'<span class=\"haute\">' + h.get('Server', 'Masqué') + '</span>' if h.get('Server') else '<span class=\"ok\">Masqué</span>'}\n"
            rapport += f"[*] Clickjacking (X-Frame) : {'<span class=\"moyenne\">MANQUANT</span>' if not h.get('X-Frame-Options') else '<span class=\"ok\">OK</span>'}\n"
            rapport += f"[*] Techno exposée (X-Powered-By) : {'<span class=\"haute\">' + h.get('X-Powered-By') + '</span>' if h.get('X-Powered-By') else '<span class=\"ok\">Masquée</span>'}\n"
            rapport += f"[*] Couche transport (HSTS) : {'<span class=\"haute\">MANQUANT</span>' if not h.get('Strict-Transport-Security') else '<span class=\"ok\">OK</span>'}\n"
            rapport += f"[*] Protection XSS : {'<span class=\"basse\">OBSOLETE</span>' if not h.get('X-XSS-Protection') else '<span class=\"ok\">OK</span>'}\n"
            rapport += f"[*] Policy (CSP) : {'<span class=\"haute\">MANQUANT (Risque XSS élevé)</span>' if not h.get('Content-Security-Policy') else '<span class=\"ok\">OK</span>'}\n"
            contenu += f"<div class='result-box'>{rapport}</div>"
        except Exception as e:
            contenu += f"<div class='result-box'><span class='haute'>Erreur : {e}</span></div>"
    return render_template_string(LAYOUT_HTML, active="owasp", titre="Scan OWASP Web", contenu=contenu)

if __name__ == '__main__':
    app.run(debug=True, port=8080, host='0.0.0.0')
