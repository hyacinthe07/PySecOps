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
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 

# --- LE NOUVEAU DESIGN PRO ---
LAYOUT_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>PySecOps Cloud - Security Dashboard</title>
    <style>
        :root {
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --bg-sidebar: rgba(22, 27, 34, 0.95);
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-orange: #d29922;
            --text-main: #c9d1d9;
            --text-dim: #8b949e;
            --border-color: #30363d;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            background-color: var(--bg-dark); 
            color: var(--text-main); 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; 
            display: flex; 
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Sidebar Glassmorphism */
        .sidebar { 
            width: 250px; 
            background: var(--bg-sidebar); 
            backdrop-filter: blur(10px);
            border-right: 1px solid var(--border-color); 
            padding: 30px 0; 
            display: flex; 
            flex-direction: column; 
        }
        .logo { 
            padding: 0 20px 30px 20px; 
            border-bottom: 1px solid var(--border-color); 
            margin-bottom: 20px; 
        }
        .logo h1 { font-size: 20px; color: var(--accent-blue); letter-spacing: 1px; }
        .logo p { font-size: 11px; color: var(--text-dim); margin-top: 5px; text-transform: uppercase; letter-spacing: 2px; }
        
        .nav-link { 
            display: flex; 
            align-items: center; 
            padding: 12px 25px; 
            color: var(--text-dim); 
            text-decoration: none; 
            transition: all 0.2s ease; 
            border-left: 3px solid transparent; 
            font-size: 14px;
        }
        .nav-link:hover { color: var(--text-main); background: rgba(88, 166, 255, 0.05); border-left-color: var(--text-dim); }
        .nav-link.active { color: var(--accent-blue); background: rgba(88, 166, 255, 0.1); border-left-color: var(--accent-blue); font-weight: 600; }

        /* Main Content */
        .content { flex: 1; padding: 40px 50px; }
        .header { margin-bottom: 30px; border-bottom: 1px solid var(--border-color); padding-bottom: 15px; }
        .header h1 { font-size: 24px; font-weight: 600; color: var(--text-main); }
        .header p { color: var(--text-dim); font-size: 14px; margin-top: 5px; }

        /* Cards & Inputs */
        .card { background-color: var(--bg-card); padding: 25px; border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 25px; }
        input[type="text"], input[type="file"] { 
            background: var(--bg-dark); 
            border: 1px solid var(--border-color); 
            color: var(--text-main); 
            padding: 10px 15px; 
            border-radius: 6px; 
            width: 70%; 
            font-size: 14px;
            transition: border-color 0.2s;
        }
        input[type="text"]:focus { outline: none; border-color: var(--accent-blue); box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.2); }
        input[type="file"] { padding: 8px; }
        
        .btn { 
            background: linear-gradient(135deg, var(--accent-blue), #388bfd); 
            color: #fff; 
            border: none; 
            padding: 10px 25px; 
            border-radius: 6px; 
            font-weight: 600; 
            cursor: pointer; 
            font-size: 14px;
            transition: transform 0.1s, box-shadow 0.2s;
        }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(88, 166, 255, 0.3); }
        .btn:active { transform: translateY(0); }

        /* Results Display (Terminal Look but clean) */
        .result-box { 
            background: #010409; 
            border: 1px solid var(--border-color); 
            border-radius: 8px; 
            padding: 20px; 
            font-family: 'Fira Code', 'Courier New', monospace; 
            font-size: 13px; 
            line-height: 1.6; 
            margin-top: 20px; 
            white-space: pre-wrap; 
            box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
        }

        /* Tables */
        table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { color: var(--text-dim); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
        td { color: var(--text-main); }
        tr:hover { background-color: rgba(88, 166, 255, 0.05); }

        /* Status Badges */
        .badge { padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; display: inline-block; }
        .badge-success { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
        .badge-danger { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }
        .badge-warning { background: rgba(210, 153, 34, 0.15); color: var(--accent-orange); }
        
        /* Override text colors in results */
        .haute { color: var(--accent-red); font-weight: bold; }
        .moyenne { color: var(--accent-orange); font-weight: bold; }
        .basse { color: var(--accent-blue); }
        .ok { color: var(--accent-green); }

    </style>
</head>
<body>

    <div class="sidebar">
        <div class="logo">
            <h1>PYSECOPS</h1>
            <p>Security Dashboard</p>
        </div>
        <a href="/" class="nav-link {{ 'active' if active == 'home' else '' }}">Overview</a>
        <a href="/ports" class="nav-link {{ 'active' if active == 'ports' else '' }}">Port Scanner</a>
        <a href="/logs" class="nav-link {{ 'active' if active == 'logs' else '' }}">Log Analyzer</a>
        <a href="/secops" class="nav-link {{ 'active' if active == 'secops' else '' }}">Crypto & SecOps</a>
        <a href="/owasp" class="nav-link {{ 'active' if active == 'owasp' else '' }}">Web Audit (OWASP)</a>
        
        <div style="margin-top: auto; padding: 20px; border-top: 1px solid var(--border-color);">
            <p style="font-size: 11px; color: var(--text-dim);">Developed by</p>
            <p style="font-size: 13px; color: var(--accent-blue);">Hyacinthe</p>
        </div>
    </div>

    <div class="content">
        <div class="header">
            <h1>{{ titre }}</h1>
            <p>{{ soustitre }}</p>
        </div>
        <div class="card">{{ contenu|safe }}</div>
    </div>

</body>
</html>
"""

# --- ROUTES ---

@app.route('/')
def home():
    return render_template_string(LAYOUT_HTML, active="home", titre="Tableau de bord", soustitre="Vue d'ensemble de l'infrastructure", contenu="<p style='color: var(--text-dim)'>Bienvenue sur PySecOps Cloud. Sélectionnez un module dans le menu latéral pour commencer votre audit.</p>")

@app.route('/ports', methods=['GET', 'POST'])
def ports():
    contenu = """<form method="POST" style="display: flex; gap: 10px;"><input type="text" name="ip" placeholder="Adresse IP cible (ex: 127.0.0.1)" required style="flex:1; max-width: 400px;"> <button type="submit" class="btn">Launch Scan</button></form>"""
    if request.method == 'POST':
        ip = request.form['ip']
        top_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        resultat = f"[*] Initializing scan on target {ip}...\n"
        resultat += f"[*] Checking top 30 common ports...\n\n"
        ouverts = 0
        for port in top_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                resultat += f"[+] <span class='haute'>PORT {port}/tcp : OPEN</span>\n"
                ouverts += 1
            s.close()
        resultat += f"\n[*] Scan completed. <span class='ok'>{ouverts} open port(s)</span> found."
        contenu += f"<div class='result-box'>{resultat}</div>"
    return render_template_string(LAYOUT_HTML, active="ports", titre="Port Scanner", soustitre="Analyse des ports réseau (Top 30)", contenu=contenu)

@app.route('/logs', methods=['GET', 'POST'])
def logs():
    contenu = """<form method="POST" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;"><input type="file" name="logfile" accept=".log,.txt" required> <button type="submit" class="btn">Analyze</button></form>"""
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
            
            tableau = "<table><tr><th>IP Address</th><th>Requests</th><th>Threat Level</th><th>Status</th></tr>"
            for ip, total in top_ips:
                alertes = sum(1 for mot in mots_suspects if mot in texte)
                if alertes > 5: statut = "<span class='badge badge-danger'>HIGH RISK</span>"
                elif alertes > 0: statut = "<span class='badge badge-warning'>SUSPICIOUS</span>"
                else: statut = "<span class='badge badge-success'>CLEAN</span>"
                tableau += f"<tr><td>{ip}</td><td>{total}</td><td>{alertes}</td><td>{statut}</td></tr>"
            tableau += "</table>"
            contenu += tableau
    return render_template_string(LAYOUT_HTML, active="logs", titre="Log Analyzer", soustitre="Détection d'intrusions via les logs (Forensic)", contenu=contenu)

@app.route('/secops', methods=['GET', 'POST'])
def secops():
    contenu = """
    <h3 style="margin-bottom:15px; color:var(--text-dim);">PASSWORD & HASH TOOLS</h3>
    <form method="POST" style="display: flex; gap: 10px; margin-bottom: 30px;">
        <input type="text" name="action_mdp" placeholder="'gen' pour générer, 'test' pour vérifier" style="flex:1; max-width: 300px;"> 
        <input type="text" name="valeur" placeholder="Mot de passe (si test)" style="flex:1; max-width: 300px;">
        <button type="submit" class="btn">Exec</button>
    </form>
    """
    if request.method == 'POST':
        action = request.form.get('action_mdp', '').lower()
        valeur = request.form.get('valeur', '')
        if action == 'gen':
            alphabet = string.ascii_letters + string.digits + string.punctuation
            mdp = ''.join(secrets.choice(alphabet) for _ in range(16))
            contenu += f"<div class='result-box'>[+] Secure Password Generated : <span class='ok'>{mdp}</span></div>"
        elif action == 'test' and valeur:
            score = sum([len(valeur)>=8, len(valeur)>=12, bool(re.search(r"[A-Z]", valeur)), bool(re.search(r"[a-z]", valeur)), bool(re.search(r"\d", valeur)), bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", valeur))])
            if score <= 2: etat = "<span class='badge badge-danger'>WEAK</span>"
            elif score <= 4: etat = "<span class='badge badge-warning'>MEDIUM</span>"
            else: etat = "<span class='badge badge-success'>STRONG</span>"
            contenu += f"<div class='result-box'>[*] Security Score : {score}/6 <br>[+] Status : {etat}</div>"
    return render_template_string(LAYOUT_HTML, active="secops", titre="SecOps Tools", soustitre="Génération cryptographique et tests de robustesse", contenu=contenu)

@app.route('/owasp', methods=['GET', 'POST'])
def owasp():
    contenu = """<form method="POST" style="display: flex; gap: 10px;"><input type="text" name="url" placeholder="Target URL (ex: http://testphp.vulnweb.com)" required style="flex:1; max-width: 500px;"> <button type="submit" class="btn">Audit OWASP</button></form>"""
    if request.method == 'POST':
        url = request.form['url']
        if not url.startswith("http"): url = "http://" + url
        try:
            r = requests.get(url, timeout=8, verify=False)
            h = r.headers
            rapport = f"[*] Target : {url}\n"
            rapport += f"[*] Server Disclosure : {'<span class=\"haute\">EXPOSED - ' + h.get('Server', '') + '</span>' if h.get('Server') else '<span class=\"ok\">MASKED</span>'}\n"
            rapport += f"[*] Clickjacking (X-Frame) : {'<span class=\"moyenne\">MISSING</span>' if not h.get('X-Frame-Options') else '<span class=\"ok\">SECURED</span>'}\n"
            rapport += f"[*] Tech Stack (X-Powered-By) : {'<span class=\"haute\">EXPOSED - ' + h.get('X-Powered-By') + '</span>' if h.get('X-Powered-By') else '<span class=\"ok\">MASKED</span>'}\n"
            rapport += f"[*] Transport Layer (HSTS) : {'<span class=\"haute\">MISSING</span>' if not h.get('Strict-Transport-Security') else '<span class=\"ok\">SECURED</span>'}\n"
            rapport += f"[*] XSS Protection : {'<span class=\"basse\">OBSOLETE</span>' if not h.get('X-XSS-Protection') else '<span class=\"ok\">SECURED</span>'}\n"
            rapport += f"[*] Content Security Policy : {'<span class=\"haute\">MISSING (High Risk)</span>' if not h.get('Content-Security-Policy') else '<span class=\"ok\">SECURED</span>'}\n"
            contenu += f"<div class='result-box'>{rapport}</div>"
        except Exception as e:
            contenu += f"<div class='result-box'><span class='haute'>Error : {e}</span></div>"
    return render_template_string(LAYOUT_HTML, active="owasp", titre="Web Vulnerability Scanner", soustitre="Audit OWASP Top 10 des en-têtes HTTP", contenu=contenu)

if __name__ == '__main__':
    app.run(debug=True, port=8080, host='0.0.0.0')
