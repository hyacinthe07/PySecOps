from flask import Blueprint, render_template, request
from app.utils.stats_utils import incrementer
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

ports_bp = Blueprint('ports', __name__)

SERVICES = {
    21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
    80:'HTTP', 110:'POP3', 135:'RPC', 139:'NetBIOS', 143:'IMAP',
    443:'HTTPS', 445:'SMB', 993:'IMAPS', 995:'POP3S', 1433:'MSSQL',
    1723:'PPTP', 3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL',
    5900:'VNC', 6379:'Redis', 8080:'HTTP-Alt', 8443:'HTTPS-Alt',
    27017:'MongoDB', 9200:'Elasticsearch',
}

def _scan_port(target: str, port: int):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((target, port)) == 0:
                return {'port': port, 'service': SERVICES.get(port, 'Unknown'), 'banner': ''}
    except Exception:
        pass
    return None

def lancer_scan(target: str, port_range: int = 1024) -> dict:
    ports_ouverts = []
    with ThreadPoolExecutor(max_workers=150) as ex:
        futures = {ex.submit(_scan_port, target, p): p for p in range(1, port_range + 1)}
        for f in as_completed(futures):
            r = f.result()
            if r:
                ports_ouverts.append(r)
    ports_ouverts.sort(key=lambda x: x['port'])
    return {
        'ports':  ports_ouverts,
        'total':  len(ports_ouverts),
        'target': target,
        'range':  port_range,
    }

@ports_bp.route('/ports', methods=['GET', 'POST'])
def ports():
    resultats = None
    erreur    = None

    if request.method == 'POST':
        ip         = request.form.get('ip', '').strip()
        port_range = int(request.form.get('port_range', 1024))

        if not ip:
            erreur = "Entrez une IP ou un nom de domaine."
        else:
            try:
                socket.gethostbyname(ip)
                resultats = lancer_scan(ip, port_range)
                incrementer("ports", ip)
            except socket.gaierror:
                erreur = f"Hôte '{ip}' introuvable."
            except Exception as e:
                erreur = f"Erreur : {e}"

    return render_template(
        'scanner.html',
        active='ports',
        resultats=resultats,
        erreur=erreur
    )
