from flask import Blueprint, render_template, request
import secrets, string, hashlib, re, base64

secops_bp = Blueprint('secops', __name__)

def generer_mdp(n=16):
    alpha = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alpha) for _ in range(n))

def hacher(texte):
    b = texte.encode('utf-8')
    return {'md5':hashlib.md5(b).hexdigest(),'sha1':hashlib.sha1(b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}

def verifier_force(mdp):
    criteres = {
        'Longueur ≥ 8':   len(mdp)>=8,
        'Longueur ≥ 12':  len(mdp)>=12,
        'Majuscule':      bool(re.search(r'[A-Z]',mdp)),
        'Minuscule':      bool(re.search(r'[a-z]',mdp)),
        'Chiffre':        bool(re.search(r'\d',mdp)),
        'Symbole':        bool(re.search(r'[!@#$%^&*(),.?\":{}|<>]',mdp)),
        'Pas commun':     mdp.lower() not in ['password','123456','azerty','admin','qwerty'],
    }
    score = sum(criteres.values())
    niveau = 'FORT' if score >= 6 else ('MOYEN' if score >= 4 else 'FAIBLE')
    return {'criteres':criteres,'score':score,'max':len(criteres),'niveau':niveau}

def conv_base64(texte, action):
    try:
        if action == 'encode':
            return base64.b64encode(texte.encode()).decode()
        return base64.b64decode(texte.encode()).decode()
    except Exception as e:
        return f"Erreur : {e}"

@secops_bp.route('/secops', methods=['GET', 'POST'])
def secops():
    resultat = None
    action_active = None
    if request.method == 'POST':
        action_active = request.form.get('action')
        if action_active == 'generer':
            try:
                n = max(8, min(64, int(request.form.get('longueur', 16))))
                resultat = {'mdp': generer_mdp(n)}
            except ValueError:
                resultat = {'erreur': 'Longueur invalide.'}
        elif action_active == 'hash':
            t = request.form.get('texte_hash','').strip()
            resultat = hacher(t) if t else {'erreur':'Texte vide.'}
        elif action_active == 'force':
            m = request.form.get('mdp_test','').strip()
            resultat = verifier_force(m) if m else {'erreur':'Vide.'}
        elif action_active == 'base64':
            t = request.form.get('texte_b64','').strip()
            s = request.form.get('sens_b64','encode')
            resultat = {'resultat': conv_base64(t,s)} if t else {'erreur':'Texte vide.'}
    return render_template('secops.html', active='secops', resultat=resultat, action_active=action_active)
