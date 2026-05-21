from flask import Blueprint, render_template
from app.utils.db_utils import get_stats

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def home():
    stats = get_stats()
    # Ajouter les compteurs manquants avec valeur par défaut
    stats.setdefault('recon_scan', 0)
    stats.setdefault('ids', 0)
    stats.setdefault('audit', 0)
    stats['modules'] = 14  # Nombre réel de modules actifs
    return render_template('home.html', active='home', stats=stats)


@home_bp.route('/dashboard-v3')
def react_dashboard():
    from flask import send_from_directory
    return send_from_directory('../frontend/build', 'index.html')

@home_bp.route('/dashboard-v3/<path:path>')
def react_static(path):
    from flask import send_from_directory
    return send_from_directory('../frontend/build', path)


@home_bp.route('/dashboard-v3')
def react_dashboard():
    from flask import send_from_directory
    return send_from_directory('../frontend/build', 'index.html')

@home_bp.route('/dashboard-v3/<path:path>')
def react_static(path):
    from flask import send_from_directory
    return send_from_directory('../frontend/build', path)
