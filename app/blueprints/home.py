from flask import Blueprint, render_template, send_from_directory, jsonify
from app.utils.db_utils import get_stats
import os

home_bp = Blueprint('home', __name__)

# Trouver le bon chemin automatiquement
def get_build_path():
    """Cherche le dossier frontend/build dans plusieurs endroits possibles."""
    candidats = [
        os.path.join(os.path.dirname(__file__), '..', '..', 'frontend', 'build'),
        os.path.join(os.getcwd(), 'frontend', 'build'),
        '/opt/render/project/src/frontend/build',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'frontend', 'build'),
    ]
    for chemin in candidats:
        chemin = os.path.abspath(chemin)
        if os.path.exists(os.path.join(chemin, 'index.html')):
            return chemin
    return None

FRONTEND_BUILD = get_build_path()


@home_bp.route('/debug-path')
def debug_path():
    """Route de debug pour voir les chemins sur Render."""
    return jsonify({
        "cwd":           os.getcwd(),
        "frontend_build":FRONTEND_BUILD,
        "exists":        FRONTEND_BUILD is not None,
        "candidats": [
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'frontend', 'build')),
            os.path.join(os.getcwd(), 'frontend', 'build'),
            '/opt/render/project/src/frontend/build',
        ]
    })


@home_bp.route('/')
def home():
    if FRONTEND_BUILD:
        return send_from_directory(FRONTEND_BUILD, 'index.html')
    stats = get_stats()
    stats.setdefault('recon_scan', 0)
    stats.setdefault('ids', 0)
    stats['modules'] = 15
    return render_template('home.html', active='home', stats=stats)


@home_bp.route('/static/js/<path:filename>')
def react_js(filename):
    if FRONTEND_BUILD:
        return send_from_directory(os.path.join(FRONTEND_BUILD, 'static', 'js'), filename)
    return '', 404


@home_bp.route('/static/css/<path:filename>')
def react_css(filename):
    if FRONTEND_BUILD:
        return send_from_directory(os.path.join(FRONTEND_BUILD, 'static', 'css'), filename)
    return '', 404


@home_bp.route('/static/media/<path:filename>')
def react_media(filename):
    if FRONTEND_BUILD:
        return send_from_directory(os.path.join(FRONTEND_BUILD, 'static', 'media'), filename)
    return '', 404


@home_bp.route('/logo192.png')
def logo192():
    if FRONTEND_BUILD:
        return send_from_directory(FRONTEND_BUILD, 'logo192.png')
    return '', 404


@home_bp.route('/favicon.ico')
def favicon():
    if FRONTEND_BUILD:
        return send_from_directory(FRONTEND_BUILD, 'favicon.ico')
    return '', 404
