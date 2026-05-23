from flask import Blueprint, render_template, send_from_directory, jsonify
from app.utils.db_utils import get_stats
import os

home_bp = Blueprint('home', __name__)

# Render exécute depuis /opt/render/project/src/
BASE = os.getcwd()
FRONTEND_BUILD = os.path.join(BASE, 'frontend', 'build')


@home_bp.route('/debug-path')
def debug_path():
    return jsonify({
        "cwd":    BASE,
        "build":  FRONTEND_BUILD,
        "exists": os.path.exists(FRONTEND_BUILD),
        "index":  os.path.exists(os.path.join(FRONTEND_BUILD, 'index.html')),
    })


@home_bp.route('/')
def home():
    index = os.path.join(FRONTEND_BUILD, 'index.html')
    if os.path.exists(index):
        return send_from_directory(FRONTEND_BUILD, 'index.html')
    stats = get_stats()
    stats.setdefault('recon_scan', 0)
    stats.setdefault('ids', 0)
    stats['modules'] = 15
    return render_template('home.html', active='home', stats=stats)


@home_bp.route('/static/js/<path:filename>')
def react_js(filename):
    return send_from_directory(
        os.path.join(FRONTEND_BUILD, 'static', 'js'), filename)


@home_bp.route('/static/css/<path:filename>')
def react_css(filename):
    return send_from_directory(
        os.path.join(FRONTEND_BUILD, 'static', 'css'), filename)


@home_bp.route('/static/media/<path:filename>')
def react_media(filename):
    return send_from_directory(
        os.path.join(FRONTEND_BUILD, 'static', 'media'), filename)


@home_bp.route('/logo192.png')
def logo192():
    return send_from_directory(FRONTEND_BUILD, 'logo192.png')


@home_bp.route('/favicon.ico')
def favicon():
    return send_from_directory(FRONTEND_BUILD, 'favicon.ico')
