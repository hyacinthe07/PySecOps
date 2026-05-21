from flask import Blueprint, render_template, send_from_directory
from app.utils.db_utils import get_stats
import os

home_bp = Blueprint('home', __name__)


@home_bp.route('/')
def home():
    stats = get_stats()
    stats.setdefault('recon_scan', 0)
    stats.setdefault('ids', 0)
    stats.setdefault('audit', 0)
    stats['modules'] = 15
    return render_template('home.html', active='home', stats=stats)


@home_bp.route('/dashboard')
def react_dashboard():
    """Sert le dashboard React buildé."""
    build_path = os.path.join(os.path.dirname(__file__), '../../frontend/build')
    return send_from_directory(build_path, 'index.html')


@home_bp.route('/dashboard/<path:path>')
def react_static(path):
    """Sert les fichiers statiques React."""
    build_path = os.path.join(os.path.dirname(__file__), '../../frontend/build')
    return send_from_directory(build_path, path)
