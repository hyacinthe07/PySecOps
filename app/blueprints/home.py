from flask import Blueprint, render_template, send_from_directory
from app.utils.db_utils import get_stats
import os

home_bp = Blueprint('home', __name__)

FRONTEND_BUILD = os.path.join(
    os.path.dirname(__file__), '../../frontend/build'
)


@home_bp.route('/')
def home():
    """Dashboard React — sert index.html du build React."""
    if os.path.exists(os.path.join(FRONTEND_BUILD, 'index.html')):
        return send_from_directory(FRONTEND_BUILD, 'index.html')
    # Fallback Jinja2 si React pas buildé
    stats = get_stats()
    stats.setdefault('recon_scan', 0)
    stats.setdefault('ids', 0)
    stats['modules'] = 15
    return render_template('home.html', active='home', stats=stats)


@home_bp.route('/static/js/<path:filename>')
def react_js(filename):
    return send_from_directory(
        os.path.join(FRONTEND_BUILD, 'static/js'), filename
    )


@home_bp.route('/static/css/<path:filename>')
def react_css(filename):
    return send_from_directory(
        os.path.join(FRONTEND_BUILD, 'static/css'), filename
    )
