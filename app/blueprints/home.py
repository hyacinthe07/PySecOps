from flask import Blueprint, render_template
from app.utils.stats_utils import get_stats

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def home():
    stats = get_stats()
    return render_template('home.html', active='home', stats=stats)
