from flask import Blueprint, render_template

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def home():
    stats = {'modules': 5, 'version': '2.0', 'status': 'Online'}
    return render_template('home.html', active='home', stats=stats)
