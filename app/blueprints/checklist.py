from flask import Blueprint, render_template
checklist_bp = Blueprint('checklist', __name__)

@checklist_bp.route('/checklist')
def checklist():
    return render_template('checklist/index.html', active='checklist')
