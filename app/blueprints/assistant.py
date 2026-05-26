from flask import Blueprint, render_template, request, jsonify
from app.utils.assistant_intelligent import repondre_intelligent
from app.utils.db_utils import enregistrer

assistant_bp = Blueprint('assistant', __name__)


@assistant_bp.route('/assistant')
def assistant():
    return render_template('assistant.html', active='assistant')


@assistant_bp.route('/api/assistant', methods=['POST'])
def api_assistant():
    question = request.json.get('question', '').strip()
    if not question:
        return jsonify({"erreur": "Question vide."})
    enregistrer("assistant", question[:50])
    return jsonify(repondre_intelligent(question))
