"""
PySecOps — Assistant Cybersécurité IA
Branché sur l'API Claude d'Anthropic.
"""
from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context
from app.utils.db_utils import enregistrer
import os
import json

assistant_bp = Blueprint('assistant', __name__)

SYSTEM_PROMPT = """Tu es un expert en cybersécurité offensive et défensive.
Tu travailles pour PySecOps, une plateforme professionnelle de sécurité.
Tu réponds en français, de manière précise, technique et concise.
Tu couvres : pentest, OSINT, forensique, cryptographie, CVE, OWASP,
malware, réseau, cloud security, DevSecOps.
Pour chaque réponse tu donnes : explication claire, exemples concrets,
commandes/outils si pertinent, et recommandations de sécurité.
Format : markdown simple, pas de blabla inutile."""


@assistant_bp.route('/assistant')
def assistant():
    return render_template('assistant.html', active='assistant')


@assistant_bp.route('/api/assistant', methods=['POST'])
def api_assistant():
    """Répond via l'API Claude avec streaming."""
    try:
        import anthropic
        question = request.json.get('question', '').strip()
        if not question:
            return jsonify({"erreur": "Question vide."})

        enregistrer("assistant", question[:50])

        client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY", "")
        )

        def generer():
            with client.messages.stream(
                model="claude-opus-4-5",
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": question}]
            ) as stream:
                for text in stream.text_stream:
                    yield f"data: {json.dumps({'text': text})}\n\n"
            yield "data: [DONE]\n\n"

        return Response(
            stream_with_context(generer()),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
        )

    except Exception as e:
        return jsonify({"erreur": str(e)})
