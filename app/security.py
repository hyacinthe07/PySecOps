from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_cors import CORS

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

def init_security(app):
    limiter.init_app(app)
    CORS(app, resources={
        r"/api/*": {
            "origins": [
                "http://localhost:3000",
                "https://pysecops.onrender.com"
            ]
        }
    })
    Talisman(
        app,
        force_https=False,
        strict_transport_security=True,
        content_security_policy=False,
        frame_options='SAMEORIGIN',
    )

    @app.errorhandler(429)
    def rate_limit_handler(e):
        from flask import jsonify
        return jsonify({"erreur": "Trop de requêtes."}), 429

    return app
