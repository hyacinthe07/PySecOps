from flask import Flask
from app.blueprints.home    import home_bp
from app.blueprints.ports   import ports_bp
from app.blueprints.logs    import logs_bp
from app.blueprints.secops  import secops_bp
from app.blueprints.owasp   import owasp_bp

def create_app():
    app = Flask(__name__, template_folder='app/templates', static_folder='app/static')
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

    app.register_blueprint(home_bp)
    app.register_blueprint(ports_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(secops_bp)
    app.register_blueprint(owasp_bp)

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=8080, host='0.0.0.0')
