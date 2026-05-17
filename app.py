from flask import Flask
from app.blueprints.home      import home_bp
from app.blueprints.ports     import ports_bp
from app.blueprints.logs      import logs_bp
from app.blueprints.secops    import secops_bp
from app.blueprints.owasp     import owasp_bp
from app.blueprints.network   import network_bp
from app.blueprints.rapports  import rapports_bp
from app.blueprints.qrcode_bp import qrcode_bp
from app.blueprints.assistant import assistant_bp
from app.blueprints.recon     import recon_bp
from app.blueprints.ids       import ids_bp
from app.blueprints.audit     import audit_bp
from app.blueprints.osint     import osint_bp
from app.utils.db_utils import init_db

def create_app():
    app = Flask(__name__, template_folder='app/templates', static_folder='app/static')
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
    init_db()
    app.register_blueprint(home_bp)
    app.register_blueprint(ports_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(secops_bp)
    app.register_blueprint(owasp_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(rapports_bp)
    app.register_blueprint(qrcode_bp)
    app.register_blueprint(assistant_bp)
    app.register_blueprint(recon_bp)
    app.register_blueprint(ids_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(osint_bp)
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=8080, host='0.0.0.0')
