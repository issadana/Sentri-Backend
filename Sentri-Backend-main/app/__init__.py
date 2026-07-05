import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flasgger import Swagger
from flask_sock import Sock

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
sock = Sock()


def create_app():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
    )
    CORS(app)

    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": "apispec",
                "route": "/apispec.json",
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/apidocs/",
    }

    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "Neural Firewall API",
            "description": "API documentation for Neural Firewall Backend",
            "version": "1.0.0",
        },
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT token format: Bearer <your_token>",
            }
        },
    }

    Swagger(app, config=swagger_config, template=swagger_template)

    app.config.from_object("config.Config")

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    sock.init_app(app)

    from app import models

    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from app.routes.users import users_bp
    app.register_blueprint(users_bp)

    from app.routes.blacklist import blacklist_bp
    app.register_blueprint(blacklist_bp)

    from app.routes.settings import settings_bp
    app.register_blueprint(settings_bp)

    from app.routes.hardware_metrics import hardware_metrics_bp
    app.register_blueprint(hardware_metrics_bp)

    from app.routes.firewall_logs import firewall_logs_bp
    app.register_blueprint(firewall_logs_bp)

    from app.routes.chat import chat_bp
    app.register_blueprint(chat_bp)

    from app.routes.dashboard_pages import dashboard_pages_bp
    app.register_blueprint(dashboard_pages_bp)

    from app.routes.dashboard_api import dashboard_api_bp
    app.register_blueprint(dashboard_api_bp)

    from app.routes.dashboard_chat import dashboard_chat_bp
    app.register_blueprint(dashboard_chat_bp)

    @app.route("/health")
    def health():
        return {"message": "Neural Firewall Backend Running"}

    return app
