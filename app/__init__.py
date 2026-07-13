import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS

db = SQLAlchemy()
jwt = JWTManager()


def create_app():
    """Dashboard-only Flask app. Reads the deployed DB; does not own migrations."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, "templates"),
        static_folder=os.path.join(base_dir, "static"),
    )
    CORS(app)

    app.config.from_object("config.Config")

    db.init_app(app)
    jwt.init_app(app)

    from app import models  # noqa: F401

    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from app.routes.dashboard_pages import dashboard_pages_bp
    app.register_blueprint(dashboard_pages_bp)

    from app.routes.dashboard_api import dashboard_api_bp
    app.register_blueprint(dashboard_api_bp)

    from app.routes.dashboard_chat import dashboard_chat_bp
    app.register_blueprint(dashboard_chat_bp)

    @app.route("/health")
    def health():
        return {"message": "NOVA Dashboard Running"}

    return app
