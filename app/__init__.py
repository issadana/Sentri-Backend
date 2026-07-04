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
    app = Flask(__name__)
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
    "specs_route": "/apidocs/"
}

    swagger_template = {
       "swagger": "2.0",
       "info": {
        "title": "Neural Firewall API",
        "description": "API documentation for Neural Firewall Backend",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT token format: Bearer <your_token>"
        }
    }
}

    Swagger(app, config=swagger_config, template=swagger_template)
    
    
    app.config.from_object("config.Config")

    db.init_app(app) #Connect SQLAlchemy to Flask app
    migrate.init_app(app, db) #Connect migration system
    jwt.init_app(app) #Connect JWT system to Flask
    sock.init_app(app) #Connect WebSocket support to Flask

    @app.route("/") 
    def home():
        return {"message": "Neural Firewall Backend Running"}
    
    from app import models
    # Register routes so Flask knows where to go when a URL is requested
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from app.routes.users import users_bp
    app.register_blueprint(users_bp)

    from app.routes.blacklist import blacklist_bp
    app.register_blueprint(blacklist_bp)

    from app.routes.acl import acl_bp
    app.register_blueprint(acl_bp)

    from app.routes.settings import settings_bp
    app.register_blueprint(settings_bp)

    from app.routes.events import events_bp
    app.register_blueprint(events_bp)

    from app.routes.models_api import models_bp
    app.register_blueprint(models_bp)
    
    from app.routes.hardware_metrics import hardware_metrics_bp
    app.register_blueprint(hardware_metrics_bp)

    from app.routes.firewall_logs import firewall_logs_bp
    app.register_blueprint(firewall_logs_bp)

    from app.routes.chat import chat_bp
    app.register_blueprint(chat_bp)

    return app