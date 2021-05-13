from flask import Flask

from app.database import db
from app.oauth2 import authorization, save_token, query_client, config_oauth
from app.routes import bp as oauth_bp


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_object('app.settings')

    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)

    setup_app(app)

    return app


def setup_app(app):
    db.init_app(app)
    config_oauth(app)
    # server.init_app(app, query_client=query_client, save_token=save_token)

    app.register_blueprint(oauth_bp)

