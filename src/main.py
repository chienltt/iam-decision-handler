from flask import Flask

from src.api import admin_bp
from src.api.admin.routes import ADMIN_API_ROUTES
from src.config import Config
from src.extension import api, db, keycloak_extension, resource_setting_storage, \
    user_role_storage, policy_enforcer_storage, public_keys_storage
from src.job.scheduler import start_scheduler, get_resource_data


def init_app(environment=None):
    """ Create a Flask application."""
    app = Flask(__name__)
    __init_extension(app=app)
    __register_blueprint(app=app)
    start_scheduler()
    get_resource_data()
    return app


def __init_extension(app):
    api.init_app(admin_bp)
    keycloak_extension.init_instance(
        server_url=Config.KEYCLOAK_URL,
        client_id=Config.KEYCLOAK_CLIENT_ID,
        realm_name=Config.KEYCLOAK_REALM,
        client_secret=Config.KEYCLOAK_CLIENT_SECRET
    )
    app.config['MYSQL_HOST'] = Config.KEYCLOAK_MYSQL_HOST
    app.config['MYSQL_USER'] = Config.KEYCLOAK_MYSQL_USER
    app.config['MYSQL_PASSWORD'] = Config.KEYCLOAK_MYSQL_PASSWORD
    app.config['MYSQL_KEYCLOAK_DB'] = Config.KEYCLOAK_MYSQL_DB
    app.config[
        'REDIS_CIRCUIT_BREAKER_OPTIONS'] = Config.REDIS_CIRCUIT_BREAKER_OPTIONS
    db.init_app(app)
    resource_setting_storage.init_app(app=app,
                                      redis_url=Config.REDIS_RESOURCE_SETTING)
    user_role_storage.init_app(app=app, redis_url=Config.REDIS_USER_ROLE)
    policy_enforcer_storage.init_app(app=app,
                                     redis_url=Config.REDIS_POLICY_ENFORCER_STORAGE)
    public_keys_storage.init_app(app=app,
                                 redis_url=Config.REDIS_PUBLIC_KEYS_STORAGE)


def __register_blueprint(app):
    app.register_blueprint(admin_bp)
    for ns in ADMIN_API_ROUTES:
        api.add_namespace(ns=ns)
