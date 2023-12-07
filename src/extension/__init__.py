from flask_restx import Api
from flask_mysqldb import MySQL
from rq import Queue
from redis import Redis

from src.extension.Keycloak_extension import KeycloakExtension
from src.extension.Redis_cache import RedisStorage

keycloak_extension = KeycloakExtension()

api = Api(
    version='1.0',
    title='Identity Api Specification',
    description='Identity Api Specification',
    doc='/docs')

db = MySQL()

resource_setting_storage = RedisStorage()
user_role_storage = RedisStorage()
policy_enforcer_storage = RedisStorage()
public_keys_storage = RedisStorage()


redis_conn = Redis(host='localhost',
                   port=6379)
rq = Queue(connection=redis_conn)
