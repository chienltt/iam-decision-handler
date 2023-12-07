class Config(object):
    KEYCLOAK_URL = "http://localhost:8080/"
    KEYCLOAK_REALM = "master"
    KEYCLOAK_CLIENT_ID = "iam-decision-handler"
    KEYCLOAK_CLIENT_SECRET = "Ioz6NDH8g4zmtrPbhyLQDzoJSGEYjZEN"
    KEYCLOAK_MYSQL_HOST = "localhost"
    KEYCLOAK_MYSQL_PORT = 3306
    KEYCLOAK_MYSQL_USER = "root"
    KEYCLOAK_MYSQL_PASSWORD = "myoianhyeuemnl"
    KEYCLOAK_MYSQL_DB = "keycloak"
    REDIS_RESOURCE_SETTING = 'redis://127.0.0.1:6379/1'
    REDIS_USER_ROLE = 'redis://127.0.0.1:6379/2'
    REDIS_PUBLIC_KEYS_STORAGE = 'redis://127.0.0.1:6379/3'
    REDIS_POLICY_ENFORCER_STORAGE = 'redis://127.0.0.1:6379/4'
    REDIS_CIRCUIT_BREAKER_OPTIONS = {
        'enable': False,
        'fail_max': 5,
        'reset_timeout': 60
    }