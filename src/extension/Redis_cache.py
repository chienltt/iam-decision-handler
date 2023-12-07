# -*- coding: utf-8 -*-
import json

import redis
import pybreaker
from redis.exceptions import RedisError


class RedisStorage(object):

    def __init__(self, app=None):
        self._app = None
        self._redis_client = None
        self._enable_breaker = None
        self._breaker = None
        if app:
            self.init_app(app)

    def init_app(self, app, redis_url):
        redis_url = redis_url
        self._redis_client = redis.Redis.from_url(
            url=redis_url,
            socket_timeout=5,  # Response timeout for Redis commands
            socket_connect_timeout=2
            # Connection timeout for establishing a connection
        )
        self._app = app
        breaker_config_option = app.config.get(
            'REDIS_CIRCUIT_BREAKER_OPTIONS')
        self._enable_breaker = breaker_config_option['enable']
        if self._enable_breaker:
            try:
                self._breaker = pybreaker.CircuitBreaker(
                    name="Cache Storage Circuit Breaker",
                    fail_max=breaker_config_option['fail_max'],
                    reset_timeout=breaker_config_option['reset_timeout'],
                    throw_new_error_on_trip=False,
                    listeners=[BreakerLogListener(app=self._app)]
                )
            except Exception as e:
                self._app.logger.error('Error while initializing cache storage '
                                       'breaker: %s' % e)

    def _has(self, name):
        return self._redis_client.exists(name)

    def _get(self, name):
        if self._has(name):
            value = self._redis_client.get(name)
            return json.loads(value)

    def get(self, name):
        try:
            if self._enable_breaker:
                self._breaker.call(self._get, name)
            else:
                return self._get(name)
        except RedisError as e:
            self._app.logger.error(
                'Error while reading cache from redis: %s' % e)
        except Exception as e:
            self._app.logger.error('Error while loading cache: %s' % e)

    def _set(self, name, value, time=None):
        if not time:
            time = self._app.config.get('REDIS_EXPIRATION_TIME', 3600)
        self._redis_client.setex(
            name=name, time=time, value=json.dumps(value))

    def set(self, name, value, time=None):
        try:
            if self._enable_breaker:
                self._breaker.call(self._set, name, value, time)
            else:
                self._set(name, value, time)
        except RedisError as e:
            self._app.logger.error('Error while saving cache to redis: %s' % e)
        except Exception as e:
            self._app.logger.error('Error while loading cache: %s' % e)

    def _delete(self, name):
        if self._has(name):
            self._redis_client.delete(name)

    def delete(self, name):
        try:
            if self._enable_breaker:
                self._breaker.call(self._delete, name)
            else:
                self._delete(name)
        except RedisError as e:
            self._app.logger.error(
                'Error while removing cache from redis: %s' % e)
        except Exception as e:
            self._app.logger.error('Error while loading cache: %s' % e)


class BreakerLogListener(pybreaker.CircuitBreakerListener):
    """
    Listener class used to listen the state of redis storage
    TODO: Develop an improvement strategy to address changes in the Redis storage
    """

    def __init__(self, app=None):
        self._app = app

    def state_change(self, cb, old_state, new_state):
        msg = "State Change: CB: {0}, New State: {1}".format(cb.name, new_state)
        self._app.logger.info(msg)
