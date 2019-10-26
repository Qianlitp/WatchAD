#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

import redis

from settings.database_config import RedisConfig


class RedisHelper(object):
    def __init__(self):
        if hasattr(RedisConfig, "password"):
            pool = redis.ConnectionPool(host=RedisConfig.host, port=RedisConfig.port, password=RedisConfig.password)
        else:
            pool = redis.ConnectionPool(host=RedisConfig.host, port=RedisConfig.port)
        self.db = redis.Redis(connection_pool=pool)
        self.pipe = self.db.pipeline()

    def exists_key(self, key):
        return self.db.exists(key)

    def set_str_value(self, key, value, expire=None):
        self.pipe.delete(key)
        self.pipe.set(key, value, expire)
        self.pipe.execute()

    def get_str_value(self, key):
        value = self.db.get(key)
        if not value:
            return None
        assert isinstance(value, bytes)
        return value.decode("utf-8")

    def add_member_set(self, key, value):
        self.db.sadd(key, value)

    def get_all_member_set(self, key) -> list:
        result = self.db.smembers(key)
        result = list(map(lambda x: x.decode("utf-8"), result))
        return result

    def set_list(self, key, *args):
        self.pipe.delete(key)
        self.pipe.lpush(key, *args)
        self.pipe.execute()

    def get_all_list(self, key) -> list:
        result = self.db.lrange(key, 0, -1)
        result = list(map(lambda x: x.decode("utf-8"), result))
        return result

    def delete(self, key):
        self.db.delete(key)

    def set_expire(self, key, seconds):
        self.db.expire(key, seconds)
