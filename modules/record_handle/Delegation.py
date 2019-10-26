#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    委派权限的相关操作
"""

from settings.database_config import MongoConfig
from models.User import User
from tools.common.errors import NoSuchDelegationType
from tools.database.MongoHelper import MongoHelper

CONSTRAINED_DELEGATION = "Constrained"
UNCONSTRAINED_DELEGATION = "Unconstrained"
RES_BASED_CONSTRAINED_DELEGATION = "Res_Constrained"


class Delegation(object):
    def __init__(self):
        self.mongo = MongoHelper(MongoConfig.uri, MongoConfig.db, MongoConfig.delegation_collection)

    def new_delegation_record(self, user: User, delegation_type: str, allowed_to=None):
        if delegation_type not in [CONSTRAINED_DELEGATION, UNCONSTRAINED_DELEGATION, RES_BASED_CONSTRAINED_DELEGATION]:
            raise NoSuchDelegationType()

        self.mongo.insert_one({
            "name": user.user_name,
            "sid": user.user_sid,
            "domain": user.domain_name,
            "delegation_type": delegation_type,
            "allowed_to": allowed_to
        })

    def find_constrained_delegation_by_sid(self, sid: str):
        return self.mongo.find_one({
            "sid": sid,
            "delegation_type": CONSTRAINED_DELEGATION
        })

    def find_res_constrained_delegation_by_name(self, name: str):
        return self.mongo.find_one({
            "name": name,
            "delegation_type": RES_BASED_CONSTRAINED_DELEGATION
        })

    def find_one_delegation(self, query: dict):
        return self.mongo.find_one(query)

    def update_delegation(self, sid, delegation_type, allowed_to):
        self.mongo.update_one({
            "sid": sid,
            "delegation_type": delegation_type
        }, {
            "allowed_to": allowed_to
        })
