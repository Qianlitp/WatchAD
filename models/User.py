#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

from tools.common.common import get_netbios_domain


class User(object):
    def __init__(self, user_info):
        self.user_sid = None
        self.user_name = None
        self.domain_name = None
        self.logon_id = None
        for key, value in user_info.items():
            self.__dict__.update({key: value})
        if "domain_name" in user_info:
            self.domain_name = get_netbios_domain(user_info["domain_name"])

    def get_doc(self):
        return {
            "user_name": self.user_name,
            "logon_id": self.logon_id,
            "user_sid": self.user_sid,
            "domain": self.domain_name
        }

    def __str__(self):
        return "UserName: %s, LogonId: %s, Domain: %s" % (self.user_name, self.logon_id, self.domain_name, )
