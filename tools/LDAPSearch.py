#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    通过 LDAP 检索域内的相关信息
"""

import random

from ldap3 import Server, Connection, ALL, Entry

from settings.config import main_config
from tools.common.common import get_netbios_domain
from tools.common.errors import LDAPSearchFailException


class LDAPSearch(object):
    def __init__(self, domain):
        self.domain = get_netbios_domain(domain)
        self.con = Connection(self._get_server(),
                              user=main_config.ldap_account[self.domain]["user"],
                              password=main_config.ldap_account[self.domain]["password"],
                              auto_bind=True)
        self.domain_dn = main_config.ldap_account[self.domain]["dn"]

    def _get_server(self):
        return Server(main_config.ldap_account[self.domain]["server"], get_info=ALL)

    def search_by_sid(self, sid, attributes=None) -> Entry:
        """
            通过SID搜索域用户的相关信息
        """
        if attributes is None:
            attributes = ['cn']
        self.con.search(self.domain_dn, '(ObjectSID={sid})'.format(sid=sid), attributes=attributes)
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            # sid 是唯一的 取数组第一个即可
            entry = self.con.entries[0]
            return entry
        elif self.con.result["result"] != 0:
            raise LDAPSearchFailException()

    def search_by_name(self, user, attributes=None) -> Entry:
        """
            通过用户名搜索
        """
        if attributes is None:
            attributes = ["CN"]
        dn = self.domain_dn
        self.con.search(dn, '(sAMAccountName=%s)' % user, attributes=attributes)
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            entry = self.con.entries[0]
            return entry
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_by_cn(self, cn, attributes=None) -> Entry:
        """
            通过CN搜索
        """
        if attributes is None:
            attributes = ["CN"]
        dn = self.domain_dn
        self.con.search(dn, '(CN=%s)' % cn, attributes=attributes)
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            entry = self.con.entries[0]
            return entry
        elif len(self.con.entries) == 0:
            return None
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_admins(self):
        admin_users = []
        self.con.search(self.domain_dn, '(&(adminCount=1)(objectclass=person))', attributes=['sAMAccountName', 'objectsid'])
        if self.con.result["result"] == 0:
            entries = self.con.entries
            for en in entries:
                name = en["sAMAccountName"][0]
                sid = en["objectSid"][0]
                admin_users.append({
                    "user": name,
                    "sid": sid,
                    "domain": self.domain
                })
            return admin_users
        else:
            raise LDAPSearchFailException()

    def search_domain_controller(self):
        dn = self.domain_dn
        self.con.search(dn, "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=532480))",
                        attributes=["cn", "dnsHostName", "objectSid"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_constrained_accounts(self):
        """
            查找所有约束委派账户
        """
        dn = self.domain_dn
        self.con.search(dn, "(msDS-AllowedToDelegateTo=*)",
                        attributes=["cn", "objectSid", "sAMAccountName", "msDS-AllowedToDelegateTo"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_res_constrained_accounts(self):
        """
            查找所有基于资源约束委派账户
        """
        dn = self.domain_dn
        self.con.search(dn, "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                        attributes=["cn", "objectSid", "sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_unconstrained_accounts(self):
        """
            无约束委派的账户
        """
        dn = self.domain_dn
        self.con.search(dn, "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
                        attributes=["cn", "objectSid", "sAMAccountName"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_pre_auth_not_required(self):
        dn = self.domain_dn
        self.con.search(dn, "(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
                        attributes=["cn", "objectSid", "sAMAccountName"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_spn_account(self):
        dn = self.domain_dn
        self.con.search(dn, "(servicePrincipalName=ldap*)",
                        attributes=["cn", "servicePrincipalName", "sAMAccountName"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def get_support_aes_account(self):
        dn = self.domain_dn
        self.con.search(dn, "(&(objectClass=Computer)(msds-supportedencryptiontypes>=8))",
                        attributes=["sAMAccountName"], paged_size=200)
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries[random.randint(20, 180)]
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()


if __name__ == '__main__':
    pass
