#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

from models.User import User
from modules.record_handle.AccountHistory import AccountHistory
from tools.LDAPSearch import LDAPSearch
from tools.database.ElsaticHelper import *
from tools.database.RedisHelper import RedisHelper
from settings.config import main_config
from tools.common.common import get_cn_from_dn, get_netbios_domain

# 默认过期时间一天
ACCOUNT_INFO_REDIS_EXPIRE_TIME = 60*60*24
# 通过sid查username的键后缀
REDIS_KEY_SID_USERNAME_SUFFIX = "_sid_to_username"
# 通过username查sid的键后缀
REDIS_KEY_USERNAME_SID_SUFFIX = "_username_to_sid"
# 通过username查最近登录IP的键后缀
REDIS_KEY_USERNAME_LOGIN_IP_SUFFIX = "_username_to_login_ip"
# 通过sid查最近登录IP的键后缀
REDIS_KEY_SID_LOGIN_IP_SUFFIX = "_sid_to_login_ip"
# 通过sid查该账户是否属于OU=Users的键后缀
REDIS_KEY_SID_IS_USERS_SUFFIX = "_sid_is_Users"
# 通过sid查该账户是否属于OU=Users的键后缀
REDIS_KEY_USERNAME_IS_USERS_SUFFIX = "_username_is_Users"
# 通过sid查最近登录主机名的键后缀
REDIS_KEY_SID_WORKSTATION_SUFFIX = "_sid_to_workstation"
# 通过username查最近登录主机名的键后缀
REDIS_KEY_USERNAME_WORKSTATION_SUFFIX = "_username_to_workstation"
# 通过sid查该账户是否有管理员权限的键后缀
REDIS_KEY_SID_IS_ADMIN_SUFFIX = "_sid_is_admin"
# 通过username查询该账户是否支持AES的键后缀
REDIS_KEY_USERNAME_AES_SUPPORT_SUFFIX = "_username_aes_support"


class AccountInfo(object):
    def __init__(self):
        self.redis = RedisHelper()
        self.account_history = AccountHistory()
        self.es = ElasticHelper()

    def check_target_is_admin_by_sid(self, sid: str, domain: str) -> bool:
        """
            检查一个账户是否拥有管理员权限
        """
        key = sid + REDIS_KEY_SID_IS_ADMIN_SUFFIX
        record = self.redis.get_str_value(key)
        # 存在redis缓存记录
        if record:
            if record == "true":
                return True
            else:
                return False
        # 不存在 则通过ldap查询，再更新redis缓存
        else:
            ldap = LDAPSearch(domain)
            user_entry = ldap.search_by_sid(sid=sid, attributes=["adminCount"])
            if user_entry:
                entry_attributes = user_entry.entry_attributes_as_dict
                if len(entry_attributes["adminCount"]) > 0 and entry_attributes["adminCount"][0] == 1:
                    self.redis.set_str_value(key, "true", expire=ACCOUNT_INFO_REDIS_EXPIRE_TIME)
                    return True
            self.redis.set_str_value(key, "false", expire=ACCOUNT_INFO_REDIS_EXPIRE_TIME)
            return False

    def check_target_is_user_by_sid(self, sid: str, domain: str) -> bool:
        """
            检查目标账号是否为 OU=Users
        """
        key = sid + REDIS_KEY_SID_IS_USERS_SUFFIX
        record = self.redis.get_str_value(key)
        # 存在redis缓存记录
        if record:
            if record == "true":
                return True
            else:
                return False
        # 不存在 则通过ldap查询，再更新redis缓存
        else:
            ldap = LDAPSearch(domain)
            user_entry = ldap.search_by_sid(sid=sid, attributes=["cn"])
            if user_entry:
                dn = user_entry.entry_dn
                if "OU=Users" in dn:
                    self.redis.set_str_value(key, "true", expire=ACCOUNT_INFO_REDIS_EXPIRE_TIME)
                    return True
            self.redis.set_str_value(key, "false", expire=ACCOUNT_INFO_REDIS_EXPIRE_TIME)
            return False

    def check_target_is_user_by_name(self, user: str, domain: str) -> bool:
        """
            检查目标账号是否为 OU=Users
        """
        key = user + REDIS_KEY_USERNAME_IS_USERS_SUFFIX
        record = self.redis.get_str_value(key)
        # 存在redis缓存记录
        if record:
            if record == "true":
                return True
            else:
                return False
        # 不存在 则通过ldap查询，再更新redis缓存
        else:
            ldap = LDAPSearch(domain)
            user_entry = ldap.search_by_name(user=user, attributes=["cn"])
            if user_entry:
                dn = str(user_entry.entry_dn)
                if "OU=Users".lower() in dn.lower() or "CN=Users".lower() in dn.lower():
                    self.redis.set_str_value(key, "true", expire=ACCOUNT_INFO_REDIS_EXPIRE_TIME)
                    return True
            self.redis.set_str_value(key, "false", expire=ACCOUNT_INFO_REDIS_EXPIRE_TIME)
            return False

    def get_user_info_by_name(self, user_name: str, domain: str) -> User:
        key = user_name + REDIS_KEY_USERNAME_SID_SUFFIX
        # 先查redis
        user_sid = self.redis.get_str_value(key)
        # redis 缓存未命中 再查mongo
        if not user_sid:
            ldap = LDAPSearch(domain)
            user_entry = ldap.search_by_name(user_name, attributes=["objectSid"])
            if not user_entry:
                return
            user_sid = user_entry.entry_attributes_as_dict["objectSid"][0]
            self.redis.set_str_value(key, user_sid, expire=ACCOUNT_INFO_REDIS_EXPIRE_TIME)
        user = User({
            "user_name": user_name,
            "user_sid": user_sid,
            "logon_id": "",
            "domain_name": domain
        })
        return user

    def get_user_info_by_sid(self, sid: str, domain: str) -> User:
        key = sid + REDIS_KEY_SID_USERNAME_SUFFIX
        # 先查redis
        user_name = self.redis.get_str_value(key)
        if not user_name:
            ldap = LDAPSearch(domain)
            user_entry = ldap.search_by_sid(sid, attributes=["sAMAccountName"])
            if not user_entry:
                return None
            user_name = user_entry.entry_attributes_as_dict["sAMAccountName"][0]
            self.redis.set_str_value(key, user_name, expire=ACCOUNT_INFO_REDIS_EXPIRE_TIME)
        user = User({
            "user_name": user_name,
            "user_sid": sid,
            "logon_id": "",
            "domain_name": domain
        })
        return user

    def check_target_is_aes_support(self, name: str, domain: str) -> bool:
        key = name + REDIS_KEY_USERNAME_AES_SUPPORT_SUFFIX
        # 先查redis
        is_support = self.redis.get_str_value(key)
        #
        if is_support is not None:
            return is_support == "true"
        else:
            ldap = LDAPSearch(domain)
            user_entry = ldap.search_by_name(name, attributes=["msDS-SupportedEncryptionTypes"])
            if not user_entry:
                return False
            support_types = user_entry.entry_attributes_as_dict["msDS-SupportedEncryptionTypes"]
            if len(support_types) == 0:
                return False
            support_types = support_types[0]
            # 等于8 支持AES128加密
            if support_types >= 8:
                self.redis.set_str_value(key, "true")
                return True
            else:
                self.redis.set_str_value(key, "false")
                return False

    def user_is_sensitive_by_sid(self, sid: str, domain: str) -> bool:
        """
            检查某个用户是否为敏感用户

            1. adminCount 1
            2. 属于敏感组
            3. 蜜罐账户
            4. 自定义敏感用户
        """
        # 蜜罐账户
        for user in main_config.honeypot_account:
            if user["sid"] == sid:
                return True

        # 自定义敏感用户
        for user in main_config.sensitive_users:
            if user["sid"] == sid:
                return True

        ldap = LDAPSearch(domain)
        user_entry = ldap.search_by_sid(sid, attributes=["adminCount", "memberOf"])
        if not user_entry:
            return False

        # adminCount
        if len(user_entry.entry_attributes_as_dict["adminCount"]) > 0 and \
                user_entry.entry_attributes_as_dict["adminCount"][0] == 1:
            return True

        # 敏感组
        groups = user_entry.entry_attributes_as_dict["memberOf"]
        sensitive_groups = list(map(lambda x: x["name"], main_config.sensitive_groups))
        for g in groups:
            g_name = get_cn_from_dn(g)
            if g_name in sensitive_groups:
                return True
        return False

    def computer_is_sensitive_by_name(self, name: str, domain: str) -> bool:
        """
            检查某个计算机是否为敏感

            1. 域控服务器
            2. 自定义敏感主机
        """
        domain = get_netbios_domain(domain)
        # 域控服务器
        if name.upper() in main_config.dc_name_list[domain]:
            return True

        # 敏感计算机
        sensitive_computers = list(map(lambda x: x["name"], main_config.sensitive_computers))
        if name.upper() in sensitive_computers:
            return True

        return False




