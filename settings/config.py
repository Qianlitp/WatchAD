#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    全局配置文件

    为了在不重启检测引擎的情况下改变配置  所有配置信息都保存在redis缓存中 热修改读取
"""
import simplejson
from datetime import datetime
from tools.database.RedisHelper import RedisHelper


class GetConfig(object):
    def __init__(self):
        self.redis = RedisHelper()

    def get_str(self, key) -> str:
        return self.redis.get_str_value(key)

    def get_int(self, key) -> int:
        return int(self.redis.get_str_value(key))

    def get_dict(self, key) -> dict:
        return simplejson.loads(self.redis.get_str_value(key))

    def get_obj(self, key):
        return simplejson.loads(self.redis.get_str_value(key))

    def get_list(self, key) -> list:
        return self.redis.get_all_list(key)


config_redis = GetConfig()


def str_to_datetime(utc_str):
    """
        字符串时间转化为datetime对象
    """
    return datetime.strptime(utc_str, "%Y-%m-%d %H:%M:%S")


class MainConfig(object):
    def __init__(self):
        pass

    # 初次安装之后，系统需要收集10天数据进行统计，在此期间以下威胁活动不触发检测：
    # NTLMRelay GoldenTicket UnknownFileShare
    @property
    def learning_end_time(self) -> datetime:
        return str_to_datetime(config_redis.get_str("learning_end_time_setting"))

    # 需要分析的域名列表
    @property
    def domain_list(self) -> list:
        return config_redis.get_list("domain_list_setting")

    @property
    def raw_data_expire(self) -> dict:
        return config_redis.get_dict("raw_data_expire_setting")

    # 域控日志保留期限 单位天
    @property
    def log_expire(self) -> int:
        expire = config_redis.get_dict("raw_data_expire_setting")
        return expire["dc_log"]

    # 域控kerberos流量保留期限 单位天
    @property
    def krb5_expire(self) -> int:
        expire = config_redis.get_dict("raw_data_expire_setting")
        return expire["dc_krb5"]

    # 域控计算机名列表
    @property
    def dc_name_list(self) -> dict:
        return config_redis.get_dict("dc_name_list_setting")

    def get_dc_name_list(self, domain=None) -> list:
        return config_redis.get_dict("dc_name_list_setting")[domain]

    def sensitive_entry(self) -> dict:
        return config_redis.get_obj("sensitive_entry_setting")

    def kerberos(self) -> dict:
        return config_redis.get_obj("kerberos_setting")

    def alarms_merge(self) -> dict:
        return config_redis.get_obj("alarms_merge_setting")

    # 敏感计算机列表
    @property
    def sensitive_computers(self) -> list:
        return self.sensitive_entry()["computer"]

    # 敏感的用户组
    @property
    def sensitive_groups(self) -> list:
        return self.sensitive_entry()["group"]

    # 敏感的用户列表
    @property
    def sensitive_users(self) -> list:
        return self.sensitive_entry()["user"]

    # 蜜罐用户列表
    @property
    def honeypot_account(self) -> list:
        return config_redis.get_obj("honeypot_account_setting")

    # ldap 查询需要的账号信息
    @property
    def ldap_account(self) -> dict:
        return config_redis.get_dict("ldap_setting")

    # 票证授予票证 (TGT) 最大有效时间，默认10小时
    @property
    def TGT_maximum_lifetime(self) -> int:
        return self.kerberos()["TGT_maximum_lifetime"]

    # 服务票证 (ST) 最大有效时间，默认600分钟
    @property
    def ST_maximum_lifetime(self) -> int:
        return self.kerberos()["ST_maximum_lifetime"]

    # 高危服务前缀，用于判断离线票据破解的相关危险程度, 以下是默认的列表，可根据需要添加
    @property
    def high_risk_spn_prefix(self) -> list:
        return self.kerberos()["high_risk_spn_prefix"]

    # 高危kerberos限定委派服务前缀，以下是默认的列表，可根据需要添加
    @property
    def high_risk_delegation_prefix(self) -> list:
        return self.kerberos()["high_risk_delegation_prefix"]

    # 账户登录爆破10分钟内阈值
    @property
    def brute_force_max(self) -> int:
        return config_redis.get_int("brute_force_max_setting")

    # 合并告警为威胁活动的时间区间，单位小时
    @property
    def merge_activity_time(self) -> int:
        return self.alarms_merge()["activity"]

    # 合并威胁活动为入侵事件的时间区间，单位小时
    @property
    def merge_invasion_time(self) -> int:
        return self.alarms_merge()["invasion"]

    # VPN等动态IP的网段
    @property
    def VPN_ip_part(self) -> list:
        return config_redis.get_list("VPN_ip_part_setting")

    # 详细文件共享的RelativeTargetName的白名单
    @property
    def detail_file_share_white_list(self) -> list:
        return config_redis.get_list("detail_file_share_white_list_setting")


main_config = MainConfig()
