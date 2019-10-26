#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    详细记录账户的在域内的重要敏感活动

    如果每次都index，会存在性能瓶颈，使用bulk，达到一定数量或者距离上一条数据时间过长时，执行入库操作。
"""


from tools.database.ElsaticHelper import *
from tools.common.common import datetime_now_obj, datetime_to_log_date, get_netbios_domain

ACCOUNT_ATTR_CHANGE = "account_attr"            # 4738
GROUP_CHANGE = "group_change"                   # 组分为通讯组和安全组，这里只关注安全组
SPN_CHANGE = "spn_change"                       # 5136
ACCESS_ENTRY = "access_entry"                 # TGS
DELEGATION_CHANGE = "delegation_change"         # 4738
NTLM_LOGIN = "ntlm_login"                       # 4624


class AccountActivity(object):
    def __init__(self, activity_type):
        self.es = ElasticHelper()
        self.activity_type = activity_type

    def save_activity(self, domain, user_name, sid, dc_name, timestamp, data: dict):
        doc = {
            "domain": get_netbios_domain(domain),
            "user_name": user_name,
            "sid": sid,
            "activity_type": self.activity_type,
            "dc_name": dc_name,
            "@timestamp": timestamp,
            "data": data
        }

        index = ElasticConfig.user_activity_write_index_prefix + datetime_to_log_date(datetime_now_obj())

        self.es.delay_index(body=doc,
                            index=index,
                            doc_type=ElasticConfig.user_activity_doc_type)
