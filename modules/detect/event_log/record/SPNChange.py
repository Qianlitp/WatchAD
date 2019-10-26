#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    记录账户SPN的变化

    SPN修改触发的日志有点特点，首先会删除存在的值，每个值触发一次删除操作。然后会添加修改后存在的值，每个值触发一次添加操作。
"""

from models.Log import Log
from modules.record_handle.AccountActivity import AccountActivity, SPN_CHANGE
from modules.record_handle.AccountInfo import AccountInfo
from tools.common.common import get_cn_from_dn

EVENT_ID = [5136]


class SPNChange(object):
    def __init__(self):
        self.account_info = AccountInfo()
        self.account_activity = AccountActivity(activity_type=SPN_CHANGE)

    def run(self, log: Log):
        if log.event_data["AttributeLDAPDisplayName"] != "servicePrincipalName":
            return

        if log.event_data["ObjectClass"] != "user":
            return

        if log.event_data["OperatorType"] not in ["%%14675", "%%14674"]:
            return

        domain = log.event_data["DSName"]
        target_user_name = get_cn_from_dn(log.object_info.dn)
        target_user_info = self.account_info.get_user_info_by_name(target_user_name, domain)

        form_data = {
            "operator": {
                "user_name": log.subject_info.user_name,
                "sid": log.subject_info.user_sid,
                "logon_id": log.subject_info.logon_id
            },
            "operator_type": "add" if log.event_data["OperatorType"] == "%%14674" else "remove",
            "value": log.event_data["AttributeValue"],
            "object_dn": log.object_info.dn
        }

        self.account_activity.save_activity(domain=log.event_data["DSName"],
                                            user_name=target_user_name,
                                            sid=target_user_info.user_sid,
                                            dc_name=log.dc_host_name,
                                            timestamp=log.utc_log_time,
                                            data=form_data)



