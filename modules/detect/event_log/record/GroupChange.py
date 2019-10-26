#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp


"""
    本模块不告警

    用户组变动情况

    用户组分通讯组和安全组，这里只关注安全组
"""
from models.Log import Log
from modules.record_handle.AccountActivity import AccountActivity, GROUP_CHANGE
from tools.common.common import get_cn_from_dn

EVENT_ID = [4728, 4729, 4732, 4733, 4756, 4757]


class GroupChange(object):
    def __init__(self):
        self.account_activity = AccountActivity(activity_type=GROUP_CHANGE)

    def run(self, log: Log):
        if log.event_id in [4728, 4732, 4756]:
            operator_type = "add"
        else:
            operator_type = "remove"

        target_user_name = get_cn_from_dn(log.event_data["MemberName"])
        target_user_sid = log.event_data["MemberSid"]
        group_name = log.event_data["TargetUserName"]
        domain = log.subject_info.domain_name

        form_data = {
            "group_name": group_name,
            "operator_type": operator_type
        }

        self.account_activity.save_activity(domain=domain,
                                            user_name=target_user_name,
                                            sid=target_user_sid,
                                            dc_name=log.dc_host_name,
                                            timestamp=log.utc_log_time,
                                            data=form_data)
