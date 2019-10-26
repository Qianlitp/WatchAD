#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    账户属性变化

    本模块不告警
"""
from models.Log import Log
from modules.record_handle.AccountActivity import AccountActivity, ACCOUNT_ATTR_CHANGE
from tools.UACFlagsParser import UACFlagsParser


EVENT_ID = [4738]


class AccountAttr(object):
    def __init__(self):
        self.UAC_parser = UACFlagsParser()
        self.account_activity = AccountActivity(activity_type=ACCOUNT_ATTR_CHANGE)

    def run(self, log: Log):
        target_user_name = log.target_info.user_name
        target_user_sid = log.target_info.sid

        # 目前只关注 UAC 值的变化
        if log.event_data["NewUacValue"] == "-" or log.event_data["OldUacValue"] == "-":
            return

        form_data = {
            "old_uac": self.UAC_parser.parse(log.event_data["OldUacValue"]),
            "new_uac": self.UAC_parser.parse(log.event_data["NewUacValue"]),
            "uac_change": self.UAC_parser.get_uac_change(log.event_data["NewUacValue"], log.event_data["OldUacValue"]),
            "operator": {
                "user_name": log.subject_info.user_name,
                "sid": log.subject_info.user_sid,
                "logon_id": log.subject_info.logon_id
            }
        }

        self.account_activity.save_activity(domain=log.target_info.domain_name,
                                            user_name=target_user_name,
                                            sid=target_user_sid,
                                            dc_name=log.dc_host_name,
                                            timestamp=log.utc_log_time,
                                            data=form_data)
