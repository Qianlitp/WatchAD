#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    机器账户认证

    记录下机器账户的 4768 TGT请求中对应的IP，作为IP和主机名匹配的依据
"""

from models.Log import Log
from tools.common.common import ip_filter
from modules.record_handle.AccountHistory import AccountHistory

EVENT_ID = [4768]


class MachineAuth(object):
    def __init__(self):
        self.account_history = AccountHistory()

    def run(self, log: Log):
        ip = log.source_info.ip_address
        if ip_filter(ip):
            return

        if log.event_data["Status"] != "0x0":
            return

        if log.event_data["PreAuthType"] != 2:
            return

        if not log.target_info.user_name.endswith("$"):
            return

        workstation = log.target_info.user_name[:-1]

        self.account_history.set_workstation_by_ip(ip=ip, workstation=workstation)
        self.account_history.set_ip_by_workstation(ip=ip, workstation=workstation)

