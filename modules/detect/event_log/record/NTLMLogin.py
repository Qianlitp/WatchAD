#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp


from models.Log import Log
from modules.record_handle.AccountActivity import AccountActivity, NTLM_LOGIN
from tools.common.common import ip_filter


EVENT_ID = [4624]


class NTLMLogin(object):
    def __init__(self):
        self.account_activity = AccountActivity(activity_type=NTLM_LOGIN)

    def run(self, log: Log):
        ip = log.source_info.ip_address

        if ip_filter(ip):
            return

        if log.event_data["AuthenticationPackageName"] != "NTLM":
            return

        if log.target_info.user_name == "ANONYMOUS LOGON":
            return

        workstation = log.source_info.work_station_name

        form_data = {
            "ip": log.source_info.ip_address,
            "lm_package_name": log.event_data["LmPackageName"],
            "source_workstation": workstation,
            "logon_type": log.event_data["LogonType"],
            "logon_id": log.target_info.logon_id
        }

        self.account_activity.save_activity(domain=log.target_info.domain_name,
                                            user_name=log.target_info.user_name,
                                            sid=log.target_info.user_sid,
                                            dc_name=log.dc_host_name,
                                            timestamp=log.utc_log_time,
                                            data=form_data)


