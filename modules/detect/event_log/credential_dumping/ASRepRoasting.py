#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4768

    通过对 不要求kerberos身份预认证的账号 请求TGT，用于离线破解密码

    特征：
    ServiceName krbtgt
    TicketEncryptionType 0x17
    PreAuthType 0

    Rubeus.exe asreproast /user:honeypotuser /dc:192.168.0.16 /domain:360testad.com
"""

from modules.detect.DetectBase import DetectBase, MEDIUM_LEVEL
from models.Log import Log
from modules.record_handle.TicketRecords import TicketRecords

EVENT_ID = [4768]

ALERT_CODE = "202"
TITLE = "AS-REP Roasting"
DESC_TEMPLATE = "收到针对开启了不需要kerberos预认证账户 [target_user_name] 的票据授予票据（TGT）请求，" \
                "且结合该来源 [source_ip]([source_workstation]) 的历史行为，票据加密类型降级为RC4-HMAC。"


class ASRepRoasting(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        if log.event_data["Status"] != "0x0":
            return

        if log.event_data["ServiceName"] != "krbtgt":
            return

        if log.ticket_info.encryption_type != "0x17":
            return

        # 不需要身份预认证
        if log.event_data["PreAuthType"] == "0":
            return self._generate_alert_doc()

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_ip": self.log.source_info.ip_address,
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
            "target_user_name": self.log.target_info.user_name,
            "ticket_info": self.log.ticket_info.get_doc(),
            "tools_match": TicketRecords.sec_tools_match(self.log.ticket_info.options),
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.source_info.ip_address),
            form_data=form_data
        )
        return doc

    def _get_level(self):
        """
            危害等级 中
        """
        return MEDIUM_LEVEL
