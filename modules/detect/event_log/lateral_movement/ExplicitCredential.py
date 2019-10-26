#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4648

    显式凭据登录，绝大多数情况都是 localhost
    如果出现了其它的 TargetServerName ，则应当告警

    可能有误报的情况：域管理员的远程桌面登录
"""

from models.Log import Log
from modules.detect.DetectBase import DetectBase, MEDIUM_LEVEL
from tools.common.common import ip_filter

EVENT_ID = [4648]

ALERT_CODE = "302"
TITLE = "显式凭据远程登录"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 尝试使用显式凭据远程登录目标 [target_user_name]，这属于不常见的情况。"


class ExplicitCredential(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        if len(log.subject_info.user_sid.split("-")) == 4:
            return

        ip = log.source_info.ip_address
        if ip_filter(ip):
            return

        server_name = log.target_info.server_name
        if server_name == "localhost":
            return
        if log.target_info.info == "localhost":
            return

        return self._generate_alert_doc()

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_ip": self.log.source_info.ip_address,
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
            "target_info": self.log.target_info.info,
            "target_user_name": self.log.target_info.user_name,
            "target_domain": self.log.target_info.domain_name,
            "target_server_name": self.log.target_info.server_name,
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.source_info.ip_address),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return MEDIUM_LEVEL
