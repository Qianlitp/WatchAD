#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    蜜罐账号活动
"""

from modules.detect.DetectBase import DetectBase, MEDIUM_LEVEL
from settings.config import main_config
from models.Log import Log

EVENT_ID = [4768, 4769, 4770, 4771, 4776, 4624, 4625, 4648]

ALERT_CODE = "104"
TITLE = "蜜罐账户的活动"
DESC_TEMPLATE = "检测到来自于 [source_ip]([source_workstation]) 尝试访问蜜罐账户 [target_user_name]。正常情况下，" \
                "蜜罐账户不应该有任何活动，所有相关活动都是恶意的。"


class HoneypotUser(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        target_user_name = log.target_info.user_name
        for each in main_config.honeypot_account:
            if each["name"] == target_user_name:

                if log.event_id == 4776:
                    workstation = log.event_data["Workstation"]
                    source_ip = self._get_source_ip_by_workstation(workstation)
                else:
                    source_ip = log.source_info.ip_address
                    workstation = self._get_workstation_by_source_ip(source_ip)

                return self._generate_alert_doc(source_ip=source_ip,
                                                source_workstation=workstation)

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "target_user_name": self.log.target_info.user_name,
            "activity_event_id": self.log.event_id,
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, kwargs["source_workstation"]),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return MEDIUM_LEVEL


