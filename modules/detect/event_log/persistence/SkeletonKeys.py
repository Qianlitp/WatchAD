#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i

"""
    4771

    万能钥匙 主动检测

    PreAuthType = 0 同时 Status 为 0xe
    配合 scripts/skeleton_key_scan 进行定时扫描
"""
from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL

EVENT_ID = [4771]

ALERT_CODE = "510"
TITLE = "万能钥匙-主动检测"
DESC_TEMPLATE = "通过来自于 [source_ip]([source_workstation]) 发起的主动扫描，在域控 [dc_hostname] 上发现了万能钥匙后门。"


class SkeletonKeys(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        # skeleton 扫描时使用的特定 options 0x50802000
        if log.ticket_info.options != "0x50802000":
            return

        if log.event_data["PreAuthType"] != "0":
            return

        if log.event_data["Status"] != "0xe":
            return

        return self._generate_alert_doc()

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_ip": self.log.source_info.ip_address,
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
            "detect_type": "active",
            "target_user_name": self.log.target_info.user_name,
            "target_sid": self.log.target_info.sid,
            "dc_hostname": self.log.dc_host_name,
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.dc_computer_name),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return HIGH_LEVEL
