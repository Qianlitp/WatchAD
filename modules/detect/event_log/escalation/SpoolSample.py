#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    5145

    https://github.com/leechristensen/SpoolSample
    https://adsecurity.org/?p=4056
    https://xz.aliyun.com/t/2896

    能从日志获取的信息有限，判断逻辑较为单一，存在误报的可能
"""

from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from tools.common.common import ip_filter

EVENT_ID = [5145]

ALERT_CODE = "407"
TITLE = "攻击打印机服务 SpoolSample"
DESC_TEMPLATE = "域控 [dc_hostname] 收到了来自于 [source_ip]([source_workstation]) 身份为 [source_user_name] 的主动认证发起请求，" \
                "该行为一般用于诱导域控发起NTLM认证，经恶意目标中继后提升权限。"


class SpoolSample(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        if "RelativeTargetName" not in log.event_data:
            return
        ip = log.source_info.ip_address
        if ip_filter(ip):
            return

        relative_target_name = log.event_data["RelativeTargetName"]
        if relative_target_name == "spoolss":
            return self._generate_alert_doc()

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_ip": self.log.source_info.ip_address,
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
            "source_user_name": self.log.subject_info.user_name,
            "source_user_sid": self.log.subject_info.user_sid,
            "source_logon_id": self.log.subject_info.logon_id,
            "relative_target_name": self.log.event_data["RelativeTargetName"],
            "dc_hostname": self.log.dc_host_name,
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.source_info.ip_address),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return HIGH_LEVEL
