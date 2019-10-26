#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp


"""
    1100

    事件日志服务关闭
"""

from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from models.Log import Log

EVENT_ID = [1100]

ALERT_CODE = "602"
TITLE = "域控事件日志服务被关闭"
DESC_TEMPLATE = "域控 [dc_hostname] 的安全事件日志服务被关闭。"


class CloseLogService(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "dc_hostname": self.log.dc_host_name,
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.subject_info.user_name),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return HIGH_LEVEL

    def run(self, log: Log):
        self.init(log=log)
        return self._generate_alert_doc()

