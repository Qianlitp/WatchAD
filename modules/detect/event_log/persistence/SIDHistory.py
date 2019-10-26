#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4765 4766

    SIDHistory 权限维持

    只适用于
    Windows Server 2003,
    Windows Server 2003 R2,
    Windows Server 2003 with SP1,
    Windows Server 2003 with SP2

    目前不考虑其它情况  出现即告警

"""


from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL

EVENT_ID = [4765, 4766]

ALERT_CODE = "509"
TITLE = "SIDHistory属性修改"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 使用身份 [source_user_name] " \
                "修改了目标账户 [target_user_name] 的SIDHistory属性。"


class SIDHistory(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        if log.event_id == 4765:
            return self._generate_alert_doc(is_success=True)
        else:
            return self._generate_alert_doc(is_success=False)

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id,
                                                    self.log.subject_info.full_user_name)
        form_data = {
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
            "source_ip": source_ip,
            "source_user_name": self.log.subject_info.user_name,
            "source_user_sid": self.log.subject_info.user_sid,
            "source_logon_id": self.log.subject_info.logon_id,
            "source_domain": self.log.subject_info.domain_name,
            "target_user_name": self.log.target_info.user_name,
            "target_domain": self.log.target_info.domain_name,
            "target_user_sid": self.log.target_info.sid,
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
