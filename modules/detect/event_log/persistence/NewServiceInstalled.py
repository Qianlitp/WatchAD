#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4697 安装了新的服务

    安装新服务属于敏感事件，全部作为低危信息告警
"""


from models.Log import Log
from modules.detect.DetectBase import DetectBase, MEDIUM_LEVEL

EVENT_ID = [4697]

ALERT_CODE = "507"
TITLE = "域控新增系统服务"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 使用身份 [source_user_name] 在域控 [dc_hostname] " \
                "上创建了新的系统服务 [service_name]。"


class NewServiceInstalled(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        return self._generate_alert_doc()

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id,
                                                    self.log.subject_info.full_user_name)
        form_data = {
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
            "dc_hostname": self.log.dc_host_name,
            "source_ip": source_ip,
            "source_user_name": self.log.subject_info.user_name,
            "source_user_sid": self.log.subject_info.user_sid,
            "source_logon_id": self.log.subject_info.logon_id,
            "service_name": self.log.event_data.get("ServiceName", ""),
            "service_file_name": self.log.event_data.get("ServiceFileName", ""),
            "service_type": self.log.event_data.get("ServiceType", ""),
            "service_start_type": self.log.event_data.get("ServiceStartType", ""),
            "service_account": self.log.event_data.get("ServiceAccount", ""),
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.subject_info.user_name),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return MEDIUM_LEVEL
