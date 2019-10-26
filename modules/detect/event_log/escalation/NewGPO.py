#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp


"""
    5137

    新增组策略
"""

import re
from models.Log import Log
from modules.detect.DetectBase import DetectBase, LOW_LEVEL

EVENT_ID = [5137]

ALERT_CODE = "404"
TITLE = "新增组策略"
DESC_TEMPLATE = "来自 [source_ip]([source_workstation]) 使用身份 [source_user_name] 创建了新的组策略。"


class NewGPO(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        if log.object_info.class_ != "groupPolicyContainer":
            return
        assert isinstance(log.object_info.dn, str)
        if "cn=policies,cn=system," not in log.object_info.dn.lower():
            return
        patt = re.compile(r"CN={(.+?)},", re.I)
        new_gpo_guid_match = patt.findall(log.object_info.dn)
        if not new_gpo_guid_match:
            return
        new_gpo_guid = new_gpo_guid_match[0]
        return self._generate_alert_doc(gpo_guid=new_gpo_guid)

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id, self.log.subject_info.full_user_name)
        form_data = {
            "source_ip": source_ip,
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
            "source_user_name": self.log.subject_info.user_name,
            "source_user_sid": self.log.subject_info.user_sid,
            "source_logon_id": self.log.subject_info.logon_id,
            "source_domain": self.log.subject_info.domain_name,
            "object_info": self.log.object_info.get_doc(),
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.subject_info.user_name),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return LOW_LEVEL
