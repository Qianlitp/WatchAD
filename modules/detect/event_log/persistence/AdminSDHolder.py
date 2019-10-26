#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    5136

    AdminSDHolder 更改，一般用作权限维持，因为更改情况极少，所以直接告警
"""

import re

from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from tools.SDDLParser import SDDLParser

EVENT_ID = [5136]

ALERT_CODE = "501"
TITLE = "AdminSDHolder对象修改"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 使用身份 [source_user_name] 修改了AdminSDHolder对象，" \
                "该对象的ACL权限是其它对象的默认模板，恶意修改后可用于权限维持。"


class AdminSDHolder(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.parser = SDDLParser()

    def run(self, log: Log):
        self.init(log=log)

        if log.object_info.class_ != "container":
            return
        if log.event_data["AttributeLDAPDisplayName"] != "nTSecurityDescriptor":
            return

        patt = re.compile(r"^CN=AdminSDHolder,CN=System,.+", re.I)
        if not patt.match(log.object_info.dn):
            return

        content = self.parser.parse(log.event_data["AttributeValue"])

        return self._generate_alert_doc(parsed_sddl=content)

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id,
                                                    self.log.subject_info.full_user_name)
        form_data = {
            "source_ip": source_ip,
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
            "object_info": self.log.object_info.get_doc(),
            "source_user_name": self.log.subject_info.user_name,
            "source_user_sid": self.log.subject_info.user_sid,
            "source_logon_id": self.log.subject_info.logon_id,
            "source_domain": self.log.subject_info.domain_name,
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.subject_info.user_name),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return HIGH_LEVEL
