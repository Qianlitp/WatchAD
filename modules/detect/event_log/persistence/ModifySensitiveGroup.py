#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4728, 4732, 4756

    新增域管理员
    准确一点说，是安全组中新增加了用户
    这种情况少见，不论情况均告警，可抄送IT部门协助确认
"""
from settings.config import main_config
from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from tools.common.common import get_cn_from_dn

EVENT_ID = [4728, 4732, 4756]

ALERT_CODE = "506"
TITLE = "敏感用户组修改"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 使用身份 [source_user_name] 将目标用户 [target_user_name] " \
                "添加到了敏感组 [group_name] 中。"


class ModifySensitiveGroup(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        group_name = log.target_info.user_name

        sensitive_groups = list(map(lambda x: x["name"], main_config.sensitive_groups))
        if group_name in sensitive_groups:
            return self._generate_alert_doc()

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id,
                                                    self.log.subject_info.full_user_name)
        form_data = {
            "source_ip": source_ip,
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
            "group_name": self.log.target_info.user_name,
            "group_sid": self.log.event_data["TargetSid"],
            "target_user_name": get_cn_from_dn(self.log.event_data["MemberName"]),
            "target_user_dn": self.log.event_data["MemberName"],
            "target_user_sid": self.log.event_data["MemberSid"],
            "target_domain": self.log.target_info.domain_name,
            "source_user_name": self.log.subject_info.user_name,
            "source_user_sid": self.log.subject_info.user_sid,
            "source_logon_id": self.log.subject_info.logon_id,
            "source_domain": self.log.subject_info.domain_name,
            "privilege_list": self.log.event_data["PrivilegeList"]
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.subject_info.user_name),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return HIGH_LEVEL
