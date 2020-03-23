#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4661

    枚举某个内置域管理员成员组
    如 net group "Domain Admins" /domain
"""


from settings.config import main_config
from models.Log import Log
from modules.detect.DetectBase import DetectBase, LOW_LEVEL
from modules.record_handle.AccountInfo import AccountInfo
from tools.LDAPSearch import LDAPSearch


EVENT_ID = [4661]

ALERT_CODE = "101"
TITLE = "使用SAMR查询敏感用户组"
DESC_TEMPLATE = "来自 [source_ip]([source_workstation]) 的账户 [source_user_name] 使用SAMR查询了敏感组 [group_name] 的信息。"


class EnumerateGroup(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.account_info = AccountInfo()

    def run(self, log: Log):
        self.init(log=log)

        if log.object_info.server != "Security Account Manager":
            return

        if log.object_info.type != "SAM_GROUP":
            return
            
        # 取事件发起的用户sid
        sid = log.subject_info.user_sid
        if not sid.startswith("S-1-5-21-"):
            return

        user_name = log.subject_info.user_name
        if user_name.endswith("$"):
            return

        # 如果账号是管理员 直接忽略
        if self.account_info.check_target_is_admin_by_sid(sid=sid, domain=log.subject_info.domain_name):
            return

        # 判断账号是否为 Users，如果不是，直接退出
        if not self.account_info.check_target_is_user_by_name(user_name, log.subject_info.domain_name):
            return
        # 验证cn无意义
        return self._generate_alert_doc(group_name=group_name)


    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id, self.log.subject_info.full_user_name)
        form_data = {
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
            "source_ip": source_ip,
            "source_user_name": self.log.subject_info.user_name,
            "source_user_sid": self.log.subject_info.user_sid,
            "source_logon_id": self.log.subject_info.logon_id,
            "source_domain": self.log.subject_info.domain_name,
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
