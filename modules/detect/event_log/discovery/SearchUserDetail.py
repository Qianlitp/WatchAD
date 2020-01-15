#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4661

    查询敏感用户的详细信息

    不检查subject user 为机器名的情况
"""

from modules.detect.DetectBase import DetectBase, LOW_LEVEL
from models.Log import Log
from modules.record_handle.AccountHistory import AccountHistory
from modules.record_handle.AccountInfo import AccountInfo
from tools.LDAPSearch import LDAPSearch
from tools.common.common import filter_domain

EVENT_ID = [4661]

ALERT_CODE = "102"
TITLE = "使用SAMR查询敏感用户"
DESC_TEMPLATE = "来自 [source_ip]([source_workstation]) 的账户 [source_user_name] 使用SAMR查询了敏感用户 [target_user_name] 的信息。"


class SearchUserDetail(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.account_info = AccountInfo()
        self.account_history = AccountHistory()

    def run(self, log: Log):
        self.init(log=log)

        if log.object_info.type != "SAM_USER":
            return

        user_name = log.subject_info.user_name
        if user_name.endswith("$"):
            return

        target_sid = log.object_info.name
        if not target_sid.startswith("S-1-5-21-"):
            return

        # 查询自身也忽略
        if log.subject_info.user_sid == target_sid:
            return

        # 判断域名是否存在于需要检查的域名中
        domain_name = log.subject_info.domain_name
        if filter_domain(domain_name):
            return

        # 如果账号是管理员 直接忽略
        if self.account_info.check_target_is_admin_by_sid(sid=log.subject_info.user_sid, domain=domain_name):
            return

        # 判断操作者是否为Users
        if not self.account_info.check_target_is_user_by_name(user_name, domain_name):
            return

        # 判断是否为敏感用户
        if not self.account_info.user_is_sensitive_by_sid(sid=target_sid, domain=domain_name):
            return

        ldap = LDAPSearch(domain_name)
        target = ldap.search_by_sid(target_sid, attributes=["cn"])
        if not target:
            return
        target_user_name = str(target["cn"])
        return self._generate_alert_doc(target_user_name=target_user_name)

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


if __name__ == '__main__':
    pass
