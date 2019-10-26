#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    5136

    检测活动目录的ACL修改

    https://blogs.technet.microsoft.com/pfesweplat/2013/05/13/take-control-over-ad-permissions-and-the-ad-acl-scanner-tool/
"""

import copy

from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from modules.record_handle.AccountInfo import AccountInfo
from tools.SDDLParser import SDDLParser


EVENT_ID = [5136]

ALERT_CODE = "401"
TITLE = "ACL异常修改"
DESC_TEMPLATE = "来自 [source_ip]([source_workstation]) 使用账户 [source_user_name] 修改了ACL，添加了某个自定义账户，" \
                "通常用于权限提升。已知结合NTLM中继添加目录复制权限之后可远程dump域控密码。"


class ACLModify(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.parser = SDDLParser()
        self.account_info = AccountInfo()
        self.watch_object_class = ["container", "domainDNS", "groupPolicyContainer"]

    def run(self, log: Log):
        self.init(log=log)

        if log.object_info.class_ not in self.watch_object_class:
            return

        if log.event_data["AttributeLDAPDisplayName"] != "nTSecurityDescriptor":
            return

        abnormal_ace_list = []
        abnormal_users = []
        content = self.parser.parse(log.event_data["AttributeValue"])
        domain = log.subject_info.domain_name
        for ace in content["dacl_ace_list"]:
            trustee = ace["trustee"]
            # 判断是否为SID，因为这种ACL几乎都是默认的用户，很少特殊指定用户
            if trustee.startswith("S-1-5-21-"):
                # 首先检查 该SID是否为某个用户？（Users），如果不是，则忽略掉
                if not self.account_info.check_target_is_user_by_sid(trustee, domain):
                    continue
                # 获取用户信息
                user = self.account_info.get_user_info_by_sid(sid=trustee, domain=domain)
                # 目标是否为管理员权限
                if self.account_info.check_target_is_admin_by_sid(trustee, domain):
                    continue
                if user.user_name in abnormal_users:
                    continue

                abnormal_users.append(user.user_name)
                abnormal_ace = self._get_abnormal_ace(ace, domain)
                abnormal_ace_list.append(abnormal_ace)

        if len(abnormal_ace_list) > 0:
            return self._generate_alert_doc(
                object_class=log.object_info.class_,
                abnormal_ace_list=abnormal_ace_list,
                parsed_sddl=content,
                abnormal_users=abnormal_users
            )

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id, self.log.subject_info.full_user_name)
        form_data = {
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
            "source_ip": source_ip,
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
        return HIGH_LEVEL

    def _get_abnormal_ace(self, ace, domain) -> dict:
        trustee = ace["trustee"]
        ace["user_name"] = "unknown"
        user_info = self.account_info.get_user_info_by_sid(sid=trustee, domain=domain)
        if user_info:
            ace["user_name"] = user_info.user_name
        return copy.deepcopy(ace)


if __name__ == '__main__':
    pass
