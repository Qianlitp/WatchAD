#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    5136

    组策略委派权限更改，主要检测异常账号的加入
"""

from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from modules.record_handle.AccountInfo import AccountInfo
from tools.SDDLParser import SDDLParser

EVENT_ID = [5136]

ALERT_CODE = "504"
TITLE = "组策略委派权限授予"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 使用身份 [source_user_name] 赋予某些账户对组策略的修改委派权限。"


class GPODelegation(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.account_info = AccountInfo()

    def run(self, log: Log):
        self.init(log=log)

        if not log.object_info.dn:
            return
        assert isinstance(log.object_info.dn, str)
        # 组策略对象
        if not log.object_info.dn.lower().startswith("cn=policies,cn=system,"):
            return
        if not log.object_info.class_ == "container":
            return

        value = log.event_data["AttributeValue"]
        parser = SDDLParser()

        value_obj = parser.parse(value)

        domain = log.subject_info.domain_name

        abnormal_ace_list = []
        abnormal_users = []
        for each in value_obj["dacl_ace_list"]:
            trustee = each.get("trustee")
            if trustee.startswith("S-1-5-21-"):
                # 首先检查 该SID是否为某个用户？（Users），如果不是，则忽略掉
                if not self.account_info.check_target_is_user_by_sid(trustee, domain):
                    continue
                user = self.account_info.get_user_info_by_sid(trustee, domain)
                abnormal_users.append(user.user_name)
                abnormal_ace_list.append(each)

        if len(abnormal_ace_list) > 0:
            return self._generate_alert_doc(abnormal_ace_list=abnormal_ace_list,
                                            parsed_sddl=value_obj,
                                            abnormal_users=abnormal_users)

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
        return HIGH_LEVEL


if __name__ == '__main__':
    pass

