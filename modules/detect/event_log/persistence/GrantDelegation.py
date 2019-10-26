#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4738

    委派权限授权

    该手法可用作权限维持，通过对某个用户添加高权限的委派
"""

from settings.config import main_config
from models.Log import Log
from models.User import User
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from modules.record_handle.Delegation import Delegation, CONSTRAINED_DELEGATION
from tools.common.common import get_netbios_domain

EVENT_ID = [4738]

ALERT_CODE = "505"
TITLE = "Kerberos约束委派权限授予"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 使用身份 [source_user_name] 将目标用户 [target_user_name] " \
                "添加了一些高风险约束委派权限。"


class GrantDelegation(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.delegation = Delegation()

    def run(self, log: Log):
        if "AllowedToDelegateTo" not in log.event_data:
            return

        if log.event_data["AllowedToDelegateTo"] == "-":
            return

        allowed_to_list = _parse_to_list(log.event_data["AllowedToDelegateTo"])

        netbios_name = get_netbios_domain(log.target_info.domain_name)
        record = self.delegation.find_constrained_delegation_by_sid(log.target_info.sid)

        # 更新记录
        if record and record["delegation_type"] == CONSTRAINED_DELEGATION:
            if record["allowed_to"] == allowed_to_list:
                return
            else:
                self.delegation.update_delegation(sid=log.target_info.sid,
                                                  delegation_type=CONSTRAINED_DELEGATION,
                                                  allowed_to=allowed_to_list)
        else:
            self.delegation.new_delegation_record(
                user=User(log.target_info.__dict__),
                delegation_type=CONSTRAINED_DELEGATION,
                allowed_to=allowed_to_list
            )

        new_delegation_list = []
        for dele in allowed_to_list:
            if dele not in record["allowed_to"]:
                new_delegation_list.append(dele)

        # 查找新增高危约束委派
        high_risk_spn = self._check_high_risk_spn(new_delegation_list, netbios_name)
        if len(high_risk_spn) == 0:
            return
        return self._generate_alert_doc(allowed_to_delegate_to=allowed_to_list,
                                        new_delegation_list=new_delegation_list)

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id,
                                                    self.log.subject_info.full_user_name)
        form_data = {
            "source_ip": source_ip,
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
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

    def _check_high_risk_spn(self, delegation_list: list, netbios_name: str) -> list:
        """
            增加约束委派权限的高危SPN检测
            1. 包含域控主机名 可直接接管域控
            2. 服务名包含 krbtgt 变种金票
            3. 服务名包含 LDAP 可导致DCSync
            等等
        """
        high_risk_list = []
        for each in delegation_list:
            for server in main_config.high_risk_delegation_prefix:
                if each.startswith(server):
                    high_risk_list.append(each)

            for dc in main_config.dc_name_list[netbios_name]:
                if dc in each:
                    high_risk_list.append(each)
        return list(set(high_risk_list))


def _parse_to_list(data: str) -> list:
    return data.split("\n\t\t")[1:]
