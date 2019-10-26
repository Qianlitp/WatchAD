#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    基于资源的约束委派

    5136

    AttributeLDAPDisplayName: msDS-AllowedToActOnBehalfOfOtherIdentity
"""

from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from models.Log import Log
from models.User import User
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from modules.record_handle.Delegation import Delegation, RES_BASED_CONSTRAINED_DELEGATION
from tools.LDAPSearch import LDAPSearch
from tools.common.common import get_domain_from_dn, get_cn_from_dn, get_netbios_domain
from modules.record_handle.AccountInfo import AccountInfo


EVENT_ID = [5136]

ALERT_CODE = "406"
TITLE = "基于资源的约束委派权限授予"
DESC_TEMPLATE = "来自 [source_ip]([source_workstation]) 使用身份 [source_user_name] 向计算机 [target_computer] 添加了基于资源的约束委派权限。"


class ResBasedConsDelegation(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.delegation = Delegation()
        self.account_info = AccountInfo()

    def run(self, log: Log):
        self.init(log=log)

        if log.event_data["AttributeLDAPDisplayName"] != "msDS-AllowedToActOnBehalfOfOtherIdentity":
            return

        # 只检测敏感计算机
        account = get_cn_from_dn(log.object_info.dn)
        domain = get_domain_from_dn(log.object_info.dn)
        if not self.account_info.computer_is_sensitive_by_name(account, domain=get_netbios_domain(domain)):
            return

        ldap = LDAPSearch(domain=domain)
        entry = ldap.search_by_cn(cn=account, attributes=["sid", "msDS-AllowedToActOnBehalfOfOtherIdentity"])
        if entry is None:
            return
        entry_sid = str(entry["sid"])

        sd = SR_SECURITY_DESCRIPTOR(entry.entry_attributes_as_dict["msDS-AllowedToActOnBehalfOfOtherIdentity"][0])
        # 拥有特殊DACL权限的SID列表
        ace_list = []
        for ace in sd["Dacl"].aces:
            ace_list.append({
                "type_name": ace["TypeName"],
                "sid": ace['Ace']['Sid'].formatCanonical()
            })
        sid_list = list(map(lambda ace: ace["sid"], ace_list))
        sid_list = sorted(list(set(sid_list)))

        target_account_info = User({
            "user_name": account,
            "user_sid": entry_sid
        })

        # 查询历史委派记录
        record = self.delegation.find_res_constrained_delegation_by_name(name=account)
        # 不存在记录 则新建 并直接告警
        if not record:
            self.delegation.new_delegation_record(user=target_account_info,
                                                  delegation_type=RES_BASED_CONSTRAINED_DELEGATION,
                                                  allowed_to=sid_list)
            return self._generate_alert_doc(target_computer=account,
                                            target_user_name=target_account_info.user_name,
                                            target_user_sid=target_account_info.user_sid,
                                            add_allowed_sid=sid_list,
                                            old_allowed_sid=[])

        # 存在记录且不变，退出
        if sid_list == record["allowed_to"]:
            return

        # 存在记录 对比历史的sid 无新增 更新记录 退出
        new_sids = self._get_new_sid(new_list=sid_list, old_list=record["allowed_to"])
        if len(new_sids) == 0:
            self.delegation.update_delegation(
                sid=entry_sid,
                delegation_type=RES_BASED_CONSTRAINED_DELEGATION,
                allowed_to=sid_list
            )
            return

        # 存在记录 有新增 更新记录 告警
        if len(new_sids) > 0:
            self.delegation.update_delegation(
                sid=entry_sid,
                delegation_type=RES_BASED_CONSTRAINED_DELEGATION,
                allowed_to=sid_list
            )
            return self._generate_alert_doc(target_computer=account,
                                            target_user_name=target_account_info.user_name,
                                            target_user_sid=target_account_info.user_sid,
                                            add_allowed_sid=new_sids,
                                            old_allowed_sid=record["allowed_to"])

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id,
                                                    self.log.subject_info.full_user_name)
        form_data = {
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
            "source_ip": source_ip,
            "source_user_name": self.log.subject_info.user_name,
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
        return HIGH_LEVEL

    def _get_new_sid(self, new_list, old_list) -> list:
        result = []
        for each in new_list:
            if each not in old_list:
                result.append(each)
        return result


if __name__ == '__main__':
    pass


