#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4672 特殊登录

    提权检测

    分析当前特殊登录的账号是否在管理员账号列表中，如果不在则告警

    目前已知的提权漏洞为 MS14-068
"""

from settings.config import main_config
from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from modules.record_handle.AccountInfo import AccountInfo
from tools.common.common import get_netbios_domain

EVENT_ID = [4672]

ALERT_CODE = "408"
TITLE = "未知权限提升"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 触发了域控 [dc_hostname] 上目标为 [target_user_name] 的特权登录事件，" \
                "但该目标不在已知管理员账户列表中，疑似未知方式的权限提升。"


class UnknownAdminLogin(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.account_info = AccountInfo()

    def run(self, log: Log):
        self.init(log=log)

        sid = log.subject_info.user_sid
        user_name = log.subject_info.user_name
        domain_name = log.subject_info.domain_name

        if domain_name.lower() == "window manager":
            return

        if not self._is_in_domain_list(domain_name):
            return

        if len(log.subject_info.user_sid.split("-")) == 4:
            return

        # 排除域控计算机账户的本地特权登录
        if user_name.endswith("$"):
            domain = get_netbios_domain(domain_name)
            if user_name[:-1] in main_config.dc_name_list[domain]:
                return

        if self.account_info.check_target_is_admin_by_sid(sid=sid, domain=domain_name):
            return

        return self._generate_alert_doc()

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id, self.log.subject_info.full_user_name)
        form_data = {
            "source_workstation": self._get_workstation_by_source_ip(source_ip),
            "source_ip": source_ip,
            "target_user_name": self.log.subject_info.user_name,
            "target_user_sid": self.log.subject_info.user_sid,
            "target_logon_id": self.log.subject_info.logon_id,
            "target_domain": self.log.subject_info.domain_name,
            "dc_hostname": self.log.dc_host_name,
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

    def _is_in_domain_list(self, domain: str) -> bool:
        """
            域名是否在已知需要监控的域列表中
        """
        domain = get_netbios_domain(domain)
        for each in main_config.domain_list:
            if domain == get_netbios_domain(each):
                return True
        return False


