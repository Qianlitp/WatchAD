#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4742 5137 5141 4928

    DCShadow 检测

    分为三部分的特征：
    1. 计算机SPN修改  (spn modify)
    2. 域控创建和删除  (DC server create and delete)
    3. 同步监控 (Replication Monitoring)
"""

import re

from settings.config import main_config
from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from tools.common.common import get_netbios_domain, get_domain_from_dn

EVENT_ID = [4742, 5137, 5141, 4928]

ALERT_CODE = "502"
TITLE = "DCShadow攻击"
DESC_TEMPLATE = "监测到来自于 [source_ip]([source_workstation]) 使用身份 [source_user_name] 针对域控 [dc_hostname] 的DCShadow攻击行为，" \
                "用于使用管理员权限远程修改域内配置信息。"


SPN_MODIFY = "非域控计算机修改SPN为异常值"
SERVER_CREATE = "配置名称空间内创建服务，目标非域控计算机"
SERVER_DELETE = "配置名称空间内服务删除，目标非域控计算机"
SETTINGS_DELETE = "配置名称空间内设置删除，目标非域控计算机"
REPLICATION_MONITORING = "源命名上下文创建，发起来源非域控计算机"


class DCShadow(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log)

        result = None
        if log.event_id == 4742:
            result = self.spn_modify(log)
        elif log.event_id == 5137:
            result = self.fake_dc_server_create(log)
        elif log.event_id == 5141:
            result = self.fake_dc_server_delete(log)
            if not result:
                result = self.ntds_settings_delete(log)
        elif log.event_id == 4928:
            result = self.replication_monitoring(log)

        if result:
            return self._generate_alert_doc(**result)

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id, self.log.subject_info.full_user_name)
        if "source_workstation" in kwargs:
            source_workstation = kwargs["source_workstation"]
            del kwargs["source_workstation"]
        else:
            source_workstation = self._get_workstation_by_source_ip(source_ip)
        form_data = {
            "source_workstation": source_workstation,
            "source_ip": source_ip,
            "source_user_name": self.log.subject_info.user_name,
            "source_user_sid": self.log.subject_info.user_sid,
            "source_logon_id": self.log.subject_info.logon_id,
            "source_domain": self.log.subject_info.domain_name,
            "dc_hostname": self.log.dc_host_name,
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, source_ip),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return HIGH_LEVEL

    def spn_modify(self, log: Log):
        """
            event_id  4742
            非域控计算机修改SPN为异常值
        """
        # 目标服务器为已知的域控计算机名 则忽略
        target_computer_name = log.target_info.user_name[:-1]
        target_domain = get_netbios_domain(log.target_info.domain_name)
        if target_domain not in main_config.dc_name_list or target_computer_name in main_config.dc_name_list[target_domain]:
            return

        spn_list = log.event_data["ServicePrincipalNames"].split("\n\t\t")
        for spn in spn_list:
            if spn.startswith("GC/"):
                return {
                    "alert_rule": SPN_MODIFY,
                    "modify_computer": target_computer_name
                }
            if spn.startswith("E3514235-4B06-11D1-AB04-00C04FC2DCD2/"):
                return {
                    "alert_rule": SPN_MODIFY,
                    "modify_computer": target_computer_name
                }

    def fake_dc_server_create(self, log: Log):
        """
            event_id 5137

            配置名称空间内创建服务，目标非域控计算机
        """
        # 目标服务器为已知的域控计算机名 则忽略
        patt = re.compile("^CN=(.+?),.+", re.I)
        target_computer_name = patt.findall(log.object_info.dn)
        if not target_computer_name:
            return
        target_computer_name = target_computer_name[0]
        target_domain = get_netbios_domain(log.event_data["DSName"])
        if target_domain not in main_config.dc_name_list or target_computer_name in main_config.dc_name_list[target_domain]:
            return

        rule_list = ["CN=Default-First-Site-Name", "CN=Sites", "CN=Configuration", "CN=Servers"]
        if log.object_info.class_ == "server":
            for rule in rule_list:
                if rule.lower() not in log.object_info.dn.lower():
                    return
            # 规则都命中，则告警
            return {
                "alert_rule": SERVER_CREATE
            }

    def fake_dc_server_delete(self, log: Log):
        """
            event_id 5141

            配置名称空间内服务删除，目标非域控计算机
        """
        # 目标服务器为已知的域控计算机名 则忽略
        patt = re.compile("^CN=(.+?),.+", re.I)
        target_computer_name = patt.findall(log.object_info.dn)
        if not target_computer_name:
            return
        target_computer_name = target_computer_name[0]
        target_domain = get_netbios_domain(log.event_data["DSName"])
        if target_domain not in main_config.dc_name_list or target_computer_name in main_config.dc_name_list[target_domain]:
            return

        rule_list = ["CN=Servers", "CN=Default-First-Site-Name", "CN=Sites", "CN=Configuration"]
        if log.object_info.class_ == "server":
            for rule in rule_list:
                if rule.lower() not in log.object_info.dn.lower():
                    return
            # 四个规则全部命中 则告警
            return {
                "alert_rule": SERVER_DELETE
            }

    def ntds_settings_delete(self, log: Log):
        """
            event_id 5141

            配置名称空间内设置删除，目标非域控计算机
        """
        # 目标服务器为已知的域控计算机名 则忽略
        patt = re.compile("^CN=NTDS Settings,CN=(.+?),.+", re.I)
        target_computer_name = patt.findall(log.object_info.dn)
        if not target_computer_name:
            return
        target_computer_name = target_computer_name[0]
        target_domain = get_netbios_domain(log.event_data["DSName"])
        if target_domain not in main_config.dc_name_list or target_computer_name in main_config.dc_name_list[target_domain]:
            return
        rule_list = ["CN=NTDS Settings", "CN=Servers", "CN=Default-First-Site-Name", "CN=Sites", "CN=Configuration"]
        if log.object_info.class_ == "nTDSDSA":
            for rule in rule_list:
                if rule.lower() not in log.object_info.dn.lower():
                    return
            # 全部命中 则告警
            return {
                "alert_rule": SETTINGS_DELETE
            }

    def replication_monitoring(self, log: Log):
        """
            event_id  4928

            源命名上下文创建，发起来源非域控计算机
        """
        patt = re.compile("^CN=NTDS Settings,CN=(.+?),.+", re.I)
        source_computer = patt.findall(log.event_data["SourceDRA"])
        source_domain = get_domain_from_dn(log.event_data["SourceDRA"])
        if not source_computer:
            return
        source_computer = source_computer[0]
        netbios_domain = get_netbios_domain(source_domain)
        if netbios_domain not in main_config.dc_name_list or source_computer in main_config.dc_name_list[netbios_domain]:
            return

        # 如果当前的源地址不在已知的DC列表中，则告警
        return {
            "alert_rule": REPLICATION_MONITORING,
            "source_workstation": source_computer
        }


if __name__ == '__main__':
    pass
