#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    5145 5142

    远程命令执行

    获取的日志信息有限，只能通过检查RelativeTargetName来大致判断，可被修改绕过
"""

import re
from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from tools.common.common import ip_filter

EVENT_ID = [5145, 5142]

ALERT_CODE = "303"
TITLE = "目标域控的远程代码执行"
DESC_TEMPLATE = "监测到来自于 [source_ip]([source_workstation]) 使用身份 [source_user_name] 在域控 [dc_hostname] 上远程执行命令。"


class RemoteCommandExec(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)

    def run(self, log: Log):
        self.init(log=log)

        result = []
        if log.event_id == 5145:
            result.append(self.check_ps_exec(log))
            result.append(self.check_wmiexec(log))
            result.append(self.check_smbexec(log))
        elif log.event_id == 5142:
            result.append(self.check_wmiexec_vbs(log))
        for tool in result:
            if tool:
                return self._generate_alert_doc(tool_name=tool)

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_ip": self.log.source_info.ip_address,
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
            "source_user_name": self.log.subject_info.user_name,
            "source_user_sid": self.log.subject_info.user_sid,
            "source_logon_id": self.log.subject_info.logon_id,
            "source_domain": self.log.subject_info.domain_name,
            "dc_hostname": self.log.dc_host_name,
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.source_info.ip_address),
            form_data=form_data
        )
        return doc

    def _get_level(self) -> str:
        return HIGH_LEVEL

    def check_ps_exec(self, log: Log):
        """
            5145
            复现记录的特征较多，目前只用5145即可

            这个是官方的远程管理工具，需要排除IT人员的操作误报
        """
        if ip_filter(log.source_info.ip_address):
            return
        # 需要admin共享
        if log.event_data["ShareName"] != r"\\*\ADMIN$":
            return

        # 同时relative target name 为 PSEXESVC.exe
        if log.event_data["RelativeTargetName"] == "PSEXESVC.exe":
            return "PsExec"

    def check_wmiexec(self, log: Log):
        """
            5145
            检测 admin 共享开启, 同时 RelativeTargetName 为时间戳形式
        """
        if ip_filter(log.source_info.ip_address):
            return

        # 需要admin共享
        if log.event_data["ShareName"] != r"\\*\ADMIN$":
            return

        relative_target_name = log.event_data["RelativeTargetName"]
        if not relative_target_name:
            return

        if re.search(r"^__\d{10}\.\d", relative_target_name):
            return "wmi_exec"

    def check_wmiexec_vbs(self, log: Log):
        """
            5142
            添加文件共享对象 WMI_SHARE
        """
        if ip_filter(log.source_info.ip_address):
            return
        if log.event_data["ShareName"] != r"\\*\WMI_SHARE":
            return

        if "ShareLocalPath" not in log.event_data:
            return

        if log.event_data["ShareLocalPath"].lower() == r"c:\windows\temp":
            return "wmi_exec"

    def check_smbexec(self, log: Log):
        """
            5145

            RelativeTargetName __output
        """
        if ip_filter(log.source_info.ip_address):
            return

        if log.event_data["ShareName"] != r"\\*\C$":
            return

        relative_target_name = log.event_data["RelativeTargetName"]
        if not relative_target_name:
            return

        if relative_target_name != "__output":
            return

        return "smb_exec"
