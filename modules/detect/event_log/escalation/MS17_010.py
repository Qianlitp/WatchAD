#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    5140

    使用工具 https://github.com/apkjet/TrustlookWannaCryToolkit 扫描时，会触发该规则

    使用原版exp 只触发 5140，且 SubjectLogonId 为一个不存在的值（0x后接5位随机数），即没有任何登录事件与之关联

    该检测逻辑不能保证完全准确，单从该日志获取的有限信息只能粗略检测攻击，存在误报的可能性（目前内部观察未出现误报）。
"""

from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from tools.database.ElsaticHelper import *

EVENT_ID = [5140]

ALERT_CODE = "403"
TITLE = "MS17-010攻击"
DESC_TEMPLATE = "来自 [source_ip]([source_workstation]) 发起了针对域控 [dc_hostname] 的MS17-010攻击。"


class MS17_010(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.es = ElasticHelper()

    def run(self, log: Log):
        self.init(log=log)

        if log.subject_info.user_sid != "S-1-5-7":
            return

        if log.subject_info.user_name != "ANONYMOUS LOGON":
            return

        if log.subject_info.domain_name != "NT AUTHORITY":
            return

        if log.event_data["ShareName"] != r"\\*\IPC$":
            return

        # 如果存在向前查找，则延迟确认
        if "_delay_info" not in log.record:
            self.delay_confirm_log()
            return
        self.es.wait_log_in_database(log.dc_computer_name, log.record_number)

        # 如果为 0x 后接5位随机数，则为原版相关衍生POC
        if len(log.subject_info.logon_id) == 7:
            if not self._confirm_no_id_logon(log.subject_info.logon_id):
                return
        # 微软提供的POC
        else:
            if not self._find_anonymous_null_logon(log.subject_info.logon_id):
                return

        return self._generate_alert_doc()

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_ip": self.log.source_info.ip_address,
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
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

    def _find_anonymous_null_logon(self, logon_id) -> bool:
        """
            4624

            查找匿名登录
        """

        id_term = get_term_statement("event_id", "4624")
        logon_id_term = get_term_statement("event_data.TargetLogonId.keyword", logon_id)
        anonymous_term = get_term_statement("event_data.TargetUserName.keyword", "ANONYMOUS LOGON")
        lm_term = get_term_statement("event_data.LmPackageName.keyword", "NTLM V1")
        workstation_term = get_term_statement("event_data.WorkstationName.keyword", "NULL")

        query = {
            "query": get_must_statement(id_term, logon_id_term, anonymous_term, lm_term, workstation_term),
            "size": 0
        }

        rsp = self.es.search(body=query, index=ElasticConfig.event_log_index, doc_type=ElasticConfig.event_log_doc_type)
        if rsp:
            return rsp["hits"]["total"] > 0
        else:
            return False

    def _confirm_no_id_logon(self, logon_id) -> bool:
        """
            4624 4634

            确认该登录IP没有任何与之相关的登录事件
        """
        id_term = get_should_statement(
            get_term_statement("event_id", 4624),
            get_term_statement("event_id", 4634)
        )
        logon_id_term = get_term_statement("event_data.TargetLogonId.keyword", logon_id)
        anonymous_term = get_term_statement("event_data.TargetUserName.keyword", "ANONYMOUS LOGON")

        query = {
            "query": get_must_statement(id_term, logon_id_term, anonymous_term),
            "size": 0
        }

        rsp = self.es.search(body=query, index=ElasticConfig.event_log_index, doc_type=ElasticConfig.event_log_doc_type)
        if rsp:
            return rsp["hits"]["total"] == 0
        else:
            return False


if __name__ == '__main__':
    pass
