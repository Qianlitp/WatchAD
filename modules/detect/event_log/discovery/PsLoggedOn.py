#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    5145

    这个是属于 PsTools工具集中的一个，用于查看某台机器上登录的用户

    查找详细的文件共享， winreg -> lsarpc -> srvsvc
"""


from models.Log import Log
from modules.detect.DetectBase import DetectBase, LOW_LEVEL
from modules.record_handle.AccountInfo import AccountInfo
from tools.common.common import datetime_to_utc, move_n_min, utc_to_datetime, get_netbios_domain
from tools.common.errors import MsearchException
from tools.database.ElsaticHelper import *

EVENT_ID = [5145]

ALERT_CODE = "103"
TITLE = "PsLoggedOn信息收集"
DESC_TEMPLATE = "来自 [source_ip]([source_workstation]) 使用身份 [source_user_name] 通过工具PsLoggedOn去探测域控 " \
                "[dc_hostname] 上已登录用户信息。"


class PsLoggedOn(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.es = ElasticHelper()
        self.account_info = AccountInfo()

    def run(self, log: Log):
        self.init(log=log)

        if log.event_data["ShareName"] != r"\\*\IPC$":
            return

        if log.event_data["RelativeTargetName"] != "srvsvc":
            return

        # 忽略域管理员的访问
        if self.account_info.check_target_is_admin_by_sid(sid=log.subject_info.user_sid,
                                                          domain=log.subject_info.domain_name):
            return

        # 存在向前查找，则延迟确认
        if "_delay_info" not in log.record:
            self.delay_confirm_log()
            return
        self.es.wait_log_in_database(log.dc_computer_name, log.record_number)

        is_match = self._search_forward(log)
        if is_match:
            return self._generate_alert_doc()

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
            "source_ip": self.log.source_info.ip_address,
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
        return LOW_LEVEL

    def _search_forward(self, log: Log):
        """

        """
        base = {
            "index": ElasticConfig.event_log_index,
            "doc_type": ElasticConfig.event_log_doc_type
        }
        # 开始向前查找
        msearch_body = [base]
        body_winreg = self._get_query(log, "winreg")
        msearch_body.append(body_winreg)

        msearch_body.append(base)
        body_lsarpc = self._get_query(log, "lsarpc")
        msearch_body.append(body_lsarpc)

        results = self.es.multi_search(body=msearch_body,
                                       index=ElasticConfig.event_log_index,
                                       doc_type=ElasticConfig.event_log_doc_type)
        for each in results["responses"]:
            if each.get("error"):
                logger.error("PsLoggedOn module - multi search error: " + each.get("error").get("reason"))
                raise MsearchException()
            elif each["hits"]["total"] == 0:
                return False
        return True

    def _get_query(self, log: Log, relative_target_name):
        computer_term = get_term_statement("computer_name", log.dc_computer_name),
        ago_time = move_n_min(utc_to_datetime(log.utc_log_time), 1)
        time_str = datetime_to_utc(ago_time)
        logon_id_term = get_term_statement("event_data.SubjectLogonId.keyword", log.subject_info.logon_id)
        share_name_term = get_term_statement("event_data.ShareName.keyword", r"\\*\IPC$")
        time_term = get_time_range("gt", time_str),
        relative_term = get_term_statement("event_data.RelativeTargetName.keyword", relative_target_name)
        query = {
            "query": get_must_statement(logon_id_term, share_name_term, relative_term, time_term, computer_term),
            "_source": False,
            "size": 1
        }
        return query
