#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    8222 4674 4658

    检测从域控远程获取密码事件

    因为这几个检测都需要多个日志记录一起判断，所以选取流程末尾的日志，然后在ES中向前查询相关的日志是否存在
"""

from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from models.Log import Log, SubjectInfo
from tools.common.common import move_n_min, utc_to_datetime, datetime_to_utc, get_netbios_domain
from tools.common.errors import MsearchException
from tools.database.ElsaticHelper import *

ALERT_CODE = "203"
TITLE = "远程Dump域控密码"
DESC_TEMPLATE = "监测到来自于 [source_ip]([source_workstation]) 的 [source_user_name] 尝试窃取域控 [dc_hostname] 的NTDS.dit文件内容。"

EVENT_ID = [8222, 4674, 4658]

REMOTELY_WMIC_VSS_COPY = "远程wmic VSSCopy"
REMOTELY_INVOKE_MIMIKATZ_DUMP = "远程Invoke-Mimikatz"
REMOTELY_INVOKE_NINJACOPY_DUMP = "远程Invoke-NinjaCopy"


class DumpPassword(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.es = ElasticHelper()

    def run(self, log: Log):
        self.init(log=log)
        if log.event_id == 8222:
            doc = self.wmic_vss(log=log)
        elif log.event_id == 4674:
            doc = self.invoke_mimikatz(log=log)
        else:
            doc = self.invoke_NinjaCopy(log=log)

        if doc:
            return self._generate_alert_doc(**doc)

    def _generate_alert_doc(self, **kwargs) -> dict:
        source_ip = self._get_source_ip_by_logon_id(self.log.subject_info.logon_id,
                                                    self.log.subject_info.full_user_name)
        form_data = {
            "source_ip": source_ip,
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
            "source_user_name": self.log.subject_info.user_name,
            "source_logon_id": self.log.subject_info.logon_id,
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

    def wmic_vss(self, log: Log):
        """
            wmic 远程 卷影拷贝

            8222

            4688 -> 4688 -> 4904 -> 8222
        """
        user_info = log.event_data["param2"]
        log.subject_info = SubjectInfo({
            "SubjectDomainName": user_info.split("\\")[0],
            "SubjectUserName": user_info.split("\\")[1],
            "SubjectUserSid": log.event_data["param1"]
        })
        vss_copy_path = log.event_data["param9"]

        # 如果存在向前查找，则延迟确认
        if "_delay_info" not in log.record:
            self.delay_confirm_log()
            return
        self.es.wait_log_in_database(log.dc_computer_name, log.record_number)

        base = {
            "index": ElasticConfig.event_log_index,
            "doc_type": ElasticConfig.event_log_doc_type
        }

        # 开始向前查找
        msearch_body = [base]
        body_4904 = self._get_query(log, 4904,
                                    get_term_statement("event_data.ProcessName.keyword",
                                                       r"C:\Windows\System32\VSSVC.exe"),
                                    get_term_statement("event_data.AuditSourceName.keyword", "VSSAudit")
                                    )
        msearch_body.append(body_4904)

        msearch_body.append(base)
        body_4688_vssvc = self._get_query(log, 4688,
                                          get_term_statement("event_data.NewProcessName.keyword",
                                                             r"C:\Windows\System32\VSSVC.exe")
                                          )
        msearch_body.append(body_4688_vssvc)

        msearch_body.append(base)
        body_4688_vssadmin = self._get_query(log, 4688,
                                             get_term_statement("event_data.NewProcessName.keyword",
                                                                r"C:\Windows\System32\vssadmin.exe")
                                             )
        msearch_body.append(body_4688_vssadmin)

        results = self.es.multi_search(body=msearch_body,
                                       index=ElasticConfig.event_log_index,
                                       doc_type=ElasticConfig.event_log_doc_type)

        for each in results["responses"]:
            if each.get("error"):
                logger.error("dump password module - wmic_vss multi search error: " + each.get("error").get("reason"))
                raise MsearchException()
            elif each["hits"]["total"] == 0:
                return

        return {
            "method": REMOTELY_WMIC_VSS_COPY,
            "vss_copy_path": vss_copy_path
        }

    def invoke_mimikatz(self, log: Log):
        """
            4674
            invoke-mimikatz 远程dump

            4656 -> 4674 -> 4688 -> 4674
        """
        if log.object_info.type != "Key" or log.object_info.server != "Security":
            return
        if "ProcessName" not in log.event_data or not log.event_data["ProcessName"]:
            return
        if log.event_data["ProcessName"].lower() != r"c:\windows\system32\wbem\wmiprvse.exe":
            return
        if log.object_info.name.lower() != r"\registry\machine\software\microsoft\windows nt\currentversion\perflib":
            return

        user_name = log.subject_info.full_user_name

        # 如果存在向前查找，则延迟确认
        if "_delay_info" not in log.record:
            self.delay_confirm_log()
            return
        self.es.wait_log_in_database(log.dc_computer_name, log.record_number)

        base = {
            "index": ElasticConfig.event_log_index,
            "doc_type": ElasticConfig.event_log_doc_type
        }

        # 开始向前查找
        msearch_body = [base]
        body_4688 = self._get_query(log, 4688,
                                    get_term_statement("event_data.NewProcessName.keyword",
                                                       r"C:\Windows\System32\wbem\WmiPrvSE.exe"
                                                       )
                                    )
        msearch_body.append(body_4688)
        msearch_body.append(base)
        body_4674 = self._get_query(log, 4674,
                                    get_term_statement("event_data.SubjectUserName.keyword", user_name),
                                    get_term_statement("event_data.ProcessName.keyword",
                                                       r"C:\Windows\System32\wsmprovhost.exe"
                                                       ),
                                    get_match_must_all("event_data.ObjectName",
                                                       r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\services\WinSock2\Parameters"),
                                    )
        msearch_body.append(body_4674)
        msearch_body.append(base)
        body_4656 = self._get_query(log, 4656,
                                    get_term_statement("event_data.ProcessName.keyword",
                                                       r"C:\Windows\System32\wsmprovhost.exe"
                                                       ),
                                    get_match_must_all("event_data.ObjectName",
                                                       r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN"),
                                    )
        msearch_body.append(body_4656)

        results = self.es.multi_search(body=msearch_body,
                                       index=ElasticConfig.event_log_index,
                                       doc_type=ElasticConfig.event_log_doc_type)

        for each in results["responses"]:
            if each.get("error"):
                logger.error("dump password module - invoke_mimikatz multi search error: " + each.get("error").get("reason"))
                raise MsearchException()
            elif each["hits"]["total"] == 0:
                return

        return {
            "method": REMOTELY_INVOKE_NINJACOPY_DUMP
        }

    def invoke_NinjaCopy(self, log: Log):
        """
            4658

            invoke-Ninjacopy 远程dump
        """
        if "ProcessName" not in log.event_data or not log.event_data["ProcessName"]:
            return
        if log.event_data["ProcessName"].lower() != r"c:\windows\system32\wsmprovhost.exe":
            return

        user_name = log.subject_info.full_user_name

        # 如果存在向前查找，则延迟确认
        if "_delay_info" not in log.record:
            self.delay_confirm_log()
            return
        self.es.wait_log_in_database(log.dc_computer_name, log.record_number)

        base = {
            "index": ElasticConfig.event_log_index,
            "doc_type": ElasticConfig.event_log_doc_type
        }

        # 开始向前查找
        msearch_body = [base]
        body_4656 = self._get_query(log, 4656,
                                    get_term_statement("event_data.SubjectUserName.keyword", user_name),
                                    get_match_must_all("event_data.ObjectName",
                                                       r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN"),
                                    get_term_statement("event_data.ProcessName.keyword",
                                                       r"C:\Windows\System32\wsmprovhost.exe")
                                    )
        msearch_body.append(body_4656)
        msearch_body.append(base)
        body_4688 = self._get_query(log, 4688,
                                    get_term_statement("event_data.NewProcessName.keyword",
                                                       r"C:\Windows\System32\wsmprovhost.exe")
                                    )
        msearch_body.append(body_4688)

        results = self.es.multi_search(body=msearch_body,
                                       index=ElasticConfig.event_log_index,
                                       doc_type=ElasticConfig.event_log_doc_type)

        for each in results["responses"]:
            if each.get("error"):
                logger.error(
                    "dump password module - invoke_NinjaCopy multi search error: " + each.get("error").get("reason"))
                raise MsearchException()
            elif each["hits"]["total"] == 0:
                return

        return {
            "method": REMOTELY_INVOKE_NINJACOPY_DUMP
        }

    def _get_query(self, log: Log, event_id, *args):
        ago_time = move_n_min(utc_to_datetime(log.utc_log_time), 5)
        time_str = datetime_to_utc(ago_time)
        query = {
            "query": get_must_statement(
                get_term_statement("computer_name", log.dc_computer_name),
                get_time_range("gt", time_str),
                get_term_statement("event_id", event_id),
                *args
            ),
            "sort": {
                "@timestamp": "desc"
            },
            "_source": False,
            "size": 1
        }
        return query


if __name__ == '__main__':
    pass
