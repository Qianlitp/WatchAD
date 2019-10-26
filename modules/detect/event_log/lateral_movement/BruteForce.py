#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4625 4771

    暴力破解账户密码:
      1. 横向，去认证多个用户
      2. 纵向，对一个用户尝试多次

"""

from modules.detect.DetectBase import DetectBase, LOW_LEVEL
from settings.config import main_config
from models.Log import Log
from modules.record_handle.AccountHistory import AccountHistory
from tools.common.common import move_n_min, utc_to_datetime, datetime_to_utc, ip_filter
from tools.database.ElsaticHelper import *

EVENT_ID = [4625, 4771]

ALERT_CODE = "301"
TITLE = "Brute force attack"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 多次认证目标身份失败，疑似暴力破解攻击。"


class BruteForce(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.es = ElasticHelper()
        self.account_history = AccountHistory()

    def run(self, log: Log):
        self.init(log=log)

        if log.subject_info.domain_name:
            domain = log.subject_info.domain_name
        else:
            domain = ".".join(log.dc_computer_name.split(".")[1:])
        if domain == "-":
            return

        brute_force_type = None

        if log.event_id == 4625 \
                and log.event_data["AuthenticationPackageName"] == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0":
            return

        user_name = log.target_info.user_name
        # 机器账户 密码强度较高 几乎不可能爆破 忽略检测
        if not user_name or user_name.endswith("$"):
            return

        if "PreAuthType" in log.event_data and log.event_data["PreAuthType"] == "0":
            return

        ip = log.source_info.ip_address
        if ip_filter(ip):
            return

        self.es.wait_log_in_database(log.dc_computer_name, log.record_number)
        target_users = []
        user_list = self._get_login_fail_count(ip_address=ip, utc_time=log.utc_log_time)
        # 横向爆破超过100个账户
        if len(user_list) > 100:
            brute_force_type = "horizontal"

        for each in user_list:
            target_users.append({
                "name": each["key"],
                "count": each["doc_count"]
            })
            if each["doc_count"] > main_config.brute_force_max:
                brute_force_type = "vertical"

        if not brute_force_type:
            return

        return self._generate_alert_doc(brute_force_type=brute_force_type,
                                        brute_force_target_users=target_users)

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_ip": self.log.source_info.ip_address,
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
            **kwargs
        }
        doc = self._get_base_doc(
            level=self._get_level(),
            unique_id=self._get_unique_id(self.code, self.log.source_info.ip_address, kwargs["brute_force_type"]),
            form_data=form_data
        )
        return doc

    def _get_level(self):
        return LOW_LEVEL

    def _get_login_fail_count(self, ip_address: str, utc_time: str) -> list:
        """
            获取发起自某个IP的一段时间内的登录失败次数

            :return 日志ID列表，用户名列表
        """
        # 事件ID
        id_term = get_should_statement(get_term_statement("event_id", 4625),
                                       get_term_statement("event_id", 4771))
        # user
        ip_term = get_should_statement(
            get_term_statement("event_data.IpAddress.keyword", ip_address),
            get_term_statement("event_data.IpAddress.keyword", "::ffff:" + ip_address)
        )
        # 限定筛选时间范围 60分钟内
        ago_time = move_n_min(utc_to_datetime(utc_time), 60)
        ago_time_str = datetime_to_utc(ago_time)
        gt_time_range = get_time_range("gt", ago_time_str)
        lt_time_range = get_time_range("lt", utc_time)
        statement = {
            "query": get_must_statement(id_term, ip_term, gt_time_range, lt_time_range),
            "size": 0,
            "sort": get_sort_statement("@timestamp", "asc"),
            "aggs": get_aggs_statement("user_list", "terms", "event_data.TargetUserName.keyword", size=101)
        }

        rsp = self.es.search(body=statement,
                             index=ElasticConfig.event_log_index,
                             doc_type=ElasticConfig.event_log_doc_type)
        user_list = rsp["aggregations"]["user_list"]["buckets"]
        return user_list
