#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    5145 RelativeTargetName ，去除以域名开头的值，包括大写和小写

    基于445端口的命令执行工具，会留下一些特殊的文件共享名。
"""

from settings.config import main_config
from models.Log import Log
from modules.detect.DetectBase import DetectBase, MEDIUM_LEVEL
from tools.common.common import ip_filter
from tools.database.ElsaticHelper import *
from tools.database.RedisHelper import RedisHelper

EVENT_ID = [5145]

ALERT_CODE = "304"
TITLE = "未知文件共享名"
DESC_TEMPLATE = "来自于 [source_ip]([source_workstation]) 使用身份 [source_user_name] 访问了域控 [dc_hostname] " \
                "上的未知文件共享 [relative_target_name]。"


class UnknownFileShare(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.redis = RedisHelper()
        self.es = ElasticHelper()

    def run(self, log: Log):
        self.init(log=log)

        # 处于数据统计时间内，不检测
        if datetime_now_obj() < main_config.learning_end_time:
            return

        ip = log.source_info.ip_address
        if ip_filter(ip):
            return

        # 本地系统
        if len(log.subject_info.user_sid.split("-")) == 4:
            return

        # 检查 relative_target_name
        relative_target_name = log.event_data["RelativeTargetName"]
        if not relative_target_name:
            return

        # 白名单
        if relative_target_name in main_config.detail_file_share_white_list:
            return

        # 排除域内共享文件
        for domain in main_config.domain_list:
            if relative_target_name.lower().startswith(domain.lower()):
                return

        # 已知共享名
        if relative_target_name in ["protected_storage", "lsarpc", "samr", "ntsvcs", "NETLOGON"]:
            return

        # 和历史数据判断， 属于正常的文件共享，则忽略
        if self._check_detail_file_share_normal(log):
            return

        return self._generate_alert_doc(relative_target_name=relative_target_name)

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_ip": self.log.source_info.ip_address,
            "source_workstation": self._get_workstation_by_source_ip(self.log.source_info.ip_address),
            "source_user_name": self.log.subject_info.user_name,
            "source_logon_id": self.log.subject_info.logon_id,
            "source_user_sid": self.log.subject_info.user_sid,
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
        return MEDIUM_LEVEL

    def _check_detail_file_share_normal(self, log: Log) -> bool:
        """
            判断详细文件共享记录是否正常
            用redis做缓存，将正常的名字缓存起来，加速判断
        """
        REDIS_KEY_WHITE_FILE_SHARE_SUFFIX = "_white_file_share"
        key = log.event_data["RelativeTargetName"] + REDIS_KEY_WHITE_FILE_SHARE_SUFFIX

        redis_record = self.redis.get_str_value(key)
        if redis_record == "white":
            return True
        else:
            if self._aggs_detail_file_share_count(log) > 10:
                self.redis.set_str_value(key, "white")
                return True
            else:
                return False

    def _aggs_detail_file_share_count(self, log: Log) -> int:
        """
            检查历史日志中，对于该名称的文件共享，多少用户使用过，如果超过10个，则可以忽略，认为是正常服务
        """
        id_term = get_term_statement("event_id", 5145)
        name_term = get_term_statement("event_data.RelativeTargetName.keyword", log.event_data["RelativeTargetName"])

        query = {
            "query": get_must_statement(id_term, name_term),
            "size": 0,
            "aggs": get_aggs_statement(name="user_count",
                                       aggs_type="terms",
                                       field="event_data.SubjectUserName.keyword",
                                       size=20)
        }
        rsp = self.es.search(body=query,
                             index=ElasticConfig.event_log_index,
                             doc_type=ElasticConfig.event_log_doc_type)
        return len(rsp["aggregations"]["user_count"]["buckets"])
