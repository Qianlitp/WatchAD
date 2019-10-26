#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    从mongo数据库中查询用户的历史登录情况
"""

from tools.database.ElsaticHelper import *
from tools.database.RedisHelper import RedisHelper

REDIS_KEY_LAST_WORKSTATION_IP_SUFFIX = "_ip_to_workstation"
REDIS_KEY_LAST_IP_WORKSTATION_SUFFIX = "_workstation_to_ip"


class AccountHistory(object):
    def __init__(self):
        self.es = ElasticHelper()
        self.redis = RedisHelper()

    def set_workstation_by_ip(self, ip: str, workstation: str):
        key = ip + REDIS_KEY_LAST_WORKSTATION_IP_SUFFIX
        self.redis.set_str_value(key, workstation, expire=60*60*24)

    def set_ip_by_workstation(self, ip: str, workstation: str):
        key = workstation + REDIS_KEY_LAST_IP_WORKSTATION_SUFFIX
        self.redis.set_str_value(key, ip, expire=60*60*24)

    def get_last_workstation_by_ip(self, ip: str) -> str:
        key = ip + REDIS_KEY_LAST_WORKSTATION_IP_SUFFIX
        workstation = self.redis.get_str_value(key)
        if workstation:
            return workstation
        else:
            return self.search_last_workstation_by_ip(ip)

    def get_last_ip_by_workstation(self, workstation: str) -> str:
        key = workstation + REDIS_KEY_LAST_IP_WORKSTATION_SUFFIX
        ip = self.redis.get_str_value(key)
        if ip:
            return ip
        else:
            return self.search_last_ip_by_workstation(workstation)

    def search_last_workstation_by_ip(self, ip: str) -> str:
        query = {
            "query": get_must_statement(
                get_term_statement("event_id", 4768),
                get_wildcard_statement("event_data.TargetUserName.keyword", "*$"),
                get_term_statement("event_data.IpAddress.keyword", "::ffff:" + ip),
                get_term_statement("event_data.Status.keyword", "0x0"),
            ),
            "_source": ["event_data.TargetUserName", "event_data.TargetDomainName"],
            "size": 1,
            "sort": {
                "@timestamp": "desc"
            }
        }
        rsp = self.es.search(body=query, index=ElasticConfig.event_log_index, doc_type=ElasticConfig.event_log_doc_type)
        if rsp and rsp["hits"]["total"] > 0:
            data = rsp["hits"]["hits"][0]["_source"]
            workstation = data["event_data"]["TargetUserName"]
            return workstation[:-1]
        else:
            return "unknown"

    def search_last_ip_by_workstation(self, workstation: str) -> str:
        query = {
            "query": get_must_statement(
                get_term_statement("event_id", 4768),
                get_wildcard_statement("event_data.TargetUserName.keyword", workstation + "$"),
                get_term_statement("event_data.Status.keyword", "0x0")
            ),
            "_source": ["event_data.IpAddress"],
            "size": 1,
            "sort": {
                "@timestamp": "desc"
            }
        }
        rsp = self.es.search(body=query, index=ElasticConfig.event_log_index, doc_type=ElasticConfig.event_log_doc_type)
        if rsp and rsp["hits"]["total"] > 0:
            data = rsp["hits"]["hits"][0]["_source"]
            ip = data["event_data"]["IpAddress"]
            return ip.replace("::ffff:", "")
        else:
            return "unknown"
