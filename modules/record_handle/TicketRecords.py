#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    正常的票据太多 目前只记录异常的票据
"""
from settings.config import main_config
from models.Kerberos import Kerberos
from tools.common.common import utc_to_datetime, datetime_to_log_date, datetime_now_obj
from tools.database.ElsaticHelper import *
from tools.database.RedisHelper import RedisHelper

REDIS_TICKET_HASH_USERNAME_SUFFIX = "_ticket_hash_username"


class TicketRecords(object):
    def __init__(self):
        self.es = ElasticHelper()
        self.redis = RedisHelper()

    def save_ticket(self, ticket_doc):
        # 首先将当前票据保存到redis缓存中
        self.redis.set_str_value(ticket_doc["ticket_data"]["ticket_hash"], ticket_doc["ticket_type"],
                                 expire=60*60*main_config.TGT_maximum_lifetime)

        index = ElasticConfig.krb5_ticket_write_index_prefix + datetime_to_log_date(datetime_now_obj())
        # 保存到ES中
        self.es.delay_index(body=ticket_doc,
                            index=index,
                            doc_type=ElasticConfig.krb5_ticket_doc_type)

    def exist_ticket_by_hash(self, ticket_hash: str, ticket_type: str) -> bool:
        result = self.redis.get_str_value(ticket_hash)
        if result and result == ticket_type:
            return True
        else:
            return False

    def set_username_by_tgt_hash(self, ticket_hash: str, username: str):
        key = ticket_hash + REDIS_TICKET_HASH_USERNAME_SUFFIX
        return self.redis.set_str_value(key, username, expire=60*60*24*7)

    def get_username_by_tgt_hash(self, ticket_hash: str) -> str:
        key = ticket_hash + REDIS_TICKET_HASH_USERNAME_SUFFIX
        username = self.redis.get_str_value(key)
        if not username:
            return "unknown"
        else:
            return username

    def terms_by_custom(self, query: dict, aggs_field: str, aggs_size) -> list:
        body = {
            "query": query,
            "size": 0,
            "aggs": get_aggs_statement("abc", "terms", aggs_field, aggs_size)
        }
        rsp = self.es.search(body=body,
                             index=ElasticConfig.krb5_ticket_index,
                             doc_type=ElasticConfig.krb5_ticket_doc_type)
        if rsp:
            return rsp["aggregations"]["abc"]["buckets"]
        else:
            return []

    @staticmethod
    def sec_tools_match(options: str) -> str:
        if options == "0x40800010":
            return "kekeo, Rubeus"
        elif options == "0x50800000":
            return "impacket"
        else:
            return "unknown"


class TicketDoc(object):
    def __init__(self, krb: Kerberos):
        super().__init__()
        req = krb.req
        rep = krb.rep
        ticket = rep.ticket
        if krb.msg_type == "AS":
            self.ticket_type = "TGT"
        else:
            self.ticket_type = "ST"
        self.source_ip = krb.client.ip
        self.kdc_options = req.req_body.kdc_options
        self.domain_controller = krb.dc_host_name
        self.issue_time = krb.utc_time
        self.user_name = rep.c_name.name_string[0]
        self.TktVNO = ticket.TktVNO
        self.ticket_doc = ticket.get_doc()

    def get_es_doc(self) -> dict:
        return {
            "ticket_type": self.ticket_type,
            "user_name": self.user_name,
            "domain_controller": self.domain_controller,
            "kdc_options": self.kdc_options,
            "issue_time": self.issue_time,
            "source_ip": self.source_ip,
            "ticket_data": self.ticket_doc
        }
