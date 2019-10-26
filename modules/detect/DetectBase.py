#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

import copy
from abc import abstractmethod

from settings.config import main_config
from settings.database_config import MongoConfig
from models.Kerberos import Kerberos
from models.Log import Log
from tools.common.common import datetime_now_obj, move_n_sec, md5, utc_to_datetime
from tools.database.MongoHelper import MongoHelper
from tools.database.ElsaticHelper import *
from tools.common.errors import NoDataInitEvent
from modules.record_handle.AccountHistory import AccountHistory

HIGH_LEVEL = "high"
MEDIUM_LEVEL = "medium"
LOW_LEVEL = "low"


class DetectBase(object):
    def __init__(self, code: str, title: str, desc: str):
        self.code = code
        self.title = title
        self.desc = desc
        self.log = None
        self.krb = None
        self.domain = None
        self.mongo = MongoHelper(MongoConfig.uri, MongoConfig.db, MongoConfig.delay_run_collection)

    def init(self, log=None, krb=None):
        if log is None and krb is None:
            raise NoDataInitEvent()
        if log and krb:
            raise NoDataInitEvent()
        if log:
            assert isinstance(log, Log)
            self.domain = ".".join(log.dc_computer_name.split(".")[1:])
        else:
            assert isinstance(krb, Kerberos)
            self.domain = krb.req.req_body.realm
        self.log = log
        self.krb = krb
        self._format_domain()

    def delay_confirm_krb(self, secs=10):
        doc = copy.deepcopy(self.krb.record)
        doc["_delay_info"] = {
            "time": move_n_sec(datetime_now_obj(), -secs),
            "data_type": "traffic_kerberos",
            "alert_code": self.code
        }
        self.mongo.insert_one(doc)

    def delay_confirm_log(self, secs=60):
        doc = copy.deepcopy(self.log.record)
        doc["_delay_info"] = {
            "time": move_n_sec(datetime_now_obj(), -secs),
            "data_type": "event_log",
            "alert_code": self.code
        }
        self.mongo.insert_one(doc)

    def _format_domain(self):
        if not self.domain:
            self.domain = ""
            self.netbios_name = ""
            self.fqdn_name = ""
        elif "." in self.domain:
            self.fqdn_name = self.domain
            self.netbios_name = _get_netbios_name(self.domain)
        elif self.domain and self.domain != "-":
            self.netbios_name = self.domain.upper()
            self.fqdn_name = _get_fqdn_name(self.domain)
        else:
            self.netbios_name = ""
            self.fqdn_name = ""

    def _get_unique_id(self, *args) -> str:
        _str = ""
        for each in args:
            _str += each
        return md5(_str)

    def _get_log_doc(self):
        if self.log is None:
            return {}
        return self.log.record

    def _get_krb_doc(self):
        if self.krb is None:
            return {}
        return self.krb.record

    def _get_dc_computer_name(self):
        if self.log:
            return self.log.dc_computer_name
        else:
            return self.krb.dc_host_name

    def _get_dc_hostname(self):
        if self.log:
            return self.log.dc_host_name
        else:
            return self.krb.dc_host_name

    def _get_detect_by(self):
        if self.log:
            return "event_log"
        else:
            return "krb_traffic"

    def _get_time(self):
        if self.log:
            return utc_to_datetime(self.log.utc_log_time)
        else:
            return utc_to_datetime(self.krb.utc_time)

    def _get_base_doc(self, **kwargs):
        return {
            "alert_code": self.code,
            "title": self.title,
            "description": self.desc,
            "classify": self._get_classify(),
            "dc_computer_name": self._get_dc_computer_name(),
            "dc_hostname": self._get_dc_hostname(),
            "domain": self.netbios_name,
            "status": "pending",
            "start_time": self._get_time(),
            "end_time": self._get_time(),
            "raw_log": self._get_log_doc(),
            "raw_krb": self._get_krb_doc(),
            "detect_by": self._get_detect_by(),
            "repeat_count": 1,
            **kwargs
        }

    def _get_classify(self):
        if self.code.startswith("1"):
            return "信息探测"
        elif self.code.startswith("2"):
            return "凭证盗取"
        elif self.code.startswith("3"):
            return "横向移动"
        elif self.code.startswith("4"):
            return "权限提升"
        elif self.code.startswith("5"):
            return "权限维持"
        elif self.code.startswith("6"):
            return "防御绕过"
        else:
            return "未知分类"

    def _get_workstation_by_source_ip(self, source_ip) -> str:
        """
            查找最近该IP认证主机名

            返回主机名和域名
        """
        account_history = AccountHistory()
        return account_history.get_last_workstation_by_ip(source_ip)

    def _get_source_ip_by_workstation(self, source_ip) -> str:
        """
        """
        account_history = AccountHistory()
        return account_history.get_last_ip_by_workstation(source_ip)

    def _get_source_ip_by_logon_id(self, logon_id: str, user_name: str) -> str:
        id_term = get_term_statement("event_id", 4624)
        logon_id_term = get_term_statement("event_data.TargetLogonId.keyword", logon_id)
        user_term = get_term_statement("event_data.TargetUserName.keyword", user_name)

        query = {
            "query": get_must_statement(id_term, logon_id_term, user_term),
            "_source": ["event_data.IpAddress"],
            "size": 1
        }
        es = ElasticHelper()

        rsp = es.search(body=query, index=ElasticConfig.event_log_index, doc_type=ElasticConfig.event_log_doc_type)
        if rsp and len(rsp["hits"]["hits"]) > 0:
            return rsp["hits"]["hits"][0]["_source"]["event_data"]["IpAddress"]
        else:
            return "unknown"

    @abstractmethod
    def _generate_alert_doc(self, **kwargs) -> dict:
        pass

    @abstractmethod
    def _get_level(self) -> str:
        pass


def _get_netbios_name(fqdn):
    prefix = fqdn.split(".")[0]
    return prefix.upper()


def _get_fqdn_name(netbios):
    prefix = netbios.lower()
    for each in main_config.domain_list:
        if each.startswith(prefix):
            return each
    return None
