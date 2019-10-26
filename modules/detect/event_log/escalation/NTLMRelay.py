#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    4624

    检测 NTLM 中继认证到域控的行为

    已知特点如下：
    1. 使用NTLM协议进行验证
    2. 来源主机名为被中继NTLM请求的最初请求
    3. 来源IP为中继攻击者IP
    4. NTLM v1 更容易受到攻击，NTLM v2可开启签名防止篡改和中继

    根据历史记录情况 判断IP和主机名的对应关系是否一致

    因为IP经常变动，不建议对所有的请求进行比对，暂时只对固定的敏感机器进行检测

"""

from settings.config import main_config
from models.Log import Log
from modules.detect.DetectBase import DetectBase, HIGH_LEVEL
from modules.record_handle.AccountHistory import AccountHistory
from modules.record_handle.AccountInfo import AccountInfo
from tools.common.common import ip_filter, get_netbios_domain, datetime_now_obj, get_ip_from_domain, filter_domain
from tools.database.ElsaticHelper import *


EVENT_ID = [4624]

ALERT_CODE = "405"
TITLE = "NTLM中继活动"
DESC_TEMPLATE = "怀疑来自 [source_workstation] 的NTLM认证请求被 [relay_workstation]([relay_ip]) 中继到了域控 [dc_hostname]，" \
                "从而获取目标 [target_user_name] 的身份特权。"


class NTLMRelay(DetectBase):
    def __init__(self):
        super().__init__(code=ALERT_CODE, title=TITLE, desc=DESC_TEMPLATE)
        self.account_history = AccountHistory()
        self.account_info = AccountInfo()
        self.es = ElasticHelper()

    def run(self, log: Log):
        self.init(log=log)

        # 处于数据统计时间内，不检测
        if datetime_now_obj() < main_config.learning_end_time:
            return

        if not log.source_info.ip_address:
            return

        if log.event_data["AuthenticationPackageName"] != "NTLM":
            return

        work_station = log.source_info.work_station_name
        netbios_name = get_netbios_domain(log.target_info.domain_name)
        if filter_domain(netbios_name):
            return

        # 为较小误报 目前只考虑来源主机为敏感主机的行为
        if not self.account_info.computer_is_sensitive_by_name(work_station, domain=netbios_name):
            return

        ip_address = log.source_info.ip_address
        if ip_filter(ip_address):
            return

        # 根据主机名去查最近的认证IP
        last_ip = self.account_history.search_last_ip_by_workstation(work_station)
        if not last_ip or last_ip == ip_address:
            return

        # 二次确认，如果上次认证IP与当前IP不相同，则对主机名进行解析，判断IP是否相等
        resolver_ips = self._get_host_ip(log)
        if ip_address in resolver_ips:
            return

        if "V1" in log.event_data["LmPackageName"]:
            version = "v1"
        else:
            version = "v2"

        relay_workstation = self.account_history.get_last_workstation_by_ip(ip_address)

        return self._generate_alert_doc(relay_workstation=relay_workstation,
                                        ntlm_version=version,
                                        resolver_ips=resolver_ips)

    def _generate_alert_doc(self, **kwargs) -> dict:
        form_data = {
            "source_ip": self.log.source_info.ip_address,
            "relay_ip": self.log.source_info.ip_address,
            "source_workstation": self.log.source_info.work_station_name,
            "target_user_name": self.log.target_info.user_name,
            "target_domain": self.log.target_info.domain_name,
            "target_user_sid": self.log.target_info.user_sid,
            "target_logon_id": self.log.target_info.logon_id,
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

    def _get_host_ip(self, log: Log) -> list:
        """
            对主机名进行DNS解析
        """
        dns_name = "{workstation}.{domain}".format(workstation=log.source_info.work_station_name,
                                                   domain=self.get_FQDN_domain(log.target_info.domain_name))
        try:
            ip_list = get_ip_from_domain(dns_name)
        except Exception as e:
            return []
        return ip_list

    def get_FQDN_domain(self, domain) -> str:
        for each in main_config.domain_list:
            if each.startswith(domain.lower()):
                return each
        return ""


if __name__ == '__main__':
    pass
