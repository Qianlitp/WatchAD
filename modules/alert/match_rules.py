#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    用运营过程中设定的误报规则，来忽略告警

    用 form_data 中的字段匹配来忽略告警，需要支持模糊匹配，IP 需要支持 CIDR

    field_type: ip 、 string、 list
    match_type: term 、 regex、 ip

    规则格式：

{
    "alert_code": "003",
    "comment": "来自IT部门网段的登录错误忽略",
    "rules": [
        {
            "field_name": "source_ip",
            "field_type": "ip",
            "match_type": "ip",
            "value": "36.110.235.0/24"
        }
    ],
    "update_time": ISODate("2019-04-03T10:26:55.213+0000")
}

"""

import re

from IPy import IP

from settings.database_config import MongoConfig
from models.Rule import Rule
from tools.database.MongoHelper import MongoHelper


class MatchRules(object):
    def __init__(self, rules_table):
        self.mongo = MongoHelper(MongoConfig.uri, MongoConfig.db, rules_table)

    def match(self, event_doc: dict):
        alert_code = event_doc["alert_code"]
        form_data = event_doc["form_data"]
        all_rules = self.mongo.find_all({"alert_code": alert_code})
        for rule in all_rules:
            try:
                rule = Rule(rule)
                # 成功匹配规则 则返回被匹配上的规则ID
                if self._match_one(rule, form_data):
                    return rule.id
            except Exception as e:
                return False
        return False

    def _match_one(self, rule: Rule, form_data):
        """
            一条忽略内容的多条规则，全部匹配才算成功
        """
        for rule_content in rule.rules:
            if rule_content.field_type == "string":
                if not self._match_string(form_data[rule_content.field_name], rule_content.value,
                                          rule_content.match_type):
                    return False
            elif rule_content.field_type == "ip":
                if not self._match_ip(form_data[rule_content.field_name], rule_content.value):
                    return False
            elif rule_content.field_type == "list":
                if not self._match_list(form_data[rule_content.field_name], rule_content.value,
                                        rule_content.match_type):
                    return False
        return True

    def _match_string(self, alert_value, rule_value, match_type) -> bool:
        """
            匹配字符串，将告警字段内容和忽略规则的内容匹配
        """
        if match_type == "term":
            if isinstance(alert_value, list):
                for each in alert_value:
                    if each == rule_value:
                        return True
                return False
            else:
                return alert_value == rule_value
        # 正则匹配
        elif match_type == "regex":
            if isinstance(alert_value, list):
                for each in alert_value:
                    if re.match(rule_value, each):
                        return True
                return False
            else:
                return True if re.match(rule_value, alert_value) else False

    def _match_ip(self, alert_ip, rule_ip) -> bool:
        """
            匹配IP类型
        """
        # CIDR
        if "/" in rule_ip:
            return IP(alert_ip) in IP(rule_ip)
        else:
            return alert_ip == rule_ip

    def _match_list(self, alert_value, rule_value, match_type):
        """
            匹配列表
        """
        for each in rule_value:
            if match_type == "ip" and self._match_ip(alert_value, each):
                return True
            elif match_type == "string" or match_type == "regex":
                if self._match_string(alert_value, each, match_type):
                    return True
        return False
