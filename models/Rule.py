#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    忽略规则的对象
"""


class Rule(object):
    def __init__(self, doc):
        self.id = str(doc["_id"])
        self.alert_code = doc["alert_code"]
        self.comment = doc["comment"]
        self.update_time = doc["update_time"]

        self.rules = self._get_rules(doc["rules"])

    def _get_rules(self, rule_list):
        results = []
        for rule in rule_list:
            results.append(RuleContent(rule))
        return results


class RuleContent(object):
    def __init__(self, doc):
        self.field_name = doc["field_name"]
        self.field_type = doc["field_type"]
        self.value = doc["value"]
        self.match_type = doc["match_type"]
