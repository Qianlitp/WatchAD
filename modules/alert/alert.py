#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    告警处理

    发送邮件，入库，合并重复告警
"""

from settings.database_config import MongoConfig
from modules.alert.match_rules import MatchRules
from tools.common.common import md5
from tools.database.MongoHelper import MongoHelper
from modules.alert.activity import Activity


class Alert(object):
    def __init__(self):
        self.alert_mongo = MongoHelper(MongoConfig.uri, MongoConfig.db, MongoConfig.alerts_collection)
        self.activity = Activity()
        self.ignore_rule = MatchRules(MongoConfig.ignore_collection)
        self.exclude_rule = MatchRules(MongoConfig.exclude_collection)

    def generate(self, doc):
        """
            生成告警，发送邮件并入库
        """
        # 计算告警表单内容的唯一ID
        form_data_id = _get_form_data_md5(doc["form_data"])
        doc["form_data_id"] = form_data_id

        # 误报排除规则过滤，不再产生记录
        if self._auto_exclude(doc):
            return

        # 忽略规则过滤
        doc = self._auto_ignore(doc)

        # 首先尝试合并相同来源且相同类型的告警到同一个威胁活动， 即unique_id重复的告警
        if self._merge_alert(doc):
            return

        # 新增，生成威胁活动
        activity_id = self.activity.new(doc)
        # 记录下威胁活动的ID以后，告警入库
        doc["activity_id"] = activity_id
        self.alert_mongo.insert_one(doc)

    def _merge_alert(self, alert_doc):
        """
            合并告警到同一个威胁活动
        """

        # 查找是否已经生成了威胁活动，没有的话直接退出，然后新增
        activity = self.activity.find_record(alert_doc["unique_id"], alert_doc["start_time"])
        if not activity:
            return False

        alert_doc["activity_id"] = activity["_id"]

        # 尝试合并告警表单内容完全重复的告警，增加重复次数
        if self._merge_repeat_count(alert_doc):
            self.activity.update(activity["_id"], {
                "$set": {
                    "end_time": alert_doc["end_time"]
                }
            })
        # 无完全重复，在该威胁活动下新增一条告警
        else:
            self.activity.add_alert(activity, alert_doc)
            self.alert_mongo.insert_one(alert_doc)
        return True

    def _merge_repeat_count(self, alert_doc: dict) -> bool:
        """
            完全重复的告警内容 不再入库 直接统计次数
        """
        query = {
            "activity_id": alert_doc["activity_id"],
            "form_data_id": alert_doc["form_data_id"]
        }
        record = self.alert_mongo.find_one(query)
        if record:
            # 账号爆破特殊处理一下
            if alert_doc["alert_code"] == "301":
                self.alert_mongo.update_one(
                    {"_id": record["_id"]},
                    {
                        "$set": {
                            "form_data.brute_force_target_users": alert_doc["form_data"]["brute_force_target_users"]
                        }
                    }
                )
                return True
            self.alert_mongo.update_one(
                {"_id": record["_id"]},
                {
                    "$inc": {"repeat_count": 1},
                    "$set": {"end_time": alert_doc["end_time"]}
                }
            )
            return True
        else:
            return False

    def _auto_exclude(self, doc):
        """
            根据预先设定的规则，自动排除误报

            和忽略的区别是，排除的误报不再产生记录，直接忽略
        """
        rule_id = self.exclude_rule.match(doc)
        if rule_id:
            return True
        else:
            return False

    def _auto_ignore(self, doc):
        """
            根据预先设定的规则，自动忽略告警
            忽略的告警也需要合并
        """
        rule_id = self.ignore_rule.match(doc)
        if rule_id:
            doc["status"] = "auto_ignore"
            doc["ignore_rule_id"] = rule_id
        return doc


def _get_form_data_md5(data: dict) -> str:
    m_str = ""
    for each in sorted(data.keys()):
        # logon_id 一定不相同 忽略
        if "logon_id" in each or each == "brute_force_target_users":
            continue
        m_str += each
        m_str += str(data[each])
    return md5(m_str)
