#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

from pymongo import ASCENDING
from bson import ObjectId
from tools.database.MongoHelper import MongoHelper
from settings.database_config import MongoConfig
from modules.alert.invasion import Invasion
from datetime import timedelta
from settings.config import main_config


class Activity(object):
    def __init__(self):
        self.activity_mongo = MongoHelper(MongoConfig.uri, MongoConfig.db, MongoConfig.activities_collection)
        self.invasion = Invasion()

    def new(self, activity_doc: dict) -> ObjectId:
        """
            新增威胁活动记录

            同时尝试生成入侵事件记录
        """
        invasion_id = self._generate_invasion(activity_doc)
        if invasion_id:
            activity_doc["invasion_id"] = invasion_id
        return self.activity_mongo.insert_one(activity_doc).inserted_id

    def add_alert(self, activity_doc, alert_doc: dict):
        doc = {
            "$set": {}
        }
        if alert_doc["end_time"] > activity_doc["end_time"]:
            doc["$set"]["end_time"] = alert_doc["end_time"]
        if alert_doc["level"] > activity_doc["level"]:
            doc["$set"]["level"] = alert_doc["level"]
        if len(doc["$set"].keys()) == 0:
            return
        self.activity_mongo.update_one({
            "_id": activity_doc["_id"]
        }, doc)

    def update(self, _id, doc):
        self.activity_mongo.update_one({
            "_id": _id
        }, doc=doc)

    def find_record(self, uid, start_time):
        """
            根据 unique_id 查找一段时间内相同的威胁活动
        """
        return self.activity_mongo.find_one({
            "unique_id": uid,
            "end_time": {"$gte": start_time + timedelta(hours=-main_config.merge_activity_time)}
        })

    def _generate_invasion(self, activity_doc) -> ObjectId:
        """
            生成入侵事件
            多个相同来源IP 不同类型的威胁活动 可以生成一个入侵事件

            返回入侵事件的ID
        """
        # 首先查找是否已存在对应的入侵事件，尝试合并
        invasion_id = self._merge_activity(activity_doc)
        if invasion_id:
            assert isinstance(invasion_id, ObjectId)
            return invasion_id

        # 没有已存在的入侵事件，则按照条件，查找是否已存在不同类型的威胁活动
        query = {
            "form_data.source_ip": activity_doc["form_data"]["source_ip"],
            "end_time": {"$gte": activity_doc["start_time"] + timedelta(hours=-main_config.merge_invasion_time)},
            "alert_code": {"$ne": activity_doc["alert_code"]}
        }

        # 如果存在不同类型的威胁活动
        another_activities = list(self.activity_mongo.find_all(query).sort("start_time", ASCENDING))
        if len(another_activities) > 0:
            invasion_id = self.invasion.new(*another_activities, activity_doc)
            # 创建完入侵事件之后，将之前查询的到威胁活动全部加上对应的ID
            for activity in another_activities:
                self.update(activity["_id"], {
                    "$set": {
                        "invasion_id": invasion_id
                    }
                })

    def _merge_activity(self, activity_doc):
        source_ip = activity_doc["form_data"]["source_ip"]
        invasion = self.invasion.find_record(source_ip, activity_doc["start_time"])
        if not invasion:
            return False

        # 向存在的入侵事件添加当前威胁活动
        self.invasion.add_activity(invasion["_id"], activity_doc)
        return invasion["_id"]
