#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    入侵事件

    将相同来源、不同类型的多个威胁活动合并成入侵事件

    时间跨度为7天内
"""

from bson import ObjectId
from tools.database.MongoHelper import MongoHelper
from settings.database_config import MongoConfig
from datetime import timedelta
from settings.config import main_config
from modules.detect.DetectBase import HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL


class Invasion(object):
    def __init__(self):
        self.mongo = MongoHelper(MongoConfig.uri, db=MongoConfig.db, collection=MongoConfig.invasions_collection)

    def new(self, *activities) -> ObjectId:
        """
            新建入侵事件 返回入侵事件ID
        """
        source_ip = activities[0]["form_data"]["source_ip"]
        title = "来自于{ip}的入侵事件".format(ip=source_ip)

        doc = {
            "title": title,
            "level": _get_max_level(list(map(lambda x: x["level"], activities))),
            "start_time": activities[0]["start_time"],
            "end_time": activities[-1]["end_time"],
            "source_ip": source_ip,
            "status": "pending"
        }

        return self.mongo.insert_one(doc).inserted_id

    def add_activity(self, invasion_id: ObjectId, activity_doc: dict):
        """
            向当前入侵事件添加一条新的威胁活动
        """
        query = {
            "_id": invasion_id
        }
        invasion = self.mongo.find_one(query=query)
        level = _get_max_level([invasion["level"], activity_doc["level"]])
        end_time = activity_doc["end_time"]
        if end_time > invasion["end_time"]:
            self.update(invasion_id, {
                "$set": {
                    "level": level,
                    "end_time": end_time
                }
            })
        else:
            self.update(invasion_id, {
                "$set": {
                    "level": level
                }
            })

    def find_record(self, source_ip, start_time, **kwargs):
        """
            根据 source_ip 查找一段时间内的相同来源的入侵事件
        """
        return self.mongo.find_one({
            "source_ip": source_ip,
            "end_time": {"$gte": start_time + timedelta(hours=-main_config.merge_invasion_time)},
            **kwargs
        })

    def update(self, _id, doc):
        self.mongo.update_one({
            "_id": _id
        }, doc=doc)


def _get_max_level(level_list: list) -> str:
    levels = [HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL]
    for level in levels:
        if level in level_list:
            return level
