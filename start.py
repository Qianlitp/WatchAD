#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    start

    -> 动态加载模块，根据 **事件ID** 与 **Krb协议流程** 注册对应的处理逻辑，构建一个映射

    -> 启动消费者

    -> 注册回调
"""

import sys
import time
from models.Log import Log
# from models.Kerberos import Kerberos
from tools.common.common import get_walk_files, format_module_path, datetime_now_obj
from tools.common.Logger import logger
from tools.database.Consumer import Consumer
from tools.database.MongoHelper import MongoHelper
from settings.database_config import MongoConfig
from modules.alert.alert import Alert
from _project_dir import project_dir


class Engine(object):
    def __init__(self):
        self.event_log_modules_map = None
        # self.traffic_kerberos_modules_map = None
        self.mongo = MongoHelper(MongoConfig.uri, MongoConfig.db, MongoConfig.delay_run_collection)
        self.alert = Alert()

    def load(self):
        # 加载事件日志检测模块
        logger.info("loading detect modules based on event_log")
        self.event_log_modules_map = self._load_module("event_log", "EVENT_ID")

        # 加载kerberos流量检测模块
        # logger.info("loading detect modules based on traffic_kerberos")
        # self.traffic_kerberos_modules_map = self._load_module("traffic_kerberos", "MSG_TYPE")

    def start(self):
        """
            引擎启动主入口
        """
        self.load()

        # 启动消费者
        c = Consumer()
        # 注册回调
        logger.info("start MQ consumer and register callback func.")
        logger.info("status: main process running")
        c.run(self.do_analyze)

    def delay_run(self):
        """
            延迟检测

            ** 请单进程运行！ **
        """
        self.load()
        logger.info("status: delay process running")
        while True:
            time.sleep(5)
            data_list = self._get_delay_data()
            for data in data_list:
                alert_code = data["_delay_info"]["alert_code"]
                # if data["type"] == "krb5":
                #     krb = Kerberos(data)
                #     self._run_analyze(data=krb, data_type=krb.msg_type, modules_map=self.traffic_kerberos_modules_map,
                #                       alert_code=alert_code)
                if data["type"] == "wineventlog":
                    log = Log(data)
                    self._run_analyze(data=log, data_type=log.event_id, modules_map=self.event_log_modules_map,
                                      alert_code=alert_code)
            # 删除完成检测数据
            self._clear_confirmed_data(data_list)

    def do_analyze(self, data: dict):
        # 解析krb5流量
        # if data["type"] == "krb5":
        #     krb = Kerberos(data)
        #     if krb.msg_type not in self.traffic_kerberos_modules_map:
        #         return
        #     self._run_analyze(data=krb, data_type=krb.msg_type, modules_map=self.traffic_kerberos_modules_map)
        # 解析事件日志
        if data["type"] == "wineventlog":
            if data["event_id"] == 4662:
                return
            if "event_data" not in data and data["event_id"] != 1100:
                return
            log = Log(data)
            if log.event_id not in self.event_log_modules_map:
                return
            self._run_analyze(data=log, data_type=log.event_id, modules_map=self.event_log_modules_map)

    def _run_analyze(self, data, data_type, modules_map: dict, alert_code=None):
        """
            运行检测模块
        :param data: 数据字典
        :param data_type: log.event_id 的值或者 krb.msg_type
        :param modules_map: 加载了检测模块的字典
        :param alert_code:  可选，具体检测的告警代码，指定了之后只运行该模块
        :return:
        """
        module_list = modules_map[data_type]
        for module in module_list:
            code = module["code"]
            if alert_code and alert_code != code:
                continue
            m_object = module["object"]
            # 运行检测模块的语句
            alert_doc = m_object.run(data)
            if alert_doc:
                # 存在问题，告警
                self.alert.generate(alert_doc)

    def _load_module(self, name: str, data_type: str) -> dict:
        modules_map = {}

        def _register_module(d_type, m):
            if d_type not in modules_map:
                modules_map[d_type] = [m]
            else:
                modules_map[d_type].append(m)

        file_list = get_walk_files(project_dir + "/modules/detect/" + name)

        for f in file_list:
            f = f.replace(project_dir, ".")
            module_path, f = format_module_path(f)
            module = __import__(module_path, fromlist=[f])
            logger.info("loaded module: " + module_path)
            data_types = getattr(module, data_type)
            assert isinstance(data_types, list)
            for d_type in data_types:
                _register_module(d_type, {
                    "code": getattr(module, "ALERT_CODE") if hasattr(module, "ALERT_CODE") else None,
                    "object": getattr(module, f)()
                })
        return modules_map

    def _get_delay_data(self):
        query = {
            "_delay_info.time": {
                "$lte": datetime_now_obj()
            }
        }
        return [each for each in self.mongo.find_all(query)]

    def _clear_confirmed_data(self, data_list):
        id_list = []
        for data in data_list:
            id_list.append(data["_id"])
        query = {
            "_id": {
                "$in": id_list
            }
        }
        self.mongo.delete_many(query)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "delay":
        Engine().delay_run()
    else:
        Engine().start()
