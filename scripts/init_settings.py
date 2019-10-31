#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    常用初始化设置功能
"""
import simplejson
from _project_dir import project_dir
from tools.LDAPSearch import LDAPSearch
from tools.database.MongoHelper import MongoHelper
from tools.database.ElsaticHelper import *
from tools.database.Consumer import Consumer
from settings.database_config import MongoConfig
from settings.elasticsearch.mapping_template import template_map
from tools.common.Logger import logger
from tools.common.common import get_dn_domain_name, get_netbios_domain, datetime_utc_now_obj, move_n_days, \
    datetime_to_common_str
from models.User import User
from modules.record_handle.Delegation import Delegation, CONSTRAINED_DELEGATION, UNCONSTRAINED_DELEGATION
from crontab import CronTab
from ldap3 import Entry
from settings.default_settings import default_settings, default_sensitive_groups
from tools.database.RedisHelper import RedisHelper


REDIS_KEY_SUFFIX = "_setting"


def init_es_template():
    """
        初始化ES的索引模板
    """
    logger.info("init the elasticsearch index template.")
    es = ElasticHelper()
    for name, temp in template_map.items():
        if es.exists_template(name=name):
            logger.info("template \"{name}\" already exists, delete it.".format(name=name))
            es.delete_template(name=name)
        logger.info("put template \"{name}\" ...".format(name=name))
        es.put_template(name=name, body=temp)
        logger.debug(es.get_template(name))


def init_ldap_settings(domain, server, user, password):
    netbios_domain = get_netbios_domain(domain)
    logger.info("init the ldap configuration.")
    if not server.startswith("ldap://"):
        server = "ldap://" + server
    mongo = MongoHelper(uri=MongoConfig.uri, db=MongoConfig.db, collection=MongoConfig.settings_collection)
    query = {
        "name": "ldap"
    }
    doc = {
        netbios_domain: {
            "server": server,
            "user": user,
            "password": password,
            "dn": get_dn_domain_name(domain)
        }
    }
    mongo.update_one(filter=query, doc={
        "$set": {
            "value": doc
        }
    }, upsert=True)
    redis = RedisHelper()
    redis.set_str_value("ldap" + REDIS_KEY_SUFFIX, simplejson.dumps(doc))


def init_default_settings(domain):
    logger.info("init other settings.")
    redis = RedisHelper()
    mongo = MongoHelper(uri=MongoConfig.uri, db=MongoConfig.db, collection=MongoConfig.settings_collection)
    for name, value in default_settings.items():
        if name == "domain_list":
            value = [domain]
        mongo.update_one(filter={
            "name": name
        }, doc={
            "$set": {
                "value": value
            }
        }, upsert=True)
        key = name + REDIS_KEY_SUFFIX
        if name in ["domain_list", "VPN_ip_part", "detail_file_share_white_list_setting"]:
            if len(value) != 0:
                redis.set_list(key, *value)
        elif name in ["raw_data_expire", "honeypot_account", "alarms_merge", "sensitive_entry", "kerberos"]:
            redis.set_str_value(key, simplejson.dumps(value))
        elif name in ["brute_force_max"]:
            redis.set_str_value(key, str(value))
        elif isinstance(value, list):
            if len(value) > 0 and isinstance(value[0], dict):
                redis.set_str_value(key, simplejson.dumps(value))
            else:
                if len(value) != 0:
                    redis.set_list(key, *value)
        elif isinstance(value, str):
            redis.set_str_value(key, value)
        elif isinstance(value, dict):
            redis.set_str_value(key, simplejson.dumps(value))
        elif isinstance(value, int):
            redis.set_str_value(key, str(value))


def set_learning_end_time_setting():
    value = move_n_days(datetime_utc_now_obj(), 10)
    logger.info("set learning end time: " + str(value))
    name = "learning_end_time"
    redis = RedisHelper()
    mongo = MongoHelper(uri=MongoConfig.uri, db=MongoConfig.db, collection=MongoConfig.settings_collection)
    mongo.update_one(filter={
        "name": name
    }, doc={
        "$set": {
            "value": value
        }
    }, upsert=True)
    key = name + REDIS_KEY_SUFFIX
    redis.set_str_value(key, datetime_to_common_str(value))


def init_sensitive_groups(domain):
    logger.info("init sensitive groups.")
    domain = get_netbios_domain(domain)
    ldap_search = LDAPSearch(domain)
    redis = RedisHelper()
    mongo = MongoHelper(uri=MongoConfig.uri, db=MongoConfig.db, collection=MongoConfig.settings_collection)
    sensitive_groups = []
    for item in default_sensitive_groups(domain):
        if len(item["sid"]) > 0:
            sensitive_groups.append(item)
        else:
            entry = ldap_search.search_by_name(item["name"], attributes=["objectSid"])
            if not entry or len(entry.entry_attributes_as_dict["objectSid"]) == 0:
                continue
            sid = entry.entry_attributes_as_dict["objectSid"][0]
            item["sid"] = sid
            sensitive_groups.append(item)
    logger.info(",".join(list(map(lambda x: x["name"], sensitive_groups))))
    sensitive_entry = mongo.find_one({"name": "sensitive_entry"})["value"]
    sensitive_entry["group"] = sensitive_groups
    mongo.update_one({"name": "sensitive_entry"}, {
        "$set": {
            "value": sensitive_entry
        }
    }, upsert=True)
    redis.set_str_value("sensitive_entry" + REDIS_KEY_SUFFIX, simplejson.dumps(sensitive_entry))


def check_es_template() -> bool:
    """
        检查ES模板安装状态
    """
    logger.info("Check the elasticsearch index template.")
    es = ElasticHelper()
    for name, temp in template_map.items():
        if es.exists_template(name=name):
            logger.info("template \"{name}\" --->  exist.".format(name=name))
        else:
            logger.info("template \"{name}\" --->  not exist.".format(name=name))
            logger.error("Check the elasticsearch template fail.")
            return False
    logger.info("Check the elasticsearch template successfully, OK.")
    return True


def check_mongo_connection() -> bool:
    mongo = MongoHelper(MongoConfig.uri)
    if not mongo.check_connection():
        logger.error("Can't connect to the MongoDB, please reconfirm the settings.")
        return False
    logger.info("Connect to the MongoDB successfully, OK.")
    return True


def check_mq_connection() -> bool:
    c = Consumer()
    if not c.check_connection():
        logger.error("Can't connect to the MQ, please reconfirm the settings.")
        return False
    logger.info("Connect to the MQ successfully, OK.")
    return True


def get_all_dc_names(domain: str):
    """
        将DC列表入库
    """
    domain = get_netbios_domain(domain)
    logger.info("Search all domain controllers using LDAP.")
    dc_name_list = []
    ldap_search = LDAPSearch(domain)
    dc_list = ldap_search.search_domain_controller()
    for each in dc_list:
        dc_name = str(each["cn"])
        dc_name_list.append(dc_name)
    mongo = MongoHelper(MongoConfig.uri, MongoConfig.db, MongoConfig.settings_collection)
    doc = {
        domain: dc_name_list
    }
    logger.info(",".join(dc_name_list))
    logger.info("domain controller count: {count}".format(count=len(dc_name_list)))
    logger.info("Save all domain controllers to settings.")
    mongo.update_one({
        "name": "dc_name_list"
    }, {
       "$set": {
           "value": doc
       }
    }, True)
    redis = RedisHelper()
    redis.set_str_value("dc_name_list" + REDIS_KEY_SUFFIX, simplejson.dumps(doc))


def get_all_constrained_delegation_users(domain: str):
    """
        获取所有拥有 约束委派 权限的用户
    """
    d = Delegation()
    ldap_search = LDAPSearch(domain=domain)
    entries = ldap_search.search_constrained_accounts()
    if entries:
        for each in entries:
            assert isinstance(each, Entry)

            user = User({
                "user_name": each.entry_attributes_as_dict["sAMAccountName"][0],
                "user_sid": each.entry_attributes_as_dict["objectSid"][0],
                "domain_name": domain
            })
            d.new_delegation_record(user=user,
                                    delegation_type=CONSTRAINED_DELEGATION,
                                    allowed_to=each.entry_attributes_as_dict["msDS-AllowedToDelegateTo"])


def get_all_unconstrained_delegation_users(domain: str):
    """
        获取所有 无约束委派 权限的用户
    """
    d = Delegation()
    ldap_search = LDAPSearch(domain)
    entries = ldap_search.search_unconstrained_accounts()
    if entries:
        for each in entries:
            assert isinstance(each, Entry)

            user = User({
                "user_name": each.entry_attributes_as_dict["sAMAccountName"][0],
                "user_sid": each.entry_attributes_as_dict["objectSid"][0],
                "domain_name": domain
            })
            d.new_delegation_record(user=user,
                                    delegation_type=UNCONSTRAINED_DELEGATION)


def load_settings():
    """
        加载Mongo中保存的配置信息到redis中
    """
    mongo = MongoHelper(MongoConfig.uri, MongoConfig.db, MongoConfig.settings_collection)
    redis = RedisHelper()
    fetcher = mongo.find_all({})
    for each in fetcher:
        key = each["name"] + "_setting"
        # 再录入
        if isinstance(each["value"], list):
            if len(each["value"]) == 0:
                continue
            elif isinstance(each["value"][0], dict):
                redis.set_str_value(key, simplejson.dumps(each["value"]))
                continue
            redis.set_list(key, *each["value"])
        elif isinstance(each["value"], dict):
            redis.set_str_value(key, simplejson.dumps(each["value"]))
        else:
            redis.set_str_value(key, each["value"])


def set_crontab_tasks():
    """
        设置定时任务：

        1. 定期删除过期的ES索引
        2. 定时扫描万能钥匙
    """
    logger.info("set crontab tasks.")
    my_user_cron = CronTab(user=True)

    # 定时扫描万能钥匙 每2分钟一次
    skeleton_job = my_user_cron.new(
        command='/usr/bin/python3 {project_dir}/scripts/skeleton_key_scan.py >/dev/null 2>&1'
        .format(project_dir=project_dir))
    skeleton_job.minute.every(2)
    skeleton_job.set_comment("skeleton_job")
    logger.info("set skeleton_key_scan every 2 min.")
    # my_user_cron.remove(skeleton_job)

    # 定时删除过期索引 每天删除
    delete_index_job = my_user_cron.new(
        command='/usr/bin/python3 {project_dir}/scripts/delete_index.py >/dev/null 2>&1'
        .format(project_dir=project_dir))
    delete_index_job.day.every(1)
    delete_index_job.hour.on(0)
    delete_index_job.minute.on(0)
    delete_index_job.set_comment("delete_index_job")
    logger.info("set delete_index_job every day.")
    # my_user_cron.remove(delete_index_job)

    my_user_cron.write()


if __name__ == '__main__':
    pass
    # init_es_template()

    # init_sensitive_groups("CORP")

    # get_all_dc_names()
    # get_all_unconstrained_delegation_users()
    # get_all_constrained_delegation_users()
    # set_crontab_tasks()
