#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp


class ElasticConfig(object):
    """
        保存了事件日志、解析后的流量信息、用户活动记录、票据记录等
    """
    # 修改ES配置信息
    host = "127.0.0.1:9200"
    uri = "http://{host}/".format(host=host)

    # -----------下方名称默认即可-------------
    event_log_index = "dc_log_all"
    event_log_write_index_prefix = "dc_log_"
    event_log_doc_type = "security_log"
    traffic_index = "dc_traffic_all"
    traffic_write_index_prefix = "dc_traffic_"
    traffic_krb_doc_type = "kerberos"
    user_activity_index = "user_activity_all"
    user_activity_write_index_prefix = "user_activity_"
    user_activity_doc_type = "user_activity"
    krb5_ticket_index = "krb5_ticket_all"
    krb5_ticket_write_index_prefix = "krb5_ticket_"
    krb5_ticket_doc_type = "ticket"
    # --------------------------------------


class MongoConfig(object):
    """
        保存了产生的告警、配置信息、忽略规则等
    """
    # 修改配置信息
    host = "127.0.0.1:27017"
    user = "WatchAD"
    password = "WatchAD-by-0KEE"
    uri = "mongodb://{user}:{password}@{host}/".format(host=host, user=user, password=password)

    # -----------下方名称默认即可-------------
    db = "WatchAD"
    delay_run_collection = "ad_delay"
    settings_collection = "ad_settings"
    delegation_collection = "ad_delegation"
    learning_collection = "ad_learning"
    alerts_collection = "ad_alerts"
    activities_collection = "ad_activities"
    invasions_collection = "ad_invasions"
    exclude_collection = "ad_exclusions"
    ignore_collection = "ad_ignore"
    # --------------------------------------


class RedisConfig(object):
    """
        运行时的缓存，配置信息会动态加载到redis中
    """
    host = "127.0.0.1"
    port = 6379


# rabbit mq
class MqConfig(object):
    """
        消息队列配置

        从该消息队列直接消费日志和流量数据
    """
    host = "127.0.0.1"
    port = 5672
    user = "WatchAD"
    password = "WatchAD-by-0KEE"

    main_queue = "watch_ad_analytics"
    exchange = "WatchAD"
    exchange_type = "fanout"

