#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

import time
import logging
from elasticsearch5 import Elasticsearch, helpers
from tools.common.Logger import logger
from tools.common.common import datetime_now_obj, get_n_min_ago

from settings.database_config import ElasticConfig

logging.getLogger("elasticsearch").setLevel(logging.ERROR)


class ElasticHelper(object):
    def __init__(self):
        self.es = Elasticsearch(ElasticConfig.uri)
        self._multi_search_results = []
        self.bulk_task_queue = []
        self.bulk_last_time = datetime_now_obj()

    def delay_index(self, body, index, doc_type):
        self.bulk_task_queue.append({
            "index": {"_index": index, "_type": doc_type}
        })
        self.bulk_task_queue.append(body)

        if self._can_do_bulk():
            self.bulk(body=self.bulk_task_queue, index=index, doc_type=doc_type)
            self.bulk_task_queue = []

        self.bulk_last_time = datetime_now_obj()

    def _can_do_bulk(self):
        # 任务队列超过100条数据
        if len(self.bulk_task_queue) > 100:
            return True
        # 时间间隔超过1分钟
        if get_n_min_ago(1) > self.bulk_last_time:
            return True
        return False

    def index(self, body, index, doc_type):
        self.es.index(body=body, index=index, doc_type=doc_type)

    def bulk(self, body, index, doc_type):
        self.es.bulk(body=body, index=index, doc_type=doc_type)

    def scan(self, body, index, doc_type):
        return helpers.scan(self.es, query=body, index=index, doc_type=doc_type, preserve_order=True)

    def search(self, body, index, doc_type):
        try:
            rsp = self.es.search(body=body, index=index, doc_type=doc_type, request_timeout=100)
            if rsp.get("error"):
                logger.error(rsp.get("error").get("reason"))
                return
            return rsp
        except Exception as e:
            print(body)
            logger.error("es search error: " + str(e) + index)

    def count(self, body, index, doc_type):
        return self.es.count(index=index, doc_type=doc_type, body=body, request_timeout=100)

    def delete_index(self, index):
        return self.es.indices.delete(index=index)

    def put_template(self, name, body, **kwargs):
        return self.es.indices.put_template(name=name, body=body, create=True, **kwargs)

    def exists_template(self, name, **kwargs) -> bool:
        return self.es.indices.exists_template(name=name, **kwargs)

    def delete_template(self, name, **kwargs):
        return self.es.indices.delete_template(name=name, **kwargs)

    def get_template(self, name, **kwargs):
        return self.es.indices.get_template(name=name, **kwargs)

    def wait_log_in_database(self, computer_name, record_number):
        """
            因为消息队列和入库ES是分开进行的，所以可能会出现当消费到某条日志时，ES还没入库，所以需要检查同步
        """
        count = 0
        query = {
            "query": get_must_statement(
                get_term_statement("computer_name", computer_name),
                get_term_statement("record_number", record_number)
            ),
            "_source": False,
            "size": 1
        }
        while True:
            try:
                rsp = self.es.search(body=query,
                                     index=ElasticConfig.event_log_index,
                                     doc_type=ElasticConfig.event_log_doc_type,
                                     request_timeout=100)
                if rsp.get("error"):
                    logger.error(rsp.get("error").get("reason"))
                    break
                if len(rsp["hits"]["hits"]) > 0:
                    return rsp["hits"]["hits"][0]["_id"]
                time.sleep(2)
                # 最多等5次，即 2 * 5 = 10秒
                if count == 10:
                    break
                count += 1
            except Exception as e:
                logger.error("es wait_log_in_database search error: " + str(e))
                break

    def multi_search(self, body, index, doc_type):
        try:
            rsp = self.es.msearch(body=body,
                                  index=index,
                                  doc_type=doc_type,
                                  request_timeout=100)
            if rsp.get("error"):
                logger.error(rsp.get("error").get("reason"))
                return
            return rsp
        except Exception as e:
            logger.error("es msearch error: " + str(e))


def get_time_range(compare, time, time_zone_offset=False):
    if time_zone_offset:
        return {
            "constant_score": {
                "filter": {
                    "range": {
                        "@timestamp": {
                            compare: time,
                            "time_zone": "+08:00"
                        }
                    }
                }
            }
        }
    else:
        return {
            "constant_score": {
                "filter": {
                    "range": {
                        "@timestamp": {
                            compare: time,
                        }
                    }
                }
            }
        }


def get_range_statement(field, compare, time):
    return {
        "constant_score": {
            "filter": {
                "range": {
                    field: {
                        compare: time,
                    }
                }
            }
        }
    }


def get_term_statement(field_name, value):
    return {
        "constant_score": {
            "filter": {
                "term": {
                    field_name: value
                }
            }
        }
    }


def get_must_statement(*args):
    return {
        "bool": {
            "must": [*args]
        }
    }


def get_should_statement(*args):
    return {
        "bool": {
            "should": [*args]
        }
    }


def get_terms_statement(field_name, value):
    return {
        "constant_score": {
            "filter": {
                "terms": {
                    field_name: value
                }
            }
        }
    }


def get_must_not_statement(statement):
    return {
        "bool": {
            "must_not": statement
        }
    }


def get_sort_statement(field, order):
    return {
        field: order
    }


def get_aggs_statement(name, aggs_type, field, size=1000000):
    return {
        name: {
            aggs_type: {
                "field": field,
                "size": size
            }
        }
    }


def get_double_aggs_statement(name1, aggs_type1, field1, name2, aggs_type2, field2):
    return {
        name1: {
            aggs_type1: {
                "field": field1,
                "size": 1000000
            },
            "aggs": {
                name2: {
                    aggs_type2: {
                        "field": field2,
                        "size": 1000000
                    }
                }
            }
        }
    }


def get_wildcard_statement(field, value):
    return {
        "constant_score": {
            "filter": {
                "wildcard": {
                    field: value
                }
            }
        }
    }


def get_match_must_all(field, value):
    """
        match 查询，对于 text 字段分词忽略大小写
    """
    return {
        "constant_score": {
            "filter": {
                "match": {
                    field: {
                        "query": value,
                        "operator": "and"
                    }
                }
            }
        }
    }