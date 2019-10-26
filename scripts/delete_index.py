#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    定期删除超过最大保留期限的域控日志索引
"""
import os
import sys

now_path = os.path.abspath(__file__)
home_path = "/".join(now_path.split("/")[:-2])
sys.path.append(home_path)

from tools.database.ElsaticHelper import ElasticHelper
from settings.config import main_config
from settings.database_config import ElasticConfig
from tools.common.common import get_n_days_ago, datetime_to_log_date
from elasticsearch5.exceptions import NotFoundError

from tools.common.Logger import logger


def main():
    logger.info("run scheduled task: delete expired index")
    es = ElasticHelper()
    raw_data_expire = main_config.raw_data_expire
    delete_map = {
        ElasticConfig.event_log_write_index_prefix: raw_data_expire["dc_log"],
        ElasticConfig.traffic_write_index_prefix: raw_data_expire["dc_krb5"],
        ElasticConfig.krb5_ticket_write_index_prefix: raw_data_expire["krb5_ticket"],
        ElasticConfig.user_activity_write_index_prefix: raw_data_expire["user_activity"]
    }

    for index_prefix, expire in delete_map.items():
        ago = get_n_days_ago(expire)
        date = datetime_to_log_date(ago)
        index_name = index_prefix + date

        try:
            es.delete_index(index_name)
            logger.info("delete index {name} successfully.".format(name=index_name))
        except NotFoundError:
            logger.warn("index {name} not found.".format(name=index_name))


if __name__ == '__main__':
    main()
