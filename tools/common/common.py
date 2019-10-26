#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

import os
import base64
import hashlib
from datetime import datetime, timedelta

import simplejson
from IPy import IP
from dns import resolver

from settings.config import main_config


def md5(target) -> str:
    m2 = hashlib.md5()
    m2.update(target.encode('utf-8'))
    return m2.hexdigest()


def base64_encode(str_) -> str:
    if isinstance(str_, dict) or isinstance(str_, list):
        str_ = simplejson.dumps(str_)
    if isinstance(str_, str):
        str_ = bytes(str_, encoding="utf-8")
    res = base64.b64encode(str_)
    return res.decode("utf-8")


def datetime_now() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def datetime_now_obj() -> datetime:
    return datetime.now()


def datetime_utc_now_obj() -> datetime:
    return datetime.utcnow()


def str_to_datetime(utc_str):
    """
        字符串时间转化为datetime对象
    """
    return datetime.strptime(utc_str, "%Y-%m-%d %H:%M:%S")


def get_n_days_ago(n) -> datetime:
    """
        获取n天之前的datetime对象
    """
    num = -int(n)
    return datetime.now() + timedelta(days=num)


def move_n_days(date_time, n) -> datetime:
    num = int(n)
    return date_time + timedelta(days=num)


def get_n_hour_ago(n) -> datetime:
    """
        获取n小时之前的datetime对象
    """
    num = -int(n)
    return datetime.now() + timedelta(hours=num)


def get_n_min_ago(n) -> datetime:
    """
        获取n分钟之前的datetime对象
    """
    num = -int(n)
    return datetime.now() + timedelta(minutes=num)


def move_n_sec(date_time, n) -> datetime:
    return date_time + timedelta(seconds=-n)


def move_n_min(date_time, n) -> datetime:
    return date_time + timedelta(minutes=-n)


def move_n_hour(date_time, n) -> datetime:
    return date_time + timedelta(hours=-n)


def move_n_day(date_time, n) -> datetime:
    return date_time + timedelta(days=-n)


def datetime_to_common_str(time) -> str:
    """
        将datetime对象转换为常见的时间格式
    """
    return time.strftime('%Y-%m-%d %H:%M:%S')


def datetime_to_log_date(date_time) -> str:
    return date_time.strftime('%Y.%m.%d')


def utc_to_local_datetime(utc_str) -> datetime:
    """
        暴力方法，直接将时间加8小时得到当前本地时间
    """
    a = datetime.strptime(utc_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    return a + timedelta(hours=8)


def utc_to_datetime(utc_str) -> datetime:
    """
        UTC格式时间转化为datetime对象
    """
    return datetime.strptime(utc_str, "%Y-%m-%dT%H:%M:%S.%fZ")


def datetime_to_utc(date_time) -> str:
    """
        将datetime对象转换为UTC时间格式
    """
    return date_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def datetime_to_utc_no_f(date_time) -> str:
    """
        将datetime对象转换为UTC时间格式
    """
    return date_time.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_walk_files(path) -> list:
    file_list = []
    for root, dirs, files in os.walk(path):
        if "__pycache__" in root:
            continue
        for f in files:
            if f == "__init__.py":
                continue
            file_list.append(os.path.join(root, f))
    return file_list


def format_module_path(f: str) -> (str, str, ):
    f = f.replace(".py", "")
    f = f[2:].replace("/", ".")
    return f, f.split(".")[-1]


def convert_nested_to_list(nested, key) -> list:
    result = []
    for each in nested:
        result.append(each[key])
    return result


def hex2bin_number(number_str) -> bin:
    n = int(number_str.upper(), 16)
    return bin(n)


def ip_filter(ip) -> bool:
    if ip == "-" or ip == "::1":
        return True
    try:
        ip = IP(ip)
    except Exception as e:
        return True
    if ip in IP("127.0.0.0/8"):
        return True
    if ip.iptype() not in ["PRIVATE", "PUBLIC"]:
        return True


def get_dn_domain_name(domain) -> str:
    result = []
    for part in domain.split("."):
        result.append("DC=" + part)
    return ",".join(result)


def get_netbios_domain(domain) -> str:
    if "." not in domain:
        return domain.upper()
    elif "." in domain:
        prefix = domain.split(".")[0]
        return prefix.upper()


def filter_domain(domain) -> bool:
    if not domain:
        return True
    if "." in domain:
        return domain.lower() not in main_config.domain_list
    else:
        for each in main_config.domain_list:
            if domain.upper() == get_netbios_domain(each):
                return False
        return True


def get_ip_from_domain(domain) -> list:
    results = []
    ans = resolver.query(domain, "A")
    for i in ans.response.answer:
        for ip in i.items:
            results.append(str(ip))
    return results


def get_domain_from_dn(dn: str) -> str:
    domain_list = []
    parts = dn.split(",")
    for each in parts:
        if each.lower().startswith("dc="):
            domain_list.append(each.split("=")[1])
    return ".".join(domain_list)


def get_cn_from_dn(dn: str) -> str:
    parts = dn.split(",")
    for each in parts:
        if each.lower().startswith("cn="):
            return each.split("=")[1]


if __name__ == '__main__':
    print(datetime_to_common_str(utc_to_datetime("2019-01-15T06:43:42.207Z")))
