#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    流量数据对象
"""
from models.ASRep import ASRep
from models.ASReq import ASReq
from models.KrbError import KrbError
from models.TGSRep import TGSRep
from models.TGSReq import TGSReq
from tools.common.common import datetime_to_common_str, utc_to_local_datetime

KRB_AS_REQ = 10
KRB_AS_REP = 11
KRB_TGS_REQ = 12
KRB_TGS_REP = 13
KRB_AP_REQ = 14
KRB_AP_REP = 15
KRB_ERROR = 30


class Kerberos(object):
    def __init__(self, record: dict):
        self.record = record
        self.uuid = record["uuid"]
        self.utc_time = record["@timestamp"]
        self.dc_host_name = record["host"]["hostname"]
        self.msg_type = record["msgType"]
        self.type = record["type"]
        self.time = datetime_to_common_str(utc_to_local_datetime(record["@timestamp"]))
        self.client = Client(record["client"]["ip"], record["client"]["port"])
        self.server = Server(record["server"]["ip"], record["server"]["port"])
        self.req = self._get_req()
        self.rep = self._get_rep()

    def _get_req(self):
        if self.msg_type == "AS":
            return ASReq(self.record["req"])
        else:
            return TGSReq(self.record["req"])

    def _get_rep(self):
        if self.record["rep"]["MsgType"] == "KRB_ERROR":
            return KrbError(self.record["rep"])
        elif self.record["rep"]["MsgType"] == "AS_REP":
            return ASRep(self.record["rep"])
        else:
            return TGSRep(self.record["rep"])


class Client(object):
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port


class Server(object):
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
