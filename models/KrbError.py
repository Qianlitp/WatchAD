#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

from models.BaseKrb5 import BaseKrb5, PrincipalName, get_padata_sequence


class KrbError(BaseKrb5):
    def __init__(self, record: dict):
        super().__init__()
        self.msg_type = record["MsgType"]
        self.msg_type_int = record["MsgTypeInt"]
        self.PVNO = record["PVNO"]
        self.c_time_utc = record["CTime"]
        self.s_time_utc = record["STime"]
        self.cu_sec = record["CuSec"]
        self.su_sec = record["SuSec"]
        self.s_name = PrincipalName(record["SName"])
        self.realm = record["Realm"]
        self.crealm = record["CRealm"]
        self.error_code = record["ErrorCode"]
        self.etext = record["EText"]
        self.e_data = get_padata_sequence(record["EData"])
