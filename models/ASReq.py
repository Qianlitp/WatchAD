#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

from models.BaseKrb5 import BaseKrb5, get_padata_sequence, ReqBody


class ASReq(BaseKrb5):
    def __init__(self, record: dict):
        super().__init__()
        self.msg_type = record["MsgType"]
        self.msg_type_int = record["MsgTypeInt"]
        self.PVNO = record["PVNO"]
        self.pa_data = get_padata_sequence(record["PAData"])
        self.req_body = ReqBody(record["ReqBody"])
        if "Renewal" in record:
            self.renewal = record["Renewal"]

