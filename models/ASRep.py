#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

from models.BaseKrb5 import BaseKrb5, get_padata_sequence, PrincipalName, Ticket, EncPart


class ASRep(BaseKrb5):
    def __init__(self, record: dict):
        super().__init__()
        self.msg_type = record["MsgType"]
        self.msg_type_int = record["MsgTypeInt"]
        self.PVNO = record["PVNO"]
        self.crealm = record["CRealm"]
        self.c_name = PrincipalName(record["CName"])
        self.ticket = Ticket(record["Ticket"])
        self.enc_part = EncPart(record["EncPart"])
        if "PAData" in record:
            self.pa_data = get_padata_sequence(record["PAData"])
