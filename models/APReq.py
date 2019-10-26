#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

from models.BaseKrb5 import BaseKrb5, Ticket, EncPart


class APReq(BaseKrb5):
    def __init__(self, record: dict):
        super().__init__()
        self.msg_type = record["MsgType"]
        self.msg_type_int = record["MsgTypeInt"]
        self.PVNO = record["PVNO"]
        self.ticket = Ticket(record["Ticket"])
        self.ap_options = record["APOptions"]
        self.enc_authenticator = EncPart(record["EncryptedAuthenticator"])
