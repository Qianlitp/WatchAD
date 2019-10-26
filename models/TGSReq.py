#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

from models.APReq import APReq
from models.BaseKrb5 import BaseKrb5, get_padata_sequence, ReqBody, get_ticket_list, PAData


class TGSReq(BaseKrb5):
    def __init__(self, record: dict):
        super().__init__()
        self.msg_type = record["MsgType"]
        self.msg_type_int = record["MsgTypeInt"]
        self.PVNO = record["PVNO"]
        self.pa_data = get_padata_sequence(record["PAData"])
        self.req_body = ReqBody(record["ReqBody"])
        if "AdditionalTickets" in record:
            self.additional_tickets = get_ticket_list(record["AdditionalTickets"])
        if "Renewal" in record:
            self.renewal = record["Renewal"]

        self._parse_pa_data()

    def _parse_pa_data(self):
        result = []
        for p in self.pa_data:
            assert isinstance(p, PAData)
            if p.pa_data_type_int == PAData.PADATA_TGS_REQ:
                assert isinstance(p.pa_data_value, dict)
                p.pa_data_value = APReq(p.pa_data_value)
            result.append(p)
        self.pa_data = result

