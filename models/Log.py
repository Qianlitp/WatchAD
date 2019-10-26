#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    单条日志对象封装
"""

from tools.TicketParser import TicketParser
from tools.common.common import datetime_to_common_str, utc_to_local_datetime, md5


class Log(object):
    def __init__(self, record, doc_id=None):
        self.doc_id = doc_id
        self.record = record
        self.event_id = record["event_id"]
        self.log_time = datetime_to_common_str(utc_to_local_datetime(record["@timestamp"]))
        self.utc_log_time = record["@timestamp"]
        self.level = record["level"]
        self.message = record["message"]
        self.record_number = record["record_number"]
        self.dc_computer_name = record["computer_name"]
        self.dc_host_name = record["beat"]["hostname"]

        if "event_data" in record:
            self.event_data = record["event_data"]

            self.source_info = SourceInfo(record["event_data"])
            self.target_info = TargetInfo(record["event_data"])
            self.subject_info = SubjectInfo(record["event_data"])
            self.ticket_info = TicketInfo(record["event_data"])
            self.object_info = ObjectInfo(record["event_data"])

    @property
    def id(self):
        id_str = str(self.event_id)
        key_list = sorted(self.record["event_data"].keys())
        for key in key_list:
            id_str += str(self.record["event_data"][key])
        return md5(id_str)


class SourceInfo(object):
    def __init__(self, event_data):
        self.work_station_name = None
        self.ip_address = None
        self.port = None

        self._field_map = {
            "WorkstationName": "work_station_name",
            "IpAddress": "ip_address",
            "IpPort": "port"
        }
        for key, value in self._field_map.items():
            if key not in event_data:
                continue
            elif key == "IpAddress":
                ip = event_data[key]
                if ip.startswith("::ffff:"):
                    ip = ip.replace("::ffff:", "")
                self.__dict__.update({value: ip})
            else:
                self.__dict__.update({value: event_data[key]})

    def get_doc(self):
        return {
            "work_station_name": self.work_station_name if self.work_station_name else "",
            "ip_address": self.ip_address if self.ip_address else "",
            "port": self.port if self.port else ""
        }


class TargetInfo(object):
    def __init__(self, event_data):
        self.domain_name = None
        self.user_name = None
        self.user_sid = None
        self.logon_id = None
        self.info = None
        self.server_name = None
        self.sid = None
        self.full_user_name = None

        self._field_map = {
            "TargetDomainName": "domain_name",
            "TargetUserName": "user_name",
            "TargetUserSid": "user_sid",
            "TargetSid": "sid",
            "TargetLogonId": "logon_id",
            "TargetInfo": "info",
            "TargetServerName": "server_name"
        }
        for key, value in self._field_map.items():
            if key not in event_data:
                continue
            # UserName 中可能存在 @xxx.com 的后缀
            if key == "TargetUserName":
                if "@" in event_data[key]:
                    user_name = event_data[key].split("@")[0]
                    self.__dict__.update({value: user_name})
                else:
                    self.__dict__.update({value: event_data[key]})
                self.__dict__.update({"full_user_name": event_data[key]})
            elif key in event_data:
                self.__dict__.update({value: event_data[key]})

    def get_doc(self):
        return {
            "domain_name": self.domain_name,
            "user_name": self.user_name,
            "user_sid": self.user_sid,
            "sid": self.sid,
            "logon_id": self.logon_id,
            "info": self.info,
            "server_name": self.server_name,
            "full_user_name": self.full_user_name
        }


class SubjectInfo(object):
    def __init__(self, event_data):
        self.logon_id = None
        self.user_name = None
        self.domain_name = None
        self.user_sid = None
        self.full_user_name = None

        self._field_map = {
            "SubjectDomainName": "domain_name",
            "SubjectUserName": "user_name",
            "SubjectUserSid": "user_sid",
            "SubjectLogonId": "logon_id",
        }

        for key, value in self._field_map.items():
            if key not in event_data:
                continue
            # UserName 中可能存在 @xxx.com 的后缀
            if key == "SubjectUserName":
                if "@" in event_data[key]:
                    user_name = event_data[key].split("@")[0]
                    self.__dict__.update({value: user_name})
                else:
                    self.__dict__.update({value: event_data[key]})
                self.__dict__.update({"full_user_name": event_data[key]})
            elif key in event_data:
                self.__dict__.update({value: event_data[key]})

    def get_doc(self):
        return {
            "domain_name": self.domain_name if self.domain_name else "",
            "user_name": self.user_name if self.user_name else "",
            "user_sid": self.user_sid if self.user_sid else "",
            "logon_id": self.logon_id if self.logon_id else "",
            "full_user_name": self.full_user_name if self.full_user_name else ""
        }


class TicketInfo(object):
    def __init__(self, event_data):
        self.encryption_type = None
        self.encryption_type_detail = None
        self.options = None
        self.options_detail = None
        self.status = None

        self._field_map = {
            "TicketEncryptionType": "encryption_type",
            "TicketOptions": "options",
            "Status": "status"
        }

        ticket_parser = TicketParser()

        for key, value in self._field_map.items():
            if key not in event_data:
                continue
            elif key == "TicketEncryptionType":
                self.__dict__.update({value: event_data[key]})
                self.encryption_type_detail = ticket_parser.encryption_parse(event_data[key])
            elif key == "TicketOptions":
                self.__dict__.update({value: event_data[key]})
                self.options_detail = ticket_parser.option_parse(event_data[key])
            else:
                self.__dict__.update({value: event_data[key]})

    def get_doc(self):
        return {
            "encryption_type": self.encryption_type if self.encryption_type else "",
            "encryption_type_detail": self.encryption_type_detail if self.encryption_type_detail else "",
            "options": self.options if self.options else "",
            "options_detail": self.options_detail if self.options_detail else "",
            "status": self.status if self.status else ""
        }


class ObjectInfo(object):
    def __init__(self, event_data):
        self.dn = None
        self.guid = None
        self.class_ = None
        self.server = None
        self.type = None
        self.name = None

        self._field_map = {
            "ObjectDN": "dn",
            "ObjectGUID": "guid",
            "ObjectClass": "class_",
            "ObjectServer": "server",
            "ObjectType": "type",
            "ObjectName": "name"
        }

        for key, value in self._field_map.items():
            if key not in event_data:
                continue
            self.__dict__.update({value: event_data[key]})

    def get_doc(self):
        return {
            "dn": self.dn if self.dn else "",
            "guid": self.guid if self.guid else "",
            "class": self.class_ if self.class_ else "",
            "server": self.server if self.server else "",
            "type": self.type if self.type else "",
            "name": self.name if self.name else ""
        }
