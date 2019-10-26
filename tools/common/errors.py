#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp


class SecBaseException(Exception):
    def __init__(self, msg):
        self.msg = "[error] " + msg

    def __str__(self):
        return self.msg


class LDAPSearchFailException(SecBaseException):
    def __init__(self, msg=u"LDAP search fail"):
        SecBaseException.__init__(self, msg)


class MsearchException(SecBaseException):
    def __init__(self, msg=u"es msearch error"):
        SecBaseException.__init__(self, msg)


class NoDataInitEvent(SecBaseException):
    def __init__(self, msg=u"no data to init alert event object"):
        SecBaseException.__init__(self, msg)


class NoSuchDelegationType(SecBaseException):
    def __init__(self, msg=u"no such delegation type"):
        SecBaseException.__init__(self, msg)
