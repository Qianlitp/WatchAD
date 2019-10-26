#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

ETYPE_MAP = {
    1: "des-cbc-crc",
    2: "des-cbc-md4",
    3: "des-cbc-md5",
    4: "des-cbc-raw",
    5: "des3-cbc-md5",
    6: "des3-cbc-raw",
    7: "des3-cbc-sha1",
    8: "des3-hmac-sha1",
    9: "dsaWithSHA1-CmsOID",
    10: "md5WithRSAEncryption-CmsOID",
    11: "sha1WithRSAEncryption-CmsOID",
    12: "rc2CBC-EnvOID",
    13: "rsaEncryption-EnvOID",
    14: "rsaES-OAEP-ENV-OID",
    15: "des-ede3-cbc-Env-OID",
    16: "des3-cbc-sha1-kd",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    23: "rc4-hmac",
    24: "rc4-hmac-exp",
    25: "camellia128-cts-cmac",
    26: "camellia256-cts-cmac",
    65: "subkey-keymaterial"
}


class Encryption(object):

    NULL = 0
    AES256_CTS_HMAC_SHA1_96 = 18
    AES128_CTS_HMAC_SHA1_96 = 17
    ARCFOUR_HMAC_MD5 = 23
    ARCFOUR_HMAC_OLD = -133
    ARCFOUR_MD4 = -128
    ARCFOUR_HMAC_MD5_56 = 24
    ARCFOUR_HMAC_OLD_EXP = -135

    NORMAL_REQ_BODY_ETYPE = [
        AES256_CTS_HMAC_SHA1_96,
        ARCFOUR_HMAC_MD5,
        ARCFOUR_HMAC_OLD,
        ARCFOUR_MD4,
        ARCFOUR_HMAC_MD5_56,
        ARCFOUR_HMAC_OLD_EXP
    ]



class BaseKrb5(object):
    def __init__(self):
        pass


class EncPart(object):
    def __init__(self, record: dict):
        self.e_type = record["EType"]
        self.cipher_hash = record["CipherHash"]
        if "KVNO" in record:
            self.KVNO = record["KVNO"]


class Ticket(object):
    def __init__(self, record: dict):
        self.TktVNO = record["TktVNO"]
        self.enc_part = EncPart(record["EncPart"])
        self.s_name = PrincipalName(record["SName"])
        self.realm = record["Realm"]

    def get_doc(self) -> dict:
        return {
            "TktVNO": self.TktVNO,
            "realm": self.realm,
            "KVNO": self.enc_part.KVNO,
            "encryption_type": ETYPE_MAP[self.enc_part.e_type],
            "etype": self.enc_part.e_type,
            "ticket_hash": self.enc_part.cipher_hash,
            "name_string": self.s_name.name_string,
            "name_type": self.s_name.name_type_int
        }

    @property
    def spn(self):
        return "/".join(self.s_name.name_string)

    @property
    def hash(self):
        return self.enc_part.cipher_hash


class PrincipalName(object):
    def __init__(self, record: dict):
        self.name_type = record["NameTypeStr"]
        self.name_type_int = record["NameTypeInt"]
        self.name_string = record["NameString"]


class ReqBody(object):
    def __init__(self, record: dict):
        self.enc_auth_data = EncPart(record["EncAuthData"])
        self.s_name = PrincipalName(record["SName"])
        self.realm = record["Realm"]
        self.rtime_utc = record["RTime"]
        self.from_utc = record["From"]
        self.c_name = PrincipalName(record["CName"])
        self.nonce = record["Nonce"]
        self.e_type = record["EType"]
        self.padding = record["Padding"]
        self.till_utc = record["Till"]
        self.kdc_options = "0x" + record["KDCOptions"]
        self.address = record["Address"]
        self.additional_tickets = record["AdditionalTickets"]


class PAData(object):
    PADATA_TGS_REQ = 1
    PADATA_ENC_TIMESTAMP = 2

    def __init__(self, record: dict):
        self.pa_data_type_int = record["PADataTypeInt"]
        self.pa_data_type_str = record["PADataTypeStr"]
        if self.pa_data_type_int == 19:
            self.pa_data_value = get_info2_entry_list(record["PADataValue"])
        else:
            self.pa_data_value = record["PADataValue"]


class ETypeInfo2Entry(object):
    def __init__(self, record: dict):
        self.e_type = record["EType"]
        self.salt = record["Salt"]


def get_padata_sequence(data: list) -> list:
    result = []
    for one in data:
        result.append(PAData(one))
    return result


def get_ticket_list(data: list) -> list:
    result = []
    for one in data:
        result.append(Ticket(one))
    return result


def get_info2_entry_list(data: list) -> list:
    result = []
    for one in data:
        result.append(ETypeInfo2Entry(one))
    return result
