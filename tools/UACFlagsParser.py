#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    UAC User-Account-Control

    解析属性值含义
"""

# UAC 的含义和标志位映射
UAC_NAME_FLAGS_MAP = {
    "SCRIPT": "0x0001",
    "ACCOUNT_DISABLE": "0x0002",
    "UNKNOWN_1": "0x0004",
    "HOMEDIR_REQUIRED": "0x0008",
    "LOCKOUT": "0x0010",
    "PASSWD_NOTREQD": "0x0020",
    "PASSWD_CANT_CHANGE": "0x0040",
    "ENCRYPTED_TEXT_PWD_ALLOWED": "0x0080",
    "TEMP_DUPLICATE_ACCOUNT": "0x0100",
    "NORMAL_ACCOUNT": "0x0200",
    "UNKNOWN_2": "0x0400",
    "INTERDOMAIN_TRUST_ACCOUNT": "0x0800",
    "WORKSTATION_TRUST_ACCOUNT": "0x1000",
    "SERVER_TRUST_ACCOUNT": "0x2000",
    "UNKNOWN_3": "0x4000",
    "UNKNOWN_4": "0x8000",
    "DONT_EXPIRE_PASSWORD": "0x10000",
    "MNS_LOGON_ACCOUNT": "0x20000",
    "SMARTCARD_REQUIRED": "0x40000",
    "TRUSTED_FOR_DELEGATION": "0x80000",
    "NOT_DELEGATED": "0x100000",
    "USE_DES_KEY_ONLY": "0x200000",
    "DONT_REQ_PREAUTH": "0x400000",
    "PASSWORD_EXPIRED": "0x800000",
    "TRUSTED_TO_AUTH_FOR_DELEGATION": "0x1000000",
    "UNKNOWN_5": "0x2000000",
    "PARTIAL_SECRETS_ACCOUNT": "0x4000000"
}

# UAC 的标志位和含义映射
UAC_FLAGS_NAME_MAP = dict(zip(UAC_NAME_FLAGS_MAP.values(), UAC_NAME_FLAGS_MAP.keys()))


class UACFlagsParser(object):
    def __init__(self):
        pass

    def parse(self, flag) -> dict:
        result = {}
        if isinstance(flag, str):
            if flag.startswith("0x"):
                flag_int = int(flag, 16)
            else:
                flag_int = int(flag)
        else:
            flag_int = int(flag)

        flags_keys = sorted(UAC_FLAGS_NAME_MAP.keys(), key=lambda x: int(x, 16), reverse=True)
        for key in flags_keys:
            key_int = int(key, 16)
            if flag_int >= key_int:
                result[UAC_FLAGS_NAME_MAP[key]] = True
                flag_int -= key_int
            else:
                result[UAC_FLAGS_NAME_MAP[key]] = False
        return result

    def get_uac_change(self, new_uac, old_uac) -> (list, list, ):
        """
            判断UAC值的变化， 返回新增列表、移除列表
        """
        result_add = []
        result_remove = []
        new_flags = self.parse(new_uac)
        old_flags = self.parse(old_uac)

        for name in UAC_NAME_FLAGS_MAP.keys():
            if new_flags[name] == old_flags[name]:
                continue
            if new_flags[name] and not old_flags[name]:
                result_add.append(name)
            if not new_flags[name] and old_flags[name]:
                result_remove.append(name)
        return result_add, result_remove


if __name__ == '__main__':
    print(UACFlagsParser().parse(512))

    # print(UAC_FLAGS_NAME_MAP)

    print(UACFlagsParser().get_uac_change("0x210", "0x15"))
