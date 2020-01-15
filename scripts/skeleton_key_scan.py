#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    万能钥匙扫描

    扫描每个域控，使用AES256加密发送 AS_REQ ，如果该域控被注入了万能钥匙，则会触发4771事件，错误代码为 0xe
"""

import os
import sys
import traceback
from random import getrandbits
from time import time
from socket import timeout

now_path = os.path.abspath(__file__)
home_path = "/".join(now_path.split("/")[:-2])
sys.path.append(home_path)
sys.path.append(home_path + "/libs")

from libs.kek.ccache import CCache, get_tgt_cred, kdc_rep2ccache
from libs.kek.krb5 import build_as_req, build_tgs_req, send_req, recv_rep, \
    decrypt_as_rep, decrypt_tgs_rep, AD_WIN2K_PAC, decode, KrbError, KDC_ERR_ETYPE_NOSUPP, AES256
from settings.config import main_config
from tools.LDAPSearch import LDAPSearch
from tools.common.common import get_netbios_domain


class SkeletonKeyScan(object):
    def __init__(self):
        pass

    def scan(self):
        domain_list = main_config.domain_list
        dc_name_list_map = main_config.dc_name_list

        # 对所有的域进行检查
        for domain in domain_list:
            # 对所有的域控进行检查
            account = self._get_support_aes_account(domain)
            for dc_name in dc_name_list_map[get_netbios_domain(domain)]:
                self.check(domain, dc_name, account)

    def check(self, domain, dc_name, account):
        nonce = getrandbits(31)
        current_time = time()
        etype = AES256
        as_req = build_as_req(get_netbios_domain(domain), account, None, current_time, nonce, True, etype)
        kdc_dns = "{dc_name}.{domain}".format(dc_name=dc_name, domain=domain)
        try:
            sock = send_req(as_req, kdc_dns, )
            data = recv_rep(sock)
            err_enc = decode(data, asn1Spec=KrbError())[0]
            print(err_enc['error-code'])
            if err_enc['error-code'] == KDC_ERR_ETYPE_NOSUPP:
                # TODO 发现万能钥匙
                return
        except timeout:
            pass
        except ConnectionRefusedError:
            pass
        except Exception as e:
            traceback.print_exc()

    def _get_support_aes_account(self, domain):
        ldap = LDAPSearch(domain)
        entry = ldap.get_support_aes_account()
        if entry:
            return str(entry["sAMAccountName"])


if __name__ == '__main__':
    SkeletonKeyScan().scan()
