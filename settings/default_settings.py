#!/usr/bin/python3
# coding: utf-8
"""
    默认配置
"""

default_settings = {
    "domain_list": [],
    "raw_data_expire": {
        "dc_log": 7,
        "dc_krb5": 7,
        "user_activity": 30,
        "krb5_ticket": 30
    },
    "honeypot_account": [],
    "brute_force_max": 100,
    "VPN_ip_part": [],
    "detail_file_share_white_list": [
        "wkssvc",
        "ntsvcs",
        "netdfs",
        "netlogon"
    ],
    "alarms_merge": {
        "activity": 24,
        "invasion": 72
    },
    "sensitive_entry": {
        "user": [],
        "computer": [],
        "group": []
    },
    "kerberos": {
        "TGT_maximum_lifetime": 10,
        "ST_maximum_lifetime": 600,
        "high_risk_spn_prefix": [
            "MSSQLSvc",
            "MSSQL",
            "FIMService",
            "AGPMServer",
            "exchangeMDB",
            "TERMSERV",
            "WSMAN",
            "Microsoft Virtual Console Service",
            "STS"
        ],
        "high_risk_delegation_prefix": [
            "ldap/",
            "http/",
            "HOST/",
            "cifs/",
            "krbtgt/",
            "mssqlsvc/"
        ]
    }
}


def default_sensitive_groups(domain: str):
    """
    :param domain: netbios domain
    :return:
    """
    return [
        {
            "name": "Administrators",
            "sid": "S-1-5-32-544",
            "domain": domain
        },
        {
            "name": "Account Operators",
            "sid": "S-1-5-32-548",
            "domain": domain
        },
        {
            "name": "Server Operators",
            "sid": "S-1-5-32-549",
            "domain": domain
        },
        {
            "name": "Print Operators",
            "sid": "S-1-5-32-550",
            "domain": domain
        },
        {
            "name": "Backup Operators",
            "sid": "S-1-5-32-551",
            "domain": domain
        },
        {
            "name": "Replicator",
            "sid": "S-1-5-32-552",
            "domain": domain
        },
        {
            "name": "Remote Desktop Users",
            "sid": "S-1-5-32-555",
            "domain": domain
        },
        {
            "name": "Network Configuration Operators",
            "sid": "S-1-5-32-556",
            "domain": domain
        },
        {
            "name": "Incoming Forest Trust Builders",
            "sid": "S-1-5-32-557",
            "domain": domain
        },
        {
            "name": "Domain Admins",
            "sid": "",
            "domain": domain
        },
        {
            "name": "Enterprise Admins",
            "sid": "",
            "domain": domain
        },
        {
            "name": "Schema Admins",
            "sid": "",
            "domain": domain
        },
        {
            "name": "DnsAdmins",
            "sid": "",
            "domain": domain
        },
        {
            "name": "Group Policy Creator Owners",
            "sid": "",
            "domain": domain
        }
    ]

