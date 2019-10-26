#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    解析 SDDL 语法的内容
"""

import re

import simplejson


class SDDLParser(object):

    def __init__(self):
        pass

    def parse(self, sddl_str) -> dict:
        try:
            parts = re.search(r"^(.+?)D:(.*?)(\(.+?)S:(.*?)(\(.*?)$", sddl_str).groups()
        except Exception as e:
            print(sddl_str)
            raise Exception(e)
        header_str = parts[0]
        header_info = self.get_header_info(header_str)
        dacl_aces = parts[2]
        sacl_aces = parts[4]

        dacl_ace_list = self.get_ace_list(dacl_aces)
        sacl_ace_list = self.get_ace_list(sacl_aces)
        return {
            "owner_sid": header_info["owner_sid"],
            "group_sid": header_info["group_sid"],
            "dacl_ace_list": dacl_ace_list,
            "sacl_ace_list": sacl_ace_list
        }

    def get_header_info(self, header_str):
        owner_sid = re.search("O:(.+)G:", header_str).groups()[0]
        group_sid = re.search("G:(.+?)$", header_str).groups()[0]

        if not owner_sid.startswith("S-"):
            if owner_sid in Trustees:
                owner_sid = Trustees[owner_sid]

        if not group_sid.startswith("S-"):
            if group_sid in Trustees:
                group_sid = Trustees[group_sid]
        return {
            "group_sid": group_sid,
            "owner_sid": owner_sid
        }

    def get_ace_list(self, aces):
        ace_list = []
        aces = re.findall(r"\(.*?\)", aces)
        aces = [x.replace(")", "") for x in aces if len(x) > 0]
        aces = [x.replace("(", "") for x in aces if len(x) > 0]

        for ace in aces:
            parts = ace.split(";")
            ace_obj = {
                "ace_type": AceType[parts[0]],
                "ace_flags": parts[1],
                "permissions": self.get_permissions(parts[2]),
                "object_type": self.get_object_type(parts[3]),
                "inherited_object_type": parts[4],
                "trustee": self.get_trustee(parts[5])
            }
            ace_list.append(ace_obj)
        return ace_list

    def get_permissions(self, permission_str):
        permissions = {
            "ace_flags": [],
            "generic_access_rights": [],
            "directory_service_access_rights": [],
            "file_access_rights": [],
            "registry_key_access_rights": []
        }
        permission_dict = {
            "ace_flags": AceFlags,
            "generic_access_rights": GenericAccessRights,
            "directory_service_access_rights": DirectoryServiceAccessRights,
            "file_access_rights": FileAccessRights,
            "registry_key_access_rights": RegistryKeyAccessRights
        }
        permission_list = re.findall("[A-Z][A-Z]", permission_str)
        for key, value in permission_dict.items():
            for p in permission_list:
                if p in value:
                    permissions[key].append(value[p])
        return permissions

    def get_object_type(self, obj_str):
        if obj_str in ControlAccessRights:
            return ControlAccessRights[obj_str]
        else:
            return obj_str

    def get_trustee(self, trustee_str):
        if not trustee_str.startswith("S-"):
            if trustee_str in Trustees:
                return Trustees[trustee_str]
            else:
                return trustee_str
        else:
            return trustee_str


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
ControlAccessRights = {
    "ee914b82-0a98-11d1-adbb-00c04fd8d5cd": "Abandon-Replication",
    "440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
    "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate-Rids",
    "68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
    "edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment",
    "014bf69c-7b3b-11d1-85f6-08002be74fab": "Change-Domain-Master",
    "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change-Infrastructure-Master",
    "bae50096-4752-11d1-9052-00c04fc2d4cf": "Change-PDC",
    "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change-Rid-Master",
    "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Master",
    "e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create-Inbound-Forest-Trust",
    "fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do-Garbage-Collection",
    "ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain-Administer-Server",
    "69ae6200-7f46-11d2-b9ad-00c04f79f805": "DS-Check-Stale-Phantoms",
    "2f16c4a5-b98e-432c-952a-cb388ba33f2e": "DS-Execute-Intentions-Script",
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
    "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "DS-Query-Self-Quota",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "DS-Replication-Monitor-Topology",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": "Enable-Per-User-Reversibly-Encrypted-Password",
    "b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Logging",
    "b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Planning",
    "7c0e2a7c-a419-48e4-a995-10180aad54dd": "Manage-Optional-Features",
    "ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
    "b4e60130-df3f-11d1-9c86-006008764d0e": "msmq-Open-Connector",
    "06bd3201-df3e-11d1-9c86-006008764d0e": "msmq-Peek",
    "4b6e08c3-df3c-11d1-9c86-006008764d0e": "msmq-Peek-computer-Journal",
    "4b6e08c1-df3c-11d1-9c86-006008764d0e": "msmq-Peek-Dead-Letter",
    "06bd3200-df3e-11d1-9c86-006008764d0e": "msmq-Receive",
    "4b6e08c2-df3c-11d1-9c86-006008764d0e": "msmq-Receive-computer-Journal",
    "4b6e08c0-df3c-11d1-9c86-006008764d0e": "msmq-Receive-Dead-Letter",
    "06bd3203-df3e-11d1-9c86-006008764d0e": "msmq-Receive-journal",
    "06bd3202-df3e-11d1-9c86-006008764d0e": "msmq-Send",
    "a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open-Address-Book",
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "Read-Only-Replication-Secret-Synchronization",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate-Hierarchy",
    "62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate-Security-Inheritance",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
    "9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh-Group-Cache",
    "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload-SSL-Certificate",
    "7726b9d5-a4b4-4288-a6b2-dce952e80a7f": "Run-Protect_Admin_Groups-Task",
    "91d67418-0135-4acc-8d79-c08e857cfbec": "SAM-Enumerate-Entire-Domain",
    "ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
    "ab721a55-1e2f-11d0-9819-00aa0040529b": "Send-To",
    "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
    "280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
    "be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password"
}

AceType = {
    "A": "ACCESS ALLOWED",
    "D": "ACCESS DENIED",
    "OA": "OBJECT ACCESS ALLOWED: ONLY APPLIES TO A SUBSET OF THE OBJECT(S).",
    "OD": "OBJECT ACCESS DENIED: ONLY APPLIES TO A SUBSET OF THE OBJECT(S).",
    "AU": "SYSTEM AUDIT",
    "AL": "SYSTEM ALARM",
    "OU": "OBJECT SYSTEM AUDIT",
    "OL": "OBJECT SYSTEM ALARM"
}

AceFlags = {
    "CI": "CONTAINER INHERIT: Child objects that are containers, such as directories, inherit the ACE as an explicit ACE.",
    "OI": "OBJECT INHERIT: Child objects that are not containers inherit the ACE as an explicit ACE.",
    "NP": "NO PROPAGATE: ONLY IMMEDIATE CHILDREN INHERIT THIS ACE.",
    "IO": "INHERITANCE ONLY: ACE DOESN'T APPLY TO THIS OBJECT, BUT MAY AFFECT CHILDREN VIA INHERITANCE.",
    "ID": "ACE IS INHERITED",
    "SA": "SUCCESSFUL ACCESS AUDIT",
    "FA": "FAILED ACCESS AUDIT"
}

AclFlags = {
    "P": "The SE_DACL_PROTECTED flag is set",
    "AR": "The SE_DACL_AUTO_INHERIT_REQ flag is set",
    "AI": "The SE_DACL_AUTO_INHERITED flag is set",
    "NO_ACCESS_CONTROL": "The ACL is null"
}

GenericAccessRights = {
    "GA": "GENERIC ALL",
    "GR": "GENERIC READ",
    "GW": "GENERIC WRITE",
    "GX": "GENERIC EXECUTE"
}

DirectoryServiceAccessRights = {
    "RC": "Read Permissions",
    "SD": "Delete",
    "WD": "Modify Permissions",
    "WO": "Modify Owner",
    "RP": "Read All Properties",
    "WP": "Write All Properties",
    "CC": "Create All Child Objects",
    "DC": "Delete All Child Objects",
    "LC": "List Contents",
    "SW": "All Validated Writes",
    "LO": "List Object",
    "DT": "Delete Subtree",
    "CR": "All Extended Rights"
}

FileAccessRights = {
    "FA": "FILE ALL ACCESS",
    "FR": "FILE GENERIC READ",
    "FW": "FILE GENERIC WRITE",
    "FX": "FILE GENERIC EXECUTE"
}

RegistryKeyAccessRights = {
    "KA": "KEY ALL ACCESS",
    "KR": "KEY READ",
    "KW": "KEY WRITE",
    "KX": "KEY EXECUTE"
}

Trustees = {
    "AO": "Account operators",
    "RU": "Alias to allow previous Windows 2000",
    "AN": "Anonymous logon",
    "AU": "Authenticated users",
    "BA": "Built-in administrators",
    "BG": "Built-in guests",
    "BO": "Backup operators",
    "BU": "Built-in users",
    "CA": "Certificate server administrators",
    "CG": "Creator group",
    "CO": "Creator owner",
    "DA": "Domain administrators",
    "DC": "Domain computers",
    "DD": "Domain controllers",
    "DG": "Domain guests",
    "DU": "Domain users",
    "EA": "Enterprise administrators",
    "ED": "Enterprise domain controllers",
    "WD": "Everyone",
    "PA": "Group Policy administrators",
    "IU": "Interactively logged-on user",
    "LA": "Local administrator",
    "LG": "Local guest",
    "LS": "Local service account",
    "SY": "Local system",
    "NU": "Network logon user",
    "NO": "Network configuration operators",
    "NS": "Network service account",
    "PO": "Printer operators",
    "PS": "Personal self",
    "PU": "Power users",
    "RS": "RAS servers group",
    "RD": "Terminal server users",
    "RE": "Replicator",
    "RC": "Restricted code",
    "SA": "Schema administrators",
    "SO": "Server operators",
    "SU": "Service logon user"
}


if __name__ == '__main__':
    pass
