#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

dc_log_template = {
    "template": "dc_log_*",
    "order": 1,
    "settings": {
        "number_of_shards": 10,
        "number_of_replicas": 1,
        "index.refresh_interval": "1s"
    },
    "mappings": {
        "security_log": {
            "include_in_all": "false",
            "properties": {
                "task": {"type": "keyword"},
                "event_id": {"type": "integer"},
                "computer_name": {"type": "keyword"},
                "audit_result": {"type": "keyword"},
                "level": {"type": "keyword"},
                "record_number": {"type": "keyword"},
                "source_name": {"type": "keyword"},
                "provider_guid": {"type": "keyword"},
                "opcode": {"type": "keyword"},
                "thread_id": {"type": "keyword"},
                "host": {"type": "keyword"},
                "event_data": {
                    "properties": {}
                },
                "message": {"type": "keyword"},
                "version": {"type": "integer"},
                "@timestamp": {"type": "date"}
            }
        }
    },
    "aliases": {
        "dc_log_all": {}
    }
}

krb5_ticket_template = {
    "template": "krb5_ticket_*",
    "order": 1,
    "settings": {
        "number_of_shards": 10,
        "number_of_replicas": 1
    },
    "mappings": {
        "ticket": {
            "include_in_all": "false",
            "properties": {
                "ticket_type": {"type": "keyword"},
                "user_name": {"type": "keyword"},
                "domain_controller": {"type": "keyword"},
                "kdc_options": {"type": "keyword"},
                "issue_time": {"type": "date"},
                "source_ip": {"type": "ip"},
                "ticket_data": {
                    "properties": {
                        "TktVNO": {"type": "integer"},
                        "KVNO": {"type": "integer"},
                        "realm": {"type": "keyword"},
                        "encryption_type": {"type": "keyword"},
                        "name_type": {"type": "integer"},
                        "etype": {"type": "integer"},
                        "ticket_hash": {"type": "keyword"}
                    }
                }
            }
        }
    },
    "aliases": {
        "krb5_ticket_all": {}
    }
}

dc_traffic_template = {
    "template": "dc_traffic_*",
    "order": 1,
    "settings": {
        "number_of_shards": 10,
        "number_of_replicas": 1
    },
    "mappings": {
        "kerberos": {
            "include_in_all": "false",
            "properties": {
                "uuid": {"type": "keyword"},
                "msgType": {"type": "keyword"},
                "req": {
                    "properties": {}
                },
                "rep": {
                    "properties": {}
                },
                "event_data": {
                    "properties": {}
                },
                "source": {
                  "properties": {
                    "ip": {"type": "ip"},
                    "port": {"type": "integer"}
                  }
                },
                "client": {
                  "properties": {
                    "ip": {"type": "ip"},
                    "port": {"type": "integer"}
                  }
                },
                "server": {
                  "properties": {
                    "ip": {"type": "ip"},
                    "port": {"type": "integer"}
                  }
                },
                "destination": {
                  "properties": {
                    "ip": {"type": "ip"},
                    "port": {"type": "integer"}
                  }
                },
                "status": {"type": "keyword"},
                "version": {"type": "integer"},
                "@timestamp": {"type": "date"}
            }
        }
    },
    "aliases": {
        "dc_traffic_all": {}
    }
}

user_activity_template = {
    "template": "user_activity_*",
    "order": 1,
    "settings": {
        "number_of_shards": 10,
        "number_of_replicas": 1
    },
    "mappings": {
        "user_activity": {
            "include_in_all": "false",
            "properties": {
                "domain": {"type": "keyword"},
                "user_name": {"type": "keyword"},
                "sid": {"type": "keyword"},
                "activity_type": {"type": "keyword"},
                "dc_name": {"type": "keyword"},
                "@timestamp": {"type": "date"},
                "data": {
                    "properties": {}
                }
            }
        }
    },
    "aliases": {
        "user_activity_all": {}
    }
}

template_map = {
    "dc_log_template": dc_log_template,
    "krb5_ticket_template": krb5_ticket_template,
    "dc_traffic_template": dc_traffic_template,
    "user_activity_template": user_activity_template
}
