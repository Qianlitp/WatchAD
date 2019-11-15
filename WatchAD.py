#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    install     安装ES索引模板,初始化LDAP配置
    check       检查各个数据库连接状态、消息队列状态
    start       加载动态配置信息、创建计划任务、启动检测引擎
    restart     重新加载动态配置信息、删除计划任务、重启检测引擎
    stop        停止引擎 （删除现有消息队列，防止数据量过大造成积压）
    status      查看当前引擎状态
"""


from io import StringIO
import optparse
import sys
from _project_dir import project_dir
import subprocess
from tools.common.Logger import logger
from scripts.init_settings import init_es_template, check_es_template, check_mongo_connection, check_mq_connection, \
    init_ldap_settings, init_default_settings, get_all_dc_names, set_learning_end_time_setting, init_sensitive_groups, \
    set_crontab_tasks

ENGINE_PROCESS_NUM = 5


def install(domain, server, user, password):
    logger.info("Install the WatchAD ...")
    # 初始化ES索引模板
    init_es_template()
    # 初始化LDAP配置信息
    init_ldap_settings(domain, server, user, password)
    # 获取域控计算机名保存入库
    get_all_dc_names(domain)
    # 初始化其余配置信息
    init_default_settings(domain)
    # 初始化填入敏感用户组
    init_sensitive_groups(domain)
    # 根据当前安装时间，设置数据统计结束时间
    set_learning_end_time_setting()
    # 设置计划任务
    set_crontab_tasks()


def check() -> bool:
    logger.info("Checking the WatchAD environment ...")
    # 检查ES模板安装状态
    if not check_es_template():
        return False
    # 检查数据库连接
    if not check_mongo_connection():
        return False
    # 检查消息队列连接
    if not check_mq_connection():
        return False
    logger.info("OK!")
    logger.info("Check the WatchAD environment successfully!")
    return True


def start():
    if not check():
        sys.exit(-1)
    logger.info("Starting the WatchAD detect engine ...")

    rsp = subprocess.call("supervisord -c {root_dir}/supervisor.conf".format(root_dir=project_dir),
                          shell=True,
                          env={"WATCHAD_ENGINE_DIR": project_dir, "WATCHAD_ENGINE_NUM": str(ENGINE_PROCESS_NUM)})
    if rsp == 0:
        logger.info("Started!")
    else:
        logger.error("Start failed.")


def stop():
    logger.info("Stopping the WatchAD detect engine ...")

    stop_rsp = subprocess.call("supervisorctl -c {root_dir}/supervisor.conf stop all".format(root_dir=project_dir),
                               shell=True, env={"WATCHAD_ENGINE_DIR": project_dir,
                                                "WATCHAD_ENGINE_NUM": str(ENGINE_PROCESS_NUM)})
    if stop_rsp == 0:
        logger.info("Stopped detection processes.")
    else:
        logger.error("Stop failed.")
    shutdown_rsp = subprocess.call("supervisorctl -c {root_dir}/supervisor.conf shutdown".format(root_dir=project_dir),
                                   shell=True, env={"WATCHAD_ENGINE_DIR": project_dir,
                                                    "WATCHAD_ENGINE_NUM": str(ENGINE_PROCESS_NUM)})

    if shutdown_rsp == 0:
        logger.info("Shutdown WatchAD.")
    else:
        logger.error("Shutdown WatchAD failed.")


def restart():
    stop()
    start()


def status():
    subprocess.call("supervisorctl -c {root_dir}/supervisor.conf status".format(root_dir=project_dir),
                    shell=True,
                    env={"WATCHAD_ENGINE_DIR": project_dir})


def usage():
    s = StringIO()
    s.write("Usage:  WatchAD.py <options> [settings]")
    s.seek(0)
    return s.read()


def parse_option():
    parser = optparse.OptionParser(usage=usage())
    parser.add_option("--install", action="store_true", dest="install", help="Initial install WatchAD.")
    parser.add_option("-d", "--domain", action="store", dest="domain", help="A FQDN domain name. e.g: corp.360.cn")
    parser.add_option("-s", "--ldap-server", action="store", dest="server",
                      help="Server address for LDAP search. e.g: dc01.corp.com")
    parser.add_option("-u", "--domain-user", action="store", dest="username",
                      help="Username for LDAP search. e.g: CORP\\peter")
    parser.add_option("-p", "--domain-passwd", action="store", dest="password",
                      help="Password for LDAP search.")
    parser.add_option("--check", action="store_true", dest="check", help="check environment status")
    parser.add_option("--start", action="store_true", dest="start", help="start WatchAD detection engine")
    parser.add_option("--restart", action="store_true", dest="restart", help="restart WatchAD detection engine")
    parser.add_option("--stop", action="store_true", dest="stop",
                      help="stop WatchAD detection engine and shutdown supervisor")
    parser.add_option("--status", action="store_true", dest="status", help="show processes status using supervisor")
    return parser


def main():
    parser = parse_option()
    if len(sys.argv) < 2:
        logger.error("WatchAD must run with an action.")
        parser.print_help()
        sys.exit(1)
    options, args = parser.parse_args()

    if options.install:
        if not options.domain or not options.server or not options.username or not options.password:
            logger.error("WatchAD install action must provide domain, server, user and password params.")
            sys.exit(1)
        install(domain=options.domain, server=options.server, user=options.username, password=options.password)
    elif options.check:
        check()
    elif options.start:
        start()
    elif options.restart:
        restart()
    elif options.stop:
        stop()
    elif options.status:
        status()


if __name__ == '__main__':
    main()
