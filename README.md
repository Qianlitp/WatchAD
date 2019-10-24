# WatchAD

[![PyPI version](https://img.shields.io/badge/Python-3.6+-blue.svg)](http://git.websec.cc/zhusiyu/dc_log_analyze) [![ElasticSearch version](https://img.shields.io/badge/ElasticSearch-5.X-success.svg)](https://www.elastic.co/guide/en/elasticsearch/reference/5.2/index.html) [![Logstash version](https://img.shields.io/badge/Logstash-6.X-yellowgreen.svg)](https://www.elastic.co/guide/en/logstash/6.2/index.html) [![RabbitMQ version](https://img.shields.io/badge/RabbitMQ-3.7-orange.svg)](https://www.rabbitmq.com/) [![DEF CON 27 Blue Team Village](https://img.shields.io/badge/DEF%20CON%2027-Blue%20Team%20Village-blue.svg)](https://www.blueteamvillage.org/home/dc27/talks#h.p_5uroKErLDdmP)

>  域安全入侵感知系统

WatchAD收集所有域控上的事件日志和kerberos流量，通过特征匹配、Kerberos协议分析、历史行为、敏感操作和蜜罐账户等方式来检测各种已知与未知威胁，功能覆盖了大部分目前的常见内网域渗透手法。该项目在360内部上线运行半年有余，发现多起威胁活动，取得了较好的效果。现决定开源系统中基于事件日志的检测部分。

目前支持的具体检测功能如下：

* **信息探测**：使用SAMR查询敏感用户组、使用SAMR查询敏感用户、蜜罐账户的活动、PsLoggedOn信息收集
* **凭证盗取**：Kerberoasting （流量）、AS-REP Roasting、远程Dump域控密码
* **横向移动**：账户爆破、显式凭据远程登录、目标域控的远程代码执行、未知文件共享名、Kerberos票据加密方式降级（流量）、异常的Kerberos票据请求（流量）
* **权限提升**：ACL修改、MS17-010攻击检测、新增组策略监控、NTLM 中继检测、基于资源的约束委派权限授予检测、攻击打印机服务 SpoolSample、未知权限提升、MS14-068攻击检测（流量）、Kerberos约束委派滥用（流量）
* **权限维持**：AdminSDHolder对象修改、DCShadow攻击检测、DSRM密码重置、组策略委派权限授予检测、Kerberos约束委派权限授予检测、敏感用户组修改、域控新增系统服务、域控新增计划任务、SIDHistory属性修改、万能钥匙-主动检测、万能钥匙-被动检测（流量）、黄金票据（流量）
* **防御绕过**：事件日志清空、事件日志服务被关闭

> 其中标注了**流量**的检测方法暂未在本次开源计划中，后续会根据大家的反馈继续开源。



## 安装部署

WatchAD是一个完整的检测系统，涉及的内容较多，请参考 [INSTALL.md](https://github.com/0Kee-Team/WatchAD/tree/master/docs/INSTALL.md) 进行安装。

项目架构简图：

![](C:\Users\zhusiyu1\Desktop\ATA相关文档\架构图.png)

本项目 WatchAD 只包含了检测引擎相关的代码，Web平台的前后端代码在项目 [WatchAD-Web](https://github.com/0Kee-Team/WatchAD-Web) 中。

## 自定义检测模块

WatchAD支持开发自定义的检测模块，详情请参考我们的[教程](https://github.com/0Kee-Team/WatchAD/tree/master/docs/DEVELOP.md)。

## Follow me

微博： [@9ian1i](https://weibo.com/u/5242748339)

Github： [@9ian1i](https://github.com/Qianlitp)

## 联系我们

我们来自360信息安全部[0KEE Team](https://0kee.360.cn/)，如果你有安全工具或者安全系统开发经验，热衷于甲方安全建设，请投递简历到：zhanglu-it#360.cn、renyan-it#360.cn、zhusiyu1#360.cn。