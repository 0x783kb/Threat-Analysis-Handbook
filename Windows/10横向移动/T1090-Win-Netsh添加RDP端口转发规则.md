# T1090-Win-Netsh添加RDP端口转发规则

> 引入自 SigmaHQ 官方库：`rules/windows/process_creation/proc_creation_win_netsh_port_forwarding_3389.yml`（引入日期 2026-10-26，规则 id 与官方保持一致以便溯源）

## 描述

检测通过 **netsh.exe** 配置 3389 端口（RDP）转发规则的行为（ATT&CK T1090 代理/中转）。典型命令如：

```
netsh interface portproxy add v4tov4 listenport=3389 connectaddress=<内网IP> connectport=3389
```

攻击者在拿到内网一台跳板机后，常用 netsh 的 portproxy 功能把 3389 流量中转到更深的内网主机，实现**不落工具的横向移动与端口中转**（对比 frp/Earthworm 等需上传文件，netsh 是系统自带、完全白利用 LOLBin）。FireEye 报告也记录了攻击者利用该手法绕过网络访问限制。

规则等级 **high**，官方 falsepositives 为合法管理行为——运维中 netsh portproxy 做端口映射确实存在，需结合白名单收口。

## 检测日志

- **Windows 安全日志**（国内默认可得）：
  - Event ID 4688：进程创建，需要启用「审核进程创建」并加入命令行。规则核心字段为 `Image`（进程路径 `\netsh.exe`）与 `CommandLine`（含 3389 等关键字），4688 正文均覆盖。
- **Sysmon 日志**（如已部署）：
  - Event ID 1：进程创建，直接匹配 `Image|endswith '\netsh.exe'`。

**⚠️ 国内适配标注（审核重点）**：规则 `selection_img` 包含 `OriginalFileName: 'netsh.exe'` 分支——该字段为 **Sysmon 独有**（Event ID 1 的 OriginalFileName），4688 环境不可得。但它是与 `Image|endswith` 并列的 **OR 分支**，仅用于对抗 netsh.exe 被改名/伪造的伪装场景；4688 环境下 `Image|endswith` 分支单独即可满足匹配，不影响规则落地。规则**不硬依赖** OriginalFileName。

## 检测规则/思路

### Sigma规则

```yaml
title: RDP Port Forwarding Rule Added Via Netsh.EXE
id: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63
status: test
description: Detects the execution of netsh to configure a port forwarding of port 3389 (RDP) rule
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
author: Florian Roth (Nextron Systems), oscd.community
date: 2019-01-29
modified: 2023-02-13
tags:
    - attack.lateral-movement
    - attack.command-and-control
    - attack.t1090
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\netsh.exe'
        - OriginalFileName: 'netsh.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' i'
            - ' p'
            - '=3389'
            - ' c'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activity
level: high
```

### 建议

- `selection_cli` 用 `contains|all` 匹配 ` i`/` p`/`=3389`/` c` 四个片段（对应 `interface portproxy ... =3389 ... connect*`），是模糊匹配，正常运维的 netsh 命令一般不会同时凑齐四个片段；但堡垒机批量做端口映射的场景需先加白。
- 命中后重点排查：`netsh interface portproxy show all` 确认当前转发表、转发目标 connectaddress 是否为敏感内网资产、执行账户与登录来源（4624）是否异常。
- 配套检测：同类手法还可关注 `netsh advfirewall` 添加 3389 放行规则（T1686.003）与 portproxy 监听的本地网络连接（Sysmon Event ID 3）。

## 参考推荐

- FireEye 原理文章：https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
- MITRE ATT&CK T1090：https://attack.mitre.org/techniques/T1090/
