# T1649-Win-Certify证书滥用工具执行

> 引入自 SigmaHQ 官方库：`rules/windows/process_creation/proc_creation_win_hktl_certify.yml`（引入日期 2026-10-27，规则 id 与官方保持一致以便溯源）

## 描述

检测 **Certify**（GhostPack 出品）的执行行为。Certify 是针对 **Active Directory 证书服务（AD CS）** 的滥用工具，可用于枚举存在配置缺陷的证书模板、申请可用于身份伪造的证书（如 ESC1–ESC8 系列 AD CS 攻击），对应 ATT&CK **T1649 窃取或伪造身份验证证书**。

AD CS 攻击近年在国内外红队/勒索组织活动中极为常见——一旦拿到域内任意账户凭据，攻击者可借配置不当的证书模板直接申请**域管理员等价的证书**，绕过常规的密码策略与 MFA。Certify 与 Certipy（Linux 侧）、Cert synchronizer 类工具共同构成 AD CS 攻击链的标配。

该规则基于两条路径检测：
1. **PE 元数据特征**（`Image` 文件名 / `OriginalFileName` / `Description`）——对抗改名场景；
2. **Certify 特有子命令与参数**（`cas` / `find` / `request` / `/template:` / `/vulnerable` 等）——纯命令行特征，改名也躲不掉。

规则等级 **high**，官方 falsepositives 为 Unknown——Certify 属纯攻击工具，正常业务不会出现，但需注意安全团队自己的授权红队演练也会触发。

## 检测日志

- **Windows 安全日志**（国内默认可得）：
  - Event ID 4688：进程创建，需启用「审核进程创建」并开启命令行审计。规则命令行分支依赖 `CommandLine` 字段，4688 正文覆盖（命令行审计开启后 4688 的 NewProcessName 对应 `Image`）。
- **Sysmon 日志**（如已部署）：
  - Event ID 1：进程创建，可完整匹配 `Image|endswith '\Certify.exe'` 及 `OriginalFileName`、`Description` 等 PE 元数据字段。

**⚠️ 国内适配标注（审核重点）**：规则 `selection_img` 中 `OriginalFileName: 'Certify.exe'` 与 `Description|contains: 'Certify'` 为 **Sysmon 独有字段**（4688 不可得）。但它们是与 `Image|endswith` 并列的 **OR 分支**，仅用于对抗工具改名的场景；且规则 condition 为 `selection_img or all of selection_cli_*`——即使 `selection_img` 整体失效，Certify 的子命令/参数（`.exe request `、` /template:` 等）在 4688 的 `CommandLine` 中仍可独立命中（需 selection_cli_commands 与 selection_cli_options **同时**满足）。规则**不硬依赖** Sysmon 独有字段。

## 检测规则/思路

### Sigma规则

```yaml
title: HackTool - Certify Execution
id: 762f2482-ff21-4970-8939-0aa317a886bb
status: test
description: Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments.
references:
    - https://github.com/GhostPack/Certify
author: pH-T (Nextron Systems)
date: 2023-04-17
modified: 2023-04-25
tags:
    - attack.discovery
    - attack.credential-access
    - attack.t1649
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\Certify.exe'
        - OriginalFileName: 'Certify.exe'
        - Description|contains: 'Certify'
    selection_cli_commands:
        CommandLine|contains:
            - '.exe cas '
            - '.exe find '
            - '.exe pkiobjects '
            - '.exe request '
            - '.exe download '
    selection_cli_options:
        CommandLine|contains:
            - ' /vulnerable'
            - ' /template:'
            - ' /altname:'
            - ' /domain:'
            - ' /path:'
            - ' /ca:'
    condition: selection_img or all of selection_cli_*
falsepositives:
    - Unknown
level: high
```

### 建议

- 命令行分支要求子命令与参数**同时出现**（如 `Certify.exe find /vulnerable`），误报率低；但注意域内运维若使用 `find /domain:` 之外的同类 AD CS 巡检脚本，关键字可能撞车，命中后结合进程签名与父进程研判。
- 命中后重点排查：执行账户是否为普通域用户（AD CS 攻击通常不需要特权账户）、目标 CA 与证书模板、随后是否有 `certreq`/`Rubeus asktgt` 等证书换票行为。
- 配套加固：对照微软 ESC1–ESC8 清单排查本域证书模板（`certipy find -vulnerable` 或 PingCastle 的 AD CS 评估）。
- 同族工具：Linux 侧 Certipy（官方另有 `proc_creation_win_hktl_certipy.yml`，本次未引入，可作后续候选）。

## 参考推荐

- Certify 项目主页：https://github.com/GhostPack/Certify
- Microsoft「Certified Pre-Owned」AD CS 滥用白皮书：https://post-cs.li/ADCS-Attack-Ebook
- MITRE ATT&CK T1649：https://attack.mitre.org/techniques/T1649/
