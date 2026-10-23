# Threat-Analysis-Handbook

## 简介

Threat-Analysis-Handbook 是一份面向实战的威胁检测知识库，按 MITRE ATT&CK 技术编号组织，主要覆盖 Web、Windows、Linux 三类场景，每篇文档包含 ATT&CK 技术、模拟测试、检测思路与检测所需数据源。

当前覆盖 **105 个 ATT&CK 技术（含子技术共 198 项 TID）**，共 337 篇文档。

## 目录结构

```
Windows/   Windows 终端检测（按战术目录：03初始访问 ~ 12命令与控制）
Linux/     Linux 终端检测（按战术目录）
Web/       Web 攻击检测（按年份目录：2020 ~ 2023）
```

## 规则说明

- 检测规则以 **Sigma 格式为主**（273 条，全部内嵌于文档的 YAML 代码块中）；Web 方向部分规则同时提供 Suricata 网络检测写法。
- 全部 273 条 Sigma 规则已通过 **pySigma 解析与 Splunk 后端转换（100%）**，id 全库唯一，可直接导入 SIEM 使用。
- 考虑到国内 Windows 日志策略配置现状，规则**不依赖 Sysmon**：`service: sysmon` 写法已全部改写为 Sigma 抽象 category（`process_creation` / `registry_event` / `network_connection` 等），可映射到安全日志 4688 等默认可得数据源。

## ATT&CK矩阵覆盖情况

![覆盖图](img/index.png)
