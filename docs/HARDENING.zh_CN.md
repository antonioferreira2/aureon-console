# 加固评估

AUREON 的评估是本机只读观察；它不是认证、渗透测试，也不能证明服务可从外部访问。应用不会执行建议或更改被审计主机的运行配置。只有 AUREON 自己的历史数据库和用户明确请求的报告会被写入。

## 当前检查范围

检查包括有效 SSH 设置及代表性 `Match` 上下文、本机防火墙证据、UID 0 账户、sudo 路径权限、默认密码老化策略、敏感账户与 SSH 主机密钥文件的元数据（不读取密钥内容）、`/tmp` 挂载选项、journald/audit/logrotate 证据、SELinux/AppArmor 与选定内核参数、Fail2ban jail 清单、受限的 Docker/Podman 容器检查、重启标记、APT/DNF/zypper 本地缓存安全更新查询、通配地址监听、时间同步和有限的备份证据。

每项检查有稳定 ID、领域、预期状态、严重性/权重、数据源、证据、限制、建议和验证步骤。结果为 `PASS`、`FAIL`、`UNKNOWN`、`NOT_APPLICABLE` 或 `ERROR`。缺失或不可读的数据不会被视为安全。若任何适用且非信息性检查为未知或出错，则不显示分数；严重失败会将总分限制为 25。分数不是合规认证或安全保证。

诸如 `MaxAuthTries <= 6` 和 `/tmp` 挂载标志是启发式标准，不是通用政策。变更前应结合证据及运行需求进行独立审查。AUREON 不读取私钥内容、不刷新软件包索引、不安装软件、不重载服务，也不提升权限。更新查询只使用本地已有索引；索引新鲜度按 14 天启发式判断。Alpine `apk` 的离线模拟不能识别安全公告，因此结果保持 `UNKNOWN`。容器检查最多覆盖检测到的 Docker/Podman runtime 中合计 100 个运行中及已停止的容器，且只接受十六进制 ID。复杂 nftables 规则、有顺序的 iptables 规则、SSH 通配符/组/重叠 `Match` 以及备份可恢复性，除非证据充分，否则保持 `UNKNOWN`。

本机规则、监听端口或工具安装状态都不能证明互联网可达性；NAT、路由、云安全组及上游防火墙可能改变实际暴露情况。请查看每项检查的证据、来源和限制。

## 命令与历史记录

```bash
aureon assess --json
aureon assess --output assessment.json
aureon assess --format csv --output assessment.csv
aureon assess-history --json
aureon assess-compare 1 2 --json
```

每次 CLI `aureon assess` 会将快照写入 AUREON 本地 SQLite 历史数据库；打开或刷新 TUI 评估面板不会创建历史记录。比较使用稳定检查 ID；缺失检查或不可用的分数不会被误认为有所改善。JSON/CSV 报告包含定义、结果、证据、限制、建议及验证信息；支持的平台上导出文件权限为 `0600`。

数据库 schema 版本 2 增加 `assessments` 表并保留既有事件；当前检查定义版本为 6。升级前应按常规备份本地数据库。被审计服务器的数据不会被修改。

## 语言

界面支持英语 (`en`)、欧洲葡萄牙语 (`pt_PT`，`pt` 作为兼容别名)、西班牙语 (`es`)、法语 (`fr`)、意大利语 (`it`)、简体中文 (`zh_CN`) 和俄语 (`ru`)。在 `config.toml` 设置 `language`，或使用 `AUREON_LANGUAGE` 环境变量；不支持的值回退为英语。主机证据和原始命令输出保留源语言以保持准确性。自动化测试检查主 TUI 面板的固定标签翻译。
