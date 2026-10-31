# 变更记录

## v0.2.0

- 保留官方 DERP 身份并复用匹配的单节点 Tailnet 区域；准备阶段可验证原 HTTPS 服务身份，迁移不自动停止旧服务，也不提前启用新服务。
- 初始化可导入有效证书缓存，同时保留 Cloudflare DNS-01 自动续期。
- 支持先验证 Tailnet、再调用外部准入控制器；控制器故障放行不会绕过 Tailnet 拒绝。
- 增加可调整的准入请求总额度 `admission.max_requests`，默认仍为 128。
- 增加同步确认的 `config reload`、`service reload`、systemd reload 与 SIGHUP。连接额度/速率、主页、现有控制器策略、验证预算和手动证书可热更新；现有 DERP 连接保持运行。结构性变更或无效证书拒绝应用。
- 不包含新的监控、指标或调试接口。监听、准入模式/后端增删、Mesh、DNS 发布和凭据变更仍需重启。

从 v0.1.0 升级时，必须先按 `docs/DEPLOYMENT.md` 转换旧配置字段并备份状态，再刷新 systemd 单元。旧版本不支持 reload，首次升级仍需重启。发行流程不升级现网服务。

## v0.1.0

首个正式版本：DERP/STUN、Cloudflare DNS-01 自动证书与地址记录发布、Tailnet 准入、初始化向导、systemd 安装、诊断及双架构自动发行。
