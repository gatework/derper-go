# derper-go

Go DERP/STUN 中继，集成 Cloudflare DNS 发布、ACME 证书和已有 tailscaled 准入。先阅读 README.md、docs/DESIGN.md 与 docs/VALIDATION.md。

## Working conventions

- 保持领域模块边界，协议实现复用 Tailscale；配置保存用户意图，凭据、身份和恢复日志独立存放。
- 使用临时密钥与本地假服务测试。integration/systemd.sh 和完整负载工具只在隔离环境运行，生产服务切换与 DNS 修改另行安排。
- Go 改动运行对应行为测试；提交前完成 go test、race、vet、Staticcheck 及相关发行检查。验证命令和低资源设置见 docs/VALIDATION.md。

## Agent skills

### Issue tracker

Issue 与规格使用 GitHub Issues：gatework/derper-go。操作约定见 docs/agents/issue-tracker.md。

### Triage labels

使用 needs-triage、needs-info、ready-for-agent、ready-for-human、wontfix。含义见 docs/agents/triage-labels.md。

### Domain docs

单项目领域文档：根目录 GLOSSARY.md 与 docs/adr/，按实际需要创建。读取规则见 docs/agents/domain.md。
