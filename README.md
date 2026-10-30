# derper-go

Go 实现的单二进制 DERP/STUN 中继，直接集成 Tailscale 服务端库，支持 Cloudflare DNS-01 自动签发、续期及 DNS 地址记录维护。

首版面向 Linux amd64/arm64，固定 Tailscale `v1.104.4`，需要 Go `1.27.3` 或更新的兼容工具链。

## 能力

- 原生 DERP、WebSocket DERP、STUN、探测及 captive-portal 响应。
- 默认通过本机 tailscaled 验证客户端；查询超时、未知节点或服务不可用时拒绝接入。
- ACME DNS-01，无需占用 TCP 80/443；自动续期通过不可变证书快照热更新。
- A/AAAA 地址记录自动维护，固定 DNS only；支持固定地址及 HTTPS IPv4 探测。
- 地址记录归属、显式接管、创建/更新响应丢失后的恢复；与 ACME TXT 生命周期独立。
- 离线配置检查、交互配置、诊断、证书导入、DERPMap 导出及 systemd 单元生成。
- 身份持久化、进程锁、原子证书写入、CA Retry-After 持久化及令牌文件轮换。

## 构建

```sh
go build -trimpath -o bin/derper-go ./cmd/derper-go
bin/derper-go version
```

或使用 `make build`。在低内存主机上使用 `GOMAXPROCS=2 go build -p 1`；磁盘上的 `GOTMPDIR` 可避免小容量 tmpfs 不足。

## 配置与运行

复制 [配置示例](examples/server.json)，修改域名、ACME 邮箱、公网地址和 Token 文件路径。Cloudflare Token 限定到对应 Zone，赋予 Zone:Read 与 DNS:Edit。JSON 中仅保存凭据引用。

```sh
bin/derper-go wizard --output derper-server.json
bin/derper-go check -c derper-server.json
bin/derper-go dns plan -c derper-server.json
bin/derper-go server -c derper-server.json
```

第一次启动会签发证书。已有有效缓存时可在 CA/Cloudflare 或凭据暂时不可用期间继续提供中继，后台维护失败写入日志。续期失败保留未过期证书；过期证书不用于新握手。

默认私有模式要求同机 tailscaled 已登录对应 tailnet，并能查询到接入节点。公开中继必须明确设置 `verification.mode=none`。

配置严格拒绝未知字段、重复字段和 null。相对路径以配置文件所在目录为基准。配置修改通过重启应用；ACME 续期自动生效。前台运行时自动重读凭据文件，systemd LoadCredential 的凭据副本需重启服务刷新。手动 TLS 模式的证书在启动时加载。

## 命令

| 命令 | 行为 |
| --- | --- |
| `server` | 持有状态锁并运行服务、证书和 DNS 后台任务 |
| `check` | 只读本地校验；不联网、不创建账户或状态 |
| `wizard` | 交互或通过参数生成配置；覆盖已有文件需 `--force` |
| `doctor` | 查询 DNS、TLS、STUN、tailscaled；不修改外部服务 |
| `dns plan` | 只读输出地址记录差异 |
| `dns apply` | 离线同步；可重复传入 `--adopt-record-id` 接管 A/AAAA |
| `cert status` | 查看证书序列号、有效期与有效状态 |
| `cert import` | 将现有证书链与私钥导入独立 ACME 缓存 |
| `cert renew` | 离线续期；`--force` 提前续期但仍遵守 CA Retry-After |
| `export-derpmap` | `--format policy` 输出策略片段，`derpmap` 输出原始映射 |
| `service render/install` | 输出/安装 systemd 单元；安装不启动或停止服务 |
| `version` | 显示应用、提交和上游版本 |

语法/配置错误退出码为 2，操作失败为 1，成功为 0。服务与修改状态的离线命令互斥；服务运行时自动续期，不应另设续期 cron。

## DNS 归属

`dns.mode` 支持 `off`、`observe`、`manage`，默认 `off`；示例和 wizard 显式启用 `manage`。

`manage` 创建记录时写入安装实例的归属标记。已有记录必须先核对地址、TTL、DNS only 状态，再明确接管：

```sh
bin/derper-go dns plan -c derper-server.json
bin/derper-go dns apply -c derper-server.json --adopt-record-id RECORD_ID
```

多记录、CNAME/NS 冲突、受管记录被外部修改或删除时停止写入并报告冲突。禁用某个地址族不会删除已有记录。需要更换配置域名时使用独立状态目录。公网地址探测失败保留已有记录。

使用动态 IPv4 时，导出的 DERPMap 通过域名解析，不固定一次探测得到的地址。未配置 IPv6 时导出 `IPv6: "none"`。

## 部署、迁移和验证

- [systemd 部署及旧 derper/AnyTLS 迁移](docs/DEPLOYMENT.md)
- [设计边界与审查记录](docs/DESIGN.md)
- [验证方法](docs/VALIDATION.md)
- [AnyTLS 地址记录管理开关补丁](compat/anytls-disable-address-records.patch)

`doctor` 的 TLS/STUN 成功只说明相应协议可达。私有 DERP 的实际转发应由两台已授权 tailnet 设备验证。

## 开发

```sh
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

测试使用本地 ACME/Cloudflare/LocalAPI 假服务、临时密钥和回环监听，不读取生产凭据。CI 检查格式、模块一致性、竞态、漏洞、CLI、systemd 和两种 Linux 架构。

MIT 许可；复用来源与上游许可证见 [NOTICE](NOTICE)。
