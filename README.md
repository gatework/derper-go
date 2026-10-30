# derper-go

一个 Go 二进制完成 DERP/STUN 中继、Cloudflare DNS 发布和 ACME 证书续期。默认通过本机已登录的 tailscaled 验证节点身份；原生 DERP、WebSocket DERP、STUN 和 TLS MetaCert 均复用 Tailscale 上游实现。

支持 Linux amd64/arm64，需要 Go 1.27.3，当前依赖 Tailscale v1.104.4。

## 获取发行版

在 [Releases](https://github.com/gatework/derper-go/releases) 下载 Linux amd64 或 arm64 归档与 `checksums.txt`。校验、解压后即可运行包内的 `derper-go init`；归档包含配置示例、部署说明和依赖许可证。

推送 `vMAJOR.MINOR.PATCH` 标签会自动完成 CI、构建、校验并发布 GitHub Release；`-rc.1` 等标签自动标记为预发布。详见 [自动发布与来源验证](docs/RELEASING.md)。

## 开始使用

```sh
go build -o derper-go ./cmd/derper-go
sudo ./derper-go init
```

向导检查已有 tailscaled，询问中继域名、证书联系邮箱和 Cloudflare API Token。Token 隐藏输入，需要对应区域的 **Zone:Read** 和 **DNS:Edit** 权限。向导自动查找区域与公网 IPv4，检查端口和 Tailnet 区域编号，并展示安装、DNS 接管及证书机构条款摘要。确认后创建独立的 `derper-go` 用户，保存配置，安装并启动 `derper-go.service`。

配置通常只有两项，见 [示例](examples/config.json)：

```json
{
  "domain": "relay.example.com",
  "email": "ops@example.com"
}
```

默认 HTTPS 使用 443；初始化时若已被占用，会在摘要中建议 8443，并在确认后保存。启动服务始终使用保存的端口。默认 STUN 使用 UDP 3478；HTTP 80 探测默认关闭。

```sh
sudo derper-go status
sudo derper-go tailnet config
```

将输出的 `derpMap` 片段合并到 Tailnet 策略。程序不会修改 Tailnet 策略或防火墙。放行已选择的 HTTPS TCP 端口及 UDP 3478，并用两台已授权的 Tailnet 设备验证实际转发。

## 自动化与前台运行

非交互初始化明确提供参数、安装批准和证书条款接受：

```sh
sudo ./derper-go init \
  --domain relay.example.com --email ops@example.com \
  --token-file /secure/cloudflare.token --yes --accept-terms
```

Token 也可通过 `CLOUDFLARE_API_TOKEN` 传入，不支持明文 Token 命令参数。`--yes` 批准安装摘要，包括预览中可接管的 DNS 记录；它不代表接受证书机构条款。

- `init --no-start`：安装并启用服务，暂不启动；随后使用 `service start`。
- `init --no-service`：只生成前台配置，默认写入当前目录 `config.json`；按输出的 `run` 命令启动。
- 重复 `init`：已完成部署显示状态，保留配置、节点身份和证书。修改已有配置后使用 `service restart`，会同步更新所需端口权限和凭据来源。
- 初始化中断：修复错误后重试同一命令，继续尚未完成的准备工作。若服务已准备但启动失败，使用 `service start`；DNS 暂时失败时服务保留并自动重试。
- 终端直接运行 `derper-go`：首次进入向导，已有默认配置时显示状态；非终端无参数只显示帮助。

## 默认值与可选配置

配置只保存意图；凭据、条款接受、安装进度、证书缓存和 DNS 归属分别保存在受保护的文件中。未知字段、重复字段和 `null` 会被拒绝；相对路径以配置文件目录为基准。

| 可选字段 | 默认与含义 |
| --- | --- |
| `port` | 443；初始化可保存建议的 8443 |
| `region` | 900；初始化从本机 DERPMap 的 900–999 中选择空闲编号并保存 |
| `access` | `tailnet`；显式 `public` 才允许公开接入 |
| `certificate.ca` | `letsencrypt`；可选 `staging` 或 HTTPS ACME 目录 |
| `certificate.file`、`certificate.key` | 同时提供时使用手动 PEM 证书，邮箱可省略；手动证书更新后重启 |
| `dns.publish` | `true`；设置 `false` 关闭 A/AAAA 发布，ACME TXT 仍独立维护 |
| `dns.ipv4` | `auto`；可用公网 IPv4 固定地址或 `off` |
| `dns.ipv6` | 默认不发布；填写公网 IPv6 后发布 AAAA |
| `tailscale.socket` | `/run/tailscale/tailscaled.sock` |
| `cloudflare.zone` | 自动发现；必要时填写 Zone ID |
| `cloudflare.token_file` | 配置目录下的 `cloudflare.token`；可指定其他凭据文件 |
| `stun.enabled`、`stun.port` | `true`、3478 |
| `captive_portal` | `false`；开启后监听 HTTP 80 的 `/generate_204` |
| `log_level` | `info`；可用 `debug`、`warn`、`error` |

IPv4 探测依次使用 ipify 和 AWS Check IP 的 HTTPS 接口，强制 IPv4、限制超时和响应大小。探测失败保留此前记录；不会自动发布探测到的 IPv6。动态 IPv4 的 Tailnet 配置使用域名解析，不写死探测结果。

## 运维命令

| 命令 | 用途 |
| --- | --- |
| `run` | 前台运行；只有该命令进入守护进程逻辑 |
| `status [--json]` | 分别报告中继就绪、证书、DNS 和 Tailnet 状态 |
| `doctor [--json]` | 只读检查 DNS、TLS、STUN 与 tailscaled |
| `tailnet config [--format derpmap]` | 导出策略片段或原始 DERPMap |
| `config show`、`config check` | 查看最小配置；检查配置及本地证书，不联网或创建状态 |
| `dns plan`、`dns apply [--yes]` | 预览；重新检查确认快照后离线发布 |
| `certificate status` | 查看当前证书有效期与序列号 |
| `certificate import --file cert.pem --key key.pem` | 导入现有证书到自动续期缓存 |
| `certificate renew [--force]` | 离线续签；遵守 CA Retry-After |
| `service render` | 输出 systemd 单元 |
| `service start/stop/restart/logs` | 操作独立的 `derper-go.service` |

命令使用 `-c` 指定配置；前台部署可用 `--state-dir` 指定状态目录。退出码：成功 0、操作或配置错误 1、命令语法错误 2、运行取消 130。服务和离线写操作共用排他状态锁；服务自动续期，无需额外 cron。

服务使用 `Type=notify`，证书可用且 TLS 接收循环已启动才发送就绪通知。DNS 发布在此之后进行；DNS 发布失败会让首次初始化返回错误，同时保留可用中继并重试。已有有效证书时，Cloudflare/CA 暂时不可用不阻塞中继启动。证书续期以原子快照生效；过期证书拒绝新握手。

## DNS 记录接管

A/AAAA 始终使用 DNS only。初始化或 `dns apply` 会展示将要接管的记录，记录 ID 由程序保存，无需手工填写。确认后若地址、TTL、代理或注释变化，拒绝写入；已有所有者注释、多条同类型记录、CNAME/NS 冲突需先人工处理。正常维护也拒绝覆盖外部修改或重建已被外部删除的受管记录。关闭某个地址族不会删除已有记录。

## 开发与部署说明

```sh
go test ./...
go test -race -timeout 5m ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

CI 验证工作流、发布故障恢复、竞态、模块一致性、漏洞，以及 amd64/arm64 原生构建和运行；使用同一份发行包在独立 systemd 容器验证实际安装、就绪、权限、重启和身份保留。本地测试使用回环假服务与临时密钥。

- [部署与 la3 迁移边界](docs/DEPLOYMENT.md)
- [模块设计与审查改进](docs/DESIGN.md)
- [验证范围](docs/VALIDATION.md)
- [AnyTLS 地址记录开关补丁](compat/anytls-disable-address-records.patch)

MIT 许可；上游来源及许可证见 [NOTICE](NOTICE)。

连接资源默认有界，无需额外配置：最多 2,048 个 TCP 连接（包括 TLS 握手、HTTP 与已升级 DERP），最多 32 个并行 Tailnet 查询、128 个进行中或等待中的准入请求。排队和查询共用 3 秒时限；查询完成后不缓存授权结果。需要调整时只添加：

```json
{
  "relay": { "max_connections": 2048 },
  "tailscale": { "max_concurrent_checks": 32 }
}
```

上述片段合并到现有配置；域名、邮箱等原有设置继续有效。连接数可设为 1–60000，并行查询可设为 1–128，省略或 0 使用默认值。上限保护资源，并不承诺达到对应连接数时的吞吐。

`status --json` 增加运行阶段、连接数、准入计数和 `certificate_cleanup`。启动签证期间每 10 秒持续心跳；超过 30 秒未更新会标记过期。服务状态放在 `/run/derper-go`，自定义前台部署放在状态目录下的 `run/`；身份、证书及恢复日志继续保存在原位置。
