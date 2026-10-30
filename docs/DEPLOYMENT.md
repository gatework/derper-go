# 部署与迁移

## 新部署

准备一台 Linux/systemd 主机。默认私有模式需要已有 tailscaled 正常运行并登录目标 Tailnet；程序只检查并给出 `tailscale up` 等指引，不负责安装或管理 tailscaled。明确需要公开中继时使用 `init --access public`。

构建或取得对应 Linux 架构的二进制，然后执行：

```sh
sudo ./derper-go init
sudo derper-go status
sudo derper-go tailnet config
```

摘要确认后，安装目录如下：

| 路径 | 内容和权限 |
| --- | --- |
| `/usr/local/bin/derper-go` | 安装的程序，0755 |
| `/etc/derper-go/config.json` | 最小配置，root:derper-go，0640 |
| `/etc/derper-go/cloudflare.token` | root 持有的 Token，0600；systemd LoadCredential 提供服务私有副本 |
| `/etc/derper-go/certificate.pem`、`certificate.key` | 使用手动证书时复制到此，root:derper-go，0640 |
| `/var/lib/derper-go` | 独立服务用户持有，0700；身份、证书、条款、安装和 DNS 日志 |
| `/etc/systemd/system/derper-go.service` | 独立 systemd 单元，Type=notify |

HTTPS 默认选择 443，占用时建议 8443。两者都被占用时退出并提示 `--port`。初始化选择的端口与自定义中继区域固定保存在配置中；运行时不改端口或区域编号。STUN 默认 UDP 3478；监听冲突会在 ACME 下单及地址记录发布之前返回错误。HTTP 80 默认不启用。

首次自动签发可等待 DNS 传播；systemd 启动超时为 15 分钟。TLS 服务进入接收循环后才报告就绪，然后进行 DNS 发布。`init` 还检查 DNS 与 Tailnet 状态，不能仅凭 `systemctl is-active` 判断发布已经成功。

导出的 Tailnet 策略片段不会自动写入控制台。合并时保留原有区域，并确认防火墙开放选定的 TCP 端口和 UDP 3478。`doctor` 检查 DNS、可信 TLS、STUN 和本地 tailscaled；真实 DERP 转发仍需两台已授权的 Tailnet 设备验证。

## 可恢复初始化

安装前先读取网络与服务状态，并展示将要修改的内容。确认后的 `setup.json` 保存所选配置、CA 条款接受、DNS 接管快照及阶段，Token 不进入该记录。证书账户、DERP 节点身份和 DNS 所有权均独立存储。

初始化准备阶段出错后，修复原因并重试同一命令。已落盘的身份与证书会保留；配置在确认后被其他进程修改时拒绝继续。系统服务启动前释放运行状态锁，守护进程再取得该锁。

- `approved`：已确认，准备尚未完成；重复 `init` 继续准备。
- `prepared`：配置已准备，或服务已安装；`--no-start` 停在此处。启动失败后使用 `service start`。
- `ready`：首次服务就绪、DNS 和 Tailnet 检查完成。

运行状态另由 `status.json` 记录。读取时校验进程锁、PID、系统启动标识和进程启动时间，过期快照不会被当作运行中的健康服务。

## 证书与凭据

ACME 使用 DNS-01，不需要 HTTP 80。生产和 staging 使用独立缓存；新 CA 的条款接受不能沿用旧 CA 记录。需要切换 CA 时先使用独立配置和状态目录初始化，确认结果后再安排服务变更。

有效缓存允许在 Cloudflare/CA 暂时故障期间继续提供中继。续期失败显示为证书维护异常，未过期证书仍可用；过期证书拒绝新 TLS 握手。TLS 热更新只发生在完整证书原子写入成功后。

手动证书可用 `init --certificate cert.pem --key key.pem`，不需要 ACME 邮箱或条款；若仍发布 DNS，则仍需 Cloudflare Token。手动证书文件在启动时读取，更新后重启。

systemd 启动时要求 LoadCredential 的源文件存在且可读；有效缓存不能绕过 systemd 对缺失凭据文件的检查。凭据内容无效或 Cloudflare API 不可用时，已有有效证书仍可投入服务。

Cloudflare Token 轮换时原子替换凭据文件。前台运行按请求重读文件；systemd 使用启动时的 LoadCredential 副本，轮换后执行 `sudo derper-go service restart`。请备份受保护的整个状态目录，尤其 `identity.json` 和 `certificates/`；不要公开 Token、账户私钥和节点身份。

## la3 现网迁移边界

本轮代码交付不执行 la3 的正式切换。现有 `derper.service`、`anytls.service`、`/etc/derper` 和 `/var/lib/derper` 继续由原部署管理。不能直接在这些路径运行新向导；新程序默认使用独立命名空间。

已确认的原部署约束：AnyTLS 占用 TCP 443，旧 DERP 使用 TCP 8443 与 UDP 3478，地址记录原由 AnyTLS 维护。因此新程序的默认端口选择会报告冲突，不能通过改一个默认值直接并行接管全部功能。

另行切换时应按以下顺序制定停机、验证及回滚窗口：

1. 备份旧 unit、配置、节点身份、证书与 DNS 记录快照，记录服务原启用状态。
2. 为新程序准备独立目录和明确的端口安排。保留原 DERP 节点私钥时，将受保护的上游身份 JSON 导入新 `identity.json`，并在离线状态核对公钥；不要让首次 `init` 生成的身份覆盖原身份。
3. 若要复用有效证书，使用 `certificate import --file ... --key ...` 导入对应自动续期缓存；验证域名和有效期。
4. 审查 [AnyTLS 补丁](../compat/anytls-disable-address-records.patch)，禁止旧进程继续维护同一 A 记录。该补丁仅针对参考版本的 A 记录发布，不能据此假定它管理 AAAA。
5. 确定唯一 DNS 写入方，通过新程序预览并明确接管匹配的记录。已有所有权注释或冲突先人工核对处理。
6. 在约定窗口交接监听端口，验证 TLS、STUN、原生及 WebSocket DERP、Tailnet 授权与拒绝行为，并从两台授权节点测试转发。
7. 只有上述验证完成后才修改 Tailnet 发布配置或长期启用状态；保留恢复旧服务、旧 DNS 和旧策略的步骤。

新程序不会停止旧服务、修改其文件或自动写入 Tailnet 策略。测试中所有安装与服务重启均在独立容器内完成。

## 从 v0.1.0 升级

本轮改进不自动升级运行中的服务。安排维护窗口后，先备份配置和整个状态目录，再使用经过 CI 的发行包替换程序；使用 `config check` 检查原有配置，`service render` 审阅新的单元，最后通过 `service restart` 更新单元并重启。

- 原有最小配置仍可读取；新限额字段均有默认值。回退到 v0.1.0 前需删去其不认识的 `relay` 和 `tailscale.max_concurrent_checks`。
- 不重新执行签发、创建身份或接管 DNS。`identity.json`、证书缓存、DNS 归属与安装日志保持兼容。旧版不会处理新的清理退避日志，遇到限流时优先修复或等待，不应立即回退重试。
- systemd 新增 `RuntimeDirectory=derper-go`；状态移到 `/run/derper-go/status.json`，读取器仍兼容旧位置。服务停止后运行目录可被 systemd 清理；持久状态不受影响。
- 新单元移除了固定 `GOMEMLIMIT=96MiB`。需要内存预算时，通过 `systemctl edit derper-go` 的 `[Service]` / `Environment=GOMEMLIMIT=256MiB` 设置，并根据连接规模与实际 GC 数据调整。该值只是示例，不能替代容量验证。
- gz 的 `10-credentials.conf` 兼容覆盖文件与新单元中的无引号 `LoadCredential` 一致，可先保留。确认新单元已生效且凭据读取成功后再安排清理覆盖文件；不要删除 Token 或更改其权限。
- 已批准、处于 `prepared` 的系统服务安装可通过再次执行 `init` 继续启动。`--no-start` / `--no-service` 仍保留其原有意图；恢复前核对配置与已批准安装一致。

升级后核对身份、公钥、证书、DNS 归属和 Tailnet 区域保持一致，再从两台授权设备验证实际转发。gz 的固定 IPv4 和 sing-box 回包路由继续保留，不能改为通过代理出口自动发现地址。
