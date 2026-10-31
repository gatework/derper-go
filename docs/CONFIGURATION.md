# 运行配置

默认只需域名和证书邮箱。`init` 负责凭据输入、预检和保存；以下选项用于有明确需求的部署。

```json
{"domain":"relay.example.com","email":"ops@example.com"}
```

查看实际默认值：

```sh
derper-go config show --effective
derper-go config check
```

配置严格校验未知字段、重复字段、空值和互斥选项。所有时间使用带单位的字符串，如 `2s`、`15s`、`10m`；数字没有隐含单位。相对路径以配置文件目录为基准。密钥和 API Token 只接受文件或已有凭据来源，不放进 JSON。

## 中继与连接

| 字段 | 默认值 | 含义 |
|---|---|---|
| `relay.listen` | `:443` | HTTPS 监听地址，可用 `127.0.0.1:8443`、`[::1]:8443`；省略 IP 监听所有接口 |
| `relay.enabled` | `true` | 是否提供 DERP；关闭后可继续提供 bootstrap DNS，且不能导出为中继区域 |
| `relay.max_connections` | `2048` | TCP 总连接额度，包含握手、HTTP、原生 DERP 与 WebSocket；范围 1–60000 |
| `relay.connection_rate.per_second` | `0`，不限速 | 每秒接受的新 TCP 连接数，支持小数，最大 100000 |
| `relay.connection_rate.burst` | 启用限速时自动向上取整每秒速率，最多 60000 | 突发额度；与连接总量限制共享监听入口，达到任一限制后关闭新连接 |
| `relay.tcp.keepalive` | `10m` | 内核 TCP keepalive 间隔；`0s` 关闭 |
| `relay.tcp.user_timeout` | `15s` | TCP 数据未获确认时的内核超时；不是空闲连接寿命；`0s` 关闭 |
| `relay.tcp.write_timeout` | `2s` | 上游 DERP 的客户端写超时；`0s` 不设置，Mesh 连接按上游独立处理 |
| `relay.homepage` | 空白页面 | 使用 `blank` 或 HTTP/HTTPS 跳转地址；不接受 URL 内嵌凭据 |
| `http.port` | `-1`，关闭 | HTTP `/generate_204` 探测监听端口；启用时与 HTTPS 绑定同一 IP，不能使用同一端口 |
| `stun.enabled` | `true` | STUN 独立开关 |
| `stun.port` | `3478` | UDP 端口，与 HTTPS 绑定同一 IP |

TCP 时间设置范围为 `1ms` 至 `24h`，或显式 `0s`。连接速率限制默认不启用，以连接总量和准入并发额度保护资源；应根据实际重连规模设置速率及突发值。

HTTPS 始终使用 TLS。上游根据端口自动选择明文 HTTP 的行为不用于本项目中继监听；`http.port` 只提供探测响应。初始化可用 `--listen`、`--http-port` 指定地址和探测端口。未指定监听地址且 443 被占用时，初始化选择并保存 `:8443`；运行时不自动改端口。

## 客户端准入

| 字段 | 默认值 | 含义 |
|---|---|---|
| `admission.mode` | `tailnet` | `tailnet` 通过现有 tailscaled 验证；`controller` 使用外部准入服务；`public` 公开接入 |
| `tailscale.socket` | `/run/tailscale/tailscaled.sock` | 本地 tailscaled socket，仅 Tailnet 模式使用 |
| `admission.max_concurrent_checks` | `32` | 并行查询数，1–128；不大于请求总额度，未指定时取 32 与总额度的较小值 |
| `admission.max_requests` | `128` | 进行中及排队请求总额度，1–8192；组合准入的两阶段共享此额度 |
| `admission.timeout` | `3s` | 排队和查询共用总预算，范围 `100ms` 至 `3s` |
| `admission.url` | 无 | 控制器地址；填写时未指定模式会选择 `controller`；显式 `mode:tailnet` 时先查 Tailnet，再查控制器，两阶段共用 timeout。远端必须 HTTPS，本机回环允许 HTTP |
| `admission.fail_open` | `false` | 控制器故障时是否允许接入；仅作用于外部控制器故障，明确拒绝、主动取消和本地额度耗尽仍拒绝；控制器网络超时属于可按该选项处理的服务故障 |
| `admission.blocked_apps` | 空列表 | 拒绝客户端自行声明的应用名称，区分大小写；可信 Mesh 节点按上游规则豁免 |

所有新连接均实时验证，不缓存已完成的授权决定。Tailnet 模式只合并同一节点正在进行的查询；控制器请求保留完整节点公钥与来源 IP，不跨来源合并。应用名称不是身份凭据。

外部控制器接收上游 `tailcfg.DERPAdmitClientRequest` 格式的 POST JSON，返回 `{"Allow":true}` 或 `{"Allow":false}`。响应最多 4 KiB，不跟随重定向，不输出响应正文。`status --json` 可查看准入计数、明确拒绝及故障状态。初始化可用 `--admission`、`--admission-url`。

```json
{
  "domain":"relay.example.com",
  "email":"ops@example.com",
  "admission":{
    "mode":"controller",
    "url":"http://127.0.0.1:9090/verify"
  }
}
```

## 区域节点互联

```json
{
  "mesh":{
    "key_file":"mesh.key",
    "peers":[
      {"host":"peer.example.com"},
      {"host":"peer2.example.com:8443","dial":"192.0.2.8:8443"}
    ]
  }
}
```

将片段合并到完整配置。`host` 用于 HTTPS 主机名、证书验证及端口；`dial` 可指定实际连接目的地，省略端口则沿用 `host` 的端口。默认不进行 Mesh 连接，最多配置 32 个节点。所有互联节点必须使用同一份非零的 64 个小写十六进制字符（32 字节）共享密钥；可用 `openssl rand -hex 32` 生成，保存为 root 可读文件。systemd 使用 `LoadCredential=mesh-key:...` 将其交给服务用户。

共享密钥允许可信 Mesh 协议访问，应只分发给区域内可信中继。互联复用上游连接观察、节点路由和重连机制；服务关闭会取消连接观察、关闭客户端并等待任务退出。节点之间应相互配置连接，形成需要的互联拓扑；列表中的本机节点会按服务端身份识别后忽略并关闭自连接，不占用连接配额；`status` 报告当前 TLS 连接数量，真实跨节点转发由协议测试覆盖。

## 引导 DNS

```json
{
  "bootstrap_dns":{
    "names":["control.example.com"],
    "unlisted":[
      {"name":"rollout.example.com","rollout_record":"rollout-percent.example.com"}
    ]
  }
}
```

`GET /bootstrap-dns` 返回公开域名与地址映射；只有明确查询 `?q=rollout.example.com` 才可能返回对应隐藏域名。隐藏域名省略 `rollout_record` 时覆盖全部来源；指定时读取单条 `0`–`100` 的 TXT 百分比，以来源 IP 稳定分组，缺失、歧义或无效值按 0 处理。

最多配置 100 个域名，每 10 分钟后台刷新，单轮最多 1 分钟、4 个并行解析。请求只读取缓存，不解析用户传入的任意域名。临时解析失败保留最近一小时内的有效地址，并报告维护异常；隐藏域名的 TXT 检查失败时不放行隐藏响应。响应禁止共享缓存。

退役 DERP 但保留引导 DNS 时，设置 `relay.enabled:false` 并配置至少一个引导域名；按需要设置 `stun.enabled:false`。该模式不依赖 tailscaled，也不启动 Mesh。

## 与上游参数的对应关系

| 上游 `derper` | 本项目 |
|---|---|
| `-a` | `relay.listen` |
| `-accept-connection-limit/-burst` | `relay.connection_rate.per_second/burst` |
| `-derp` | `relay.enabled` |
| `-disallow-app-names` | `admission.blocked_apps` |
| `-home` | `relay.homepage` |
| `-http-port` | `http.port` |
| `-stun/-stun-port` | `stun.enabled/port` |
| `-tcp-keepalive-time/-user-timeout/-write-timeout` | `relay.tcp.keepalive/user_timeout/write_timeout` |
| `-verify-clients/-socket` | `admission.mode:tailnet`、`tailscale.socket` |
| `-verify-client-url/-fail-open` | `admission.mode:controller`、`admission.url/fail_open`；故障放行默认关闭 |
| `-mesh-psk-file/-mesh-with` | `mesh.key_file/peers`，使用结构化 `host/dial`，不使用斜杠元组 |
| `-bootstrap-dns-names/-unpublished-bootstrap-dns-names` | `bootstrap_dns.names/unlisted` |
| `-hostname/-acme-email` | `domain/email` |
| `-certmode/-certdir` | 自动 Cloudflare DNS-01 或 `certificate.file/key`；缓存由部署状态目录管理 |
| `-c/-version` | `--config`、`version` |

本轮范围为常用生产功能。ACE、GCP/EAB、IP 短期证书、setec 和实验性 `rate-config` 未开放为配置；严格校验会拒绝这些字段。现有 Cloudflare DNS-01 自动证书和域名记录发布继续独立运行。

## 安全热重载

修改配置后执行 `sudo derper-go service reload` 或 `sudo systemctl reload derper-go`。前台实例使用 `derper-go config reload -c config.json`，也接受 SIGHUP。命令等待守护进程确认，失败时返回原因，原运行配置继续有效。控制通道为服务私有目录中的 0600 Unix socket，不向公网开放。

可以热更新 `relay.max_connections`、`relay.connection_rate`、`relay.homepage`、`admission.timeout`、已有控制器的 `url/fail_open`，以及手动证书内容/路径。降低连接上限不关闭已有连接；仅阻止超过新额度的新连接。进行中的授权查询沿用原控制器快照；自动证书续期仍由原维护循环负责。

所有值及手动证书通过检查后才应用；部分写入的证书/密钥、非法配置或结构性变更均拒绝应用。监听、准入模式、增删控制器、请求/并行额度、Mesh、bootstrap DNS、DNS 发布、CA 和凭据来源变更需要 `service restart`。重载不会刷新 systemd 的 LoadCredential 副本，Token 轮换仍需重启。
