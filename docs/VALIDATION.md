# 验证

## 自动化

```sh
go test ./...
go test -race -timeout 5m ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/derper-go
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/derper-go
```

本地 ACME 测试服务实际处理账户注册、订单、授权、CSR、证书签名及失败响应。Cloudflare 测试覆盖权限错误、响应大小、分页、令牌轮换、幂等与不确定写操作恢复。

DERP 测试使用上游客户端与真实 TLS/HTTP Upgrade/WebSocket 连接，验证双向数据、证书切换期间已有连接保持可用、MetaCert、STUN 事务和映射地址。本机验证使用临时 Unix socket 假服务，覆盖允许、拒绝、断开与超时。

CLI 校验和导出命令验证无网络/无状态写入；配置解码提供 fuzz 入口。systemd 单元应使用 systemd-analyze verify 检查。

## 额外回归

兼容补丁已针对固定 AnyTLS 基线的 certmgr/config 测试验证，新增测试确认关闭地址发布后仍能首次签发和续期，同时清理自己的 TXT。

在受限主机上可设置 GOMAXPROCS=2、go test -p 1 和磁盘 GOTMPDIR；竞态检测需要 CGO。所有测试数据与生产状态分离。

## 部署验收

模拟服务及回环测试不能替代真实公网和 tailnet 验收。正式迁移时至少核对：

1. Cloudflare 权限、实际 DNS 传播、受信任的生产证书链和域名。
2. 公网 TCP/UDP 可达、STUN 返回有效绑定响应。
3. 两台已授权设备经目标 Region 实际转发；未授权客户端被拒绝。
4. 同域名 A/AAAA 仅有一个管理者；其他 TXT 和其他区域配置保留。
5. 有效缓存下临时断开控制面、服务重启、失败恢复和回滚步骤。

生产切换与真实 CA 签发应在独立部署阶段执行，不属于本轮代码交付的验证结论。
