# 验证范围

## 本地回归

```sh
go test ./...
go vet ./...
```

低资源开发机可设置 `GOMAXPROCS=2 GOMEMLIMIT=200MiB`，并为 `GOTMPDIR` 指定磁盘上的临时目录，使用 `-p 1`。测试不读取生产 Token，不向真实 ACME 或 Cloudflare 发起写请求。

覆盖：

- 严格配置、最小 JSON、默认值和显式关闭、路径解析与无副作用检查。
- 真实本地 HTTP ACME/Cloudflare 假服务：签发、续期、重启、TXT 清理、取消、响应丢失和持久化 Retry-After。
- 证书原子更新、有效缓存无凭据启动、短期证书续期调度、SNI 与过期拒绝。
- 原生 DERP/WebSocket 转发、TLS MetaCert、STUN 事务和地址、准入超时与关闭取消。
- DNS 归属、批量接管验证、确认快照变更、外部修改与删除、丢失响应恢复、地址发现失败保留记录。
- 初始化只读预检、选择结果保存、显式条款、磁盘写入失败、安装失败恢复、排他运行锁交接、取消与 EOF。
- 重复初始化保留配置与身份，过期状态及 PID 复用不误报就绪，DNS 故障时 TLS 中继继续工作。

## CI

CI 运行格式和模块检查、全量 race、go vet、govulncheck、两个 Linux 架构的原生构建/运行、发行包及许可证检查。amd64 归档重建后逐字节对比；普通 CI 保留归档，标签发布复用同一份受检附件。`golang.org/x/net` 固定 v0.62.0；此前检查发现的 GO-2026-5932 位于未被本项目导入的 `x/crypto/openpgp`，应继续以 CI 的可达性分析为准，不能把模块存在等同于已构建程序受影响。

systemd 作业下载同次工作流的 amd64 发行包，并构建独立 Ubuntu 容器，在容器内真实执行 `init`、`service restart/stop/start`，核对服务用户、目录与密钥权限、Type=notify、443 占用时保存 8443、修改端口后重新生成权限、实际 TLS 探测、重复初始化和节点身份保留。使用本地自签测试证书、公开准入与关闭 DNS，避免使用真实云凭据。自动 ACME、Cloudflare 和私有准入分别由对应本地假服务测试验证。

容器测试脚本位于 `integration/systemd.sh`，要求专用标记文件和环境变量。不要在宿主机或生产机执行该脚本。完整测试环境由 `.github/workflows/ci.yml` 创建和销毁。

## 生产验证边界

本轮不进行 la3 切换，不停止旧 DERP/AnyTLS 服务，不改变生产 DNS。CI 的协议与服务验证不等同于跨公网的 Tailnet 转发验证。正式切换仍需按部署文档安排窗口，并从两台授权 Tailnet 设备确认真实 DERP 数据转发。

## Release 回归

`python3 -m unittest discover -s scripts -p 'test_*.py' -v` 验证版本格式、归档路径与类型、完整 SHA、ELF 架构、动态加载器拒绝、缺失架构、旧包混入，以及发布时的 API 错误、上传响应丢失、草稿恢复、标签移动、已公开附件防覆盖和预发布状态。发布脚本通过临时假服务接口运行这些测试，不创建真实 Release。

工作流由固定版本的 actionlint 校验。正式标签还经过完整 CI、GitHub 来源证明和上传回读；只有附件内容及远端标签再次核对成功后才公开草稿。流程和重试方法见 [RELEASING.md](RELEASING.md)。
