# 部署与迁移

## 准备

运行环境为 Linux + systemd。部署前准备已登录 tailnet 的 tailscaled、Cloudflare Token 和域名。默认监听 TCP 8443、UDP 3478，HTTP 监听关闭。公网防火墙应允许配置的 TCP/UDP 端口。

创建专用账户和配置目录（账户已存在时沿用）：

```sh
sudo useradd --system --user-group --home-dir /var/lib/derper --shell /usr/sbin/nologin derper
sudo install -d -m 0750 -o root -g derper /etc/derper
sudo install -d -m 0700 -o derper -g derper /var/lib/derper
sudo install -m 0755 bin/derper-go /usr/local/bin/derper-go
sudo install -m 0640 -o root -g derper derper-server.json /etc/derper/server.json
sudo install -m 0600 cloudflare.token /etc/derper/cloudflare.token
```

Token 文件应只有令牌文本和可选的末尾换行。systemd 使用 [LoadCredential](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredential=ID[:PATH]) 在启动时复制凭据交给服务；替换源文件后需重启服务刷新副本。普通前台运行时，调用用户需要读取配置中的 Token 文件，程序会在每次请求时重新读取。

应用可凭有效证书缓存启动，但 systemd 仍要求 LoadCredential 指定的源文件存在且可读；凭据内容无效或 API 不可用不会中断仍持有有效证书的中继。

如果需要自动签发，配置中明确接受相应 CA 条款。staging 使用其独立 directory_url，对应独立缓存；staging 证书不可用作生产信任链。

## systemd

```sh
sudo /usr/local/bin/derper-go check -c /etc/derper/server.json
sudo /usr/local/bin/derper-go service render -c /etc/derper/server.json
sudo /usr/local/bin/derper-go service install -c /etc/derper/server.json
sudo systemctl enable --now derper-go.service
journalctl -u derper-go.service -f
```

service install 仅写入单元并执行 daemon-reload，要求账户、二进制、配置与凭据已就绪。已有单元需 --force 才能替换。模板要求 state_dir=/var/lib/derper，配置及手动证书放在 /etc 等服务可读路径，不能放在受 ProtectHome 隔离的 home 目录。

Type=simple 的 active 状态不等同于首次签发完成。应等待日志中的 relay ready，再执行 doctor 和实际中继验证。证书有效但 DNS 更新失败时，服务继续运行，DNS 维护告警会持续记录。

```sh
/usr/local/bin/derper-go doctor -c /etc/derper/server.json
/usr/local/bin/derper-go export-derpmap -c /etc/derper/server.json --format policy
```

导出片段应合并到现有 tailnet 配置，保留其他区域及原来的默认区域策略。TCP 8443 不需要绑定低端口的 capability；模板会为显式低端口配置添加 CAP_NET_BIND_SERVICE。

## 从已有 derper 和 AnyTLS 迁移

迁移是单独的维护操作。先备份旧二进制、systemd unit、计时器、配置、DERP 身份和现有证书，保留各文件权限。运行中的 AnyTLS 账户缓存保持独立。

1. 在独立临时状态目录、测试端口上验证新程序；将旧 DERP 身份复制到测试目录时保留 0600 权限。正式切换使用原身份，不能重新生成。
2. 通过 cert import 导入旧 derper 的证书链和私钥，以便切换时立即提供有效 TLS：
   ```sh
   sudo /usr/local/bin/derper-go cert import -c /etc/derper/server.json \
     --certificate /var/lib/derper/certs/relay.example.com.crt \
     --private-key /var/lib/derper/certs/relay.example.com.key
   sudo chown -R derper:derper /var/lib/derper/acme
   ```
   在由 root 执行初始化、导入或 dns apply 后，状态目录及新文件需交还给 derper；其他应用的状态目录不参与此步骤。
3. 同域名仍由 AnyTLS 管理 A 记录时，先设置新程序 dns.mode=observe。两者的 DNS-01 TXT 可以并存，但地址记录应只有一个管理者。
4. [兼容补丁](../compat/anytls-disable-address-records.patch) 基于 AnyTLS 提交 993de621b283。补丁新增 acme.publish_address_records，省略时仍为 true。将它设为 false 只关闭地址记录维护，保留证书签发、续期和 TXT 清理：
   ```sh
   git apply --check /path/to/anytls-disable-address-records.patch
   git apply /path/to/anytls-disable-address-records.patch
   go test ./internal/certmgr ./internal/config
   ```
   对应代码构建、测试后再更新 AnyTLS；现有版本会拒绝这个新增字段。
5. 确认原地址维护任务停止后，将新配置切换为 manage，执行 dns plan；核对记录 ID、地址、TTL 和 DNS only，再执行带 --adopt-record-id 的 dns apply。A/AAAA 可分别重复传入参数。初始化结果的属主应为 derper。
6. 维护窗口中停用旧 derper 的证书同步 timer，停止旧 derper，启动新服务。保留域名、端口、DERP 身份和 Region ID，首次切换会触发客户端重连。
7. 验证 DNS、证书链、STUN、未知客户端拒绝，以及两台真实 tailnet 设备经指定 DERP 的转发。持续观察续期及 DNS 维护日志。

## 回滚

停止新服务，恢复旧程序、配置、unit 和证书同步计时器，再启动旧服务。若已将地址管理权移交，恢复 AnyTLS 的 publish_address_records=true，或恢复未打补丁的配置与二进制；回滚过程中维持单一地址管理者。

旧 DERP 身份文件与证书副本应保留到观察期结束。不要把新程序的整个状态目录覆盖到 AnyTLS 的 ACME 缓存中。

## 状态与权限

- DERP 身份兼容官方 PrivateKey JSON，损坏时明确报错，不自动轮换。
- ACME 缓存按 CA directory URL 与域名隔离；账户、完整证书 bundle、TXT 操作日志和续期退避状态分别持久化。
- dns.json 记录安装归属、已管理记录及未确定结果的写操作。其内容用于冲突检测，应与程序状态一起备份。
- process.lock 防止多个 daemon 或离线管理命令共同写入。读取状态的命令不取得写锁。
- 证书 bundle 单文件原子替换后才更新内存。手动 TLS 模式在重启后加载更新；ACME 自动续期不重启中继。
