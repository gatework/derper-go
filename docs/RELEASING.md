# 版本与自动发布

推送版本标签即可自动创建 GitHub Release。发布工作流复用同一提交的完整 CI，验证通过后上传发行包；不需要本地交叉编译，也不需要额外保存发布 Token。

## 发布一个版本

先为目标版本填写 `CHANGELOG.md`（预发布可复用对应正式版的条目），再将代码合并或推送到 `main`，确认普通 CI 通过，然后在对应提交创建并推送标签：

```sh
git switch main
git pull --ff-only
git tag -a v0.1.0 -m 'derper-go v0.1.0'
git push origin v0.1.0
```

支持严格的 SemVer 标签，例如 `v0.1.0`、`v0.2.0-rc.1`。带预发布标识的版本自动标记为 Prerelease，不成为 Latest。正式版本由 GitHub 根据版本和发布时间选择 Latest。版本标签必须指向 `main` 历史中的提交；发布期间若标签移动，流程停止。

普通分支 CI 不发布 Release。不要修改已经发布的标签或覆盖其附件；修复应使用新版本号。

## 验证与产物

每次发布执行：

1. 校验标签格式、提交 SHA、`main` 归属和非空的版本变更记录。
2. 工作流语法、发布故障恢复测试、Go 格式/模块检查、race、vet 和可达漏洞扫描。
3. 在对应原生 runner 上构建并运行 Linux amd64、arm64 二进制，校验 CLI 版本、完整提交 SHA、ELF 架构与静态链接。
4. 重建 amd64 包并逐字节比较，检查归档可复现性。
5. 直接使用已打包的 amd64 二进制，在隔离 systemd 容器安装、重启、切换低端口并核对身份保留。
6. 为通过验证的两个归档及校验和生成 GitHub/Sigstore 构建来源证明。
7. 创建草稿、补齐缺失附件、下载回读校验，然后公开 Release。

发行附件为：

```text
derper-go_v0.1.0_linux_amd64.tar.gz
derper-go_v0.1.0_linux_arm64.tar.gz
checksums.txt
```

每个归档包含程序、README、CHANGELOG、配置示例、部署说明、许可证、`go.mod`、`go.sum` 和 `build-info.json`。元数据记录版本、完整提交、Go 版本、操作系统、架构及源码提交时间。编译使用 `CGO_ENABLED=0`、`-trimpath`，归档排序、属主、权限、时间和 gzip 头均固定。

普通 CI 也保留两个发行归档 14 天，可在 Actions 页面下载。其版本为 `dev`，包含对应提交标识。

## 下载与验证

从对应版本的 Release 下载目标架构归档和 `checksums.txt`，再执行：

```sh
sha256sum --ignore-missing -c checksums.txt
gh attestation verify derper-go_v0.1.0_linux_amd64.tar.gz \
  --repo gatework/derper-go

tar -xzf derper-go_v0.1.0_linux_amd64.tar.gz
cd derper-go_v0.1.0_linux_amd64
./derper-go version
sudo ./derper-go init
```

`--ignore-missing` 允许只下载所需架构，但至少需要一个匹配的归档。来源验证需要支持 `gh attestation` 的较新 GitHub CLI，并访问 GitHub。源码压缩包由 GitHub 自动提供，不包含已编译程序。

## 失败恢复

先修复对应错误，再从 Actions 重跑失败作业；也可以对同一标签手动触发：

```sh
gh workflow run release.yml --ref v0.1.0 --repo gatework/derper-go
```

- CI 失败：不创建公开 Release。
- 新草稿暂不可见：只对创建成功后的“尚未读到”进行有界重试，不重复创建。
- 上传失败：保留草稿；重跑只补齐缺失附件。GitHub 留下的未完成 `starter` 占位附件可在草稿中重新上传。
- 已上传内容不同、出现未知附件、标签或资源 ID 变化：停止发布，不用 `--clobber` 覆盖未知状态。
- 已公开且内容完全一致：重跑只验证，不改写附件或版本状态。
- 认证、限流、网络错误：直接失败，不能被当作“版本尚不存在”。

发布权限只授予最后一个作业；PR 和普通 CI 仅有仓库读取权限。Actions 均固定到提交 SHA，检出不持久化 Git 凭据。自动发布不部署程序、不重启 la3 服务，也不修改生产 DNS。

## 本地打包

在具有 GNU tar、gzip、Python 3.11+ 与项目 Go 工具链的环境中执行：

```sh
make package VERSION=v0.1.0
# 只构建一个架构，可指定输出目录：
make package VERSION=v0.1.0 ARCHES=arm64 DIST_DIR=dist-arm64
```

`COMMIT` 必须是当前 HEAD 的完整 Git SHA，受跟踪源码必须干净。打包通过 Git archive 提取此提交，只包含受跟踪的普通文件和目录，未跟踪文件、忽略文件和链接不会进入发行包。构建强制 `GOWORK=off` 并清空 `GOFLAGS`，排除外部工作区、overlay 和 modfile 的影响；时间戳固定取该提交时间。只有 CI 对受检标签生成并证明的附件才作为正式发布来源；本地打包不会自动创建标签或 Release。
