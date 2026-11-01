package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/setup"
)

func initialize(ctx context.Context, args []string, ui terminal) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(ui.err)
	path, dir, tokenFile := config.DefaultPath, "", ""
	var input config.Config
	var identityPath, importCert, importKey string
	httpPort := -1
	yes, accept, noService, noStart, noDNS, noSTUN, dryRun := false, false, false, false, false, false, false
	fs.StringVar(&path, "config", path, "配置文件")
	fs.StringVar(&path, "c", path, "配置文件")
	fs.StringVar(&dir, "state-dir", "", "状态目录（仅前台部署可覆盖）")
	fs.StringVar(&identityPath, "identity", "", "迁移原 DERP 身份文件；必须配合 --region 和 --no-start")
	fs.StringVar(&importCert, "import-certificate", "", "导入有效证书链，继续使用自动续期")
	fs.StringVar(&importKey, "import-key", "", "导入证书的私钥文件")
	fs.StringVar(&input.Domain, "domain", "", "中继域名，例如 relay.example.com")
	fs.StringVar(&input.Email, "email", "", "证书联系邮箱")
	fs.StringVar(&tokenFile, "token-file", "", "Cloudflare API Token 文件（也可使用 CLOUDFLARE_API_TOKEN 环境变量）")
	fs.StringVar(&input.Relay.Listen, "listen", "", "HTTPS 监听地址，如 :443、127.0.0.1:8443 或 [::1]:443")
	fs.IntVar(&httpPort, "http-port", -1, "HTTP 探测端口，-1 关闭（默认）")
	fs.StringVar(&input.Admission.URL, "admission-url", "", "自定义准入控制器 HTTPS 地址，本机也可使用 HTTP")
	fs.IntVar(&input.Region, "region", 0, "Tailnet 中继区域（默认从 900–999 自动选择）")
	access := ""
	fs.StringVar(&access, "admission", "", "准入模式：tailnet（默认）、controller 或 public")
	fs.StringVar(&input.DNS.IPv4, "ipv4", "", "公网 IPv4（默认自动发现，off 关闭）")
	fs.StringVar(&input.DNS.IPv6, "ipv6", "", "公网 IPv6（默认不发布）")
	fs.StringVar(&input.Tailscale.Socket, "socket", "", "已有 tailscaled 的套接字")
	fs.StringVar(&input.Certificate.CA, "ca", "", "letsencrypt、staging 或 HTTPS ACME 目录")
	fs.StringVar(&input.Certificate.File, "certificate", "", "已有证书链 PEM 文件")
	fs.StringVar(&input.Certificate.Key, "key", "", "已有私钥 PEM 文件")
	fs.BoolVar(&noDNS, "no-dns", false, "关闭地址记录发布")
	fs.BoolVar(&noSTUN, "no-stun", false, "关闭 STUN")
	fs.BoolVar(&dryRun, "dry-run", false, "只读预检并展示安装摘要，不执行安装或发布")
	fs.BoolVar(&yes, "yes", false, "批准显示的安装摘要及 DNS 接管")
	fs.BoolVar(&accept, "accept-terms", false, "明确接受所选证书机构的服务条款")
	fs.BoolVar(&noService, "no-service", false, "只准备前台配置，默认写入当前目录 config.json")
	fs.BoolVar(&noStart, "no-start", false, "安装服务后暂不启动")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(ui.err, "出现多余的位置参数")
		return 2
	}
	emptyPath := ""
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "c", "config", "state-dir", "token-file", "identity", "import-certificate", "import-key", "certificate", "key", "socket":
			if f.Value.String() == "" {
				emptyPath = f.Name
			}
		}
	})
	if emptyPath != "" {
		fmt.Fprintln(ui.err, "--"+emptyPath+" 不能为空")
		return 2
	}

	request := setup.Request{StateDir: dir, Preview: dryRun, Interactive: ui.interactive,
		Sources: setup.Sources{TokenFile: tokenFile, Identity: identityPath, ImportCertificate: importCert, ImportKey: importKey},
		Consent: setup.Consent{Install: yes, Terms: accept}}
	if noService {
		request.Mode = setup.PrepareForeground
	} else if noStart {
		request.Mode = setup.PrepareService
	}
	admission := config.AdmissionMode(access)
	publishDNS, stunEnabled := !noDNS, !noSTUN
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "config", "c":
			request.ConfigPath = path
		case "domain":
			request.Overrides.Domain = &input.Domain
		case "email":
			request.Overrides.Email = &input.Email
		case "listen":
			request.Overrides.Listen = &input.Relay.Listen
		case "http-port":
			request.Overrides.HTTPPort = &httpPort
		case "admission-url":
			request.Overrides.AdmissionURL = &input.Admission.URL
		case "region":
			request.Overrides.Region = &input.Region
		case "admission":
			request.Overrides.Admission = &admission
		case "ipv4":
			request.Overrides.IPv4 = &input.DNS.IPv4
		case "ipv6":
			request.Overrides.IPv6 = &input.DNS.IPv6
		case "socket":
			request.Overrides.Socket = &input.Tailscale.Socket
		case "ca":
			request.Overrides.CA = &input.Certificate.CA
		case "certificate":
			request.Overrides.CertificateFile = &input.Certificate.File
		case "key":
			request.Overrides.CertificateKey = &input.Certificate.Key
		case "no-dns":
			request.Overrides.PublishDNS = &publishDNS
		case "no-stun":
			request.Overrides.STUNEnabled = &stunEnabled
		}
	})
	result, err := setup.New().Initialize(ctx, request, initTerminal{ui})
	if err != nil {
		return failure(ui, err)
	}
	return renderInitialization(ui, result)
}
