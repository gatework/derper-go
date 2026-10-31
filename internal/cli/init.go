package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/setup"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/systemd"
)

func initialize(ctx context.Context, args []string, ui terminal) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(ui.err)
	path, dir, tokenFile := config.DefaultPath, "", ""
	var input config.Config
	var identityPath, importCert, importKey string
	httpPort := -1
	yes, accept, noService, noStart, noDNS, noSTUN := false, false, false, false, false, false
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
	seen := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if noService && !seen["c"] && !seen["config"] {
		path = "config.json"
	}
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return failure(ui, err)
	}
	if dir == "" {
		dir = setup.DataDir(path)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return failure(ui, err)
	}
	c, err := config.Load(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return failure(ui, err)
	}
	journal, journalErr := state.ReadDeployment(dir)
	if journalErr != nil && !errors.Is(journalErr, os.ErrNotExist) {
		return failure(ui, journalErr)
	}
	if journalErr == nil {
		if errors.Is(err, os.ErrNotExist) {
			c, err = config.Decode(journal.Config)
			if err != nil {
				return failure(ui, err)
			}
		}
		if journal.Phase == "prepared" && !noService && !noStart {
			fmt.Fprintln(ui.out, "继续启动已批准的服务，保留现有身份、证书和 DNS 归属。")
			if e := setup.New().ResumePrepared(ctx, path, dir); e != nil {
				return failure(ui, e)
			}
		}
		if journal.Phase == "ready" || journal.Phase == "prepared" {
			fmt.Fprintln(ui.out, "此部署已初始化，保留现有配置、身份与证书。")
			return result(ui, showStatus(ui, dir, false))
		}
		if s, e := state.InUse(dir); e != nil {
			return failure(ui, e)
		} else if s {
			return result(ui, showStatus(ui, dir, false))
		}
		fmt.Fprintln(ui.out, "检测到未完成的初始化，将继续完成安装。")
	}
	for name := range seen {
		switch name {
		case "domain":
			c.Domain = input.Domain
		case "email":
			c.Email = input.Email
		case "listen":
			c.Relay.Listen = input.Relay.Listen
		case "http-port":
			c.HTTP.Port = &httpPort
		case "admission-url":
			c.Admission.URL = input.Admission.URL
		case "region":
			c.Region = input.Region
		case "admission":
			c.Admission.Mode = config.AdmissionMode(access)
		case "ipv4":
			c.DNS.IPv4 = input.DNS.IPv4
		case "ipv6":
			c.DNS.IPv6 = input.DNS.IPv6
		case "socket":
			c.Tailscale.Socket = input.Tailscale.Socket
		case "ca":
			c.Certificate.CA = input.Certificate.CA
		case "certificate":
			c.Certificate.File, err = filepath.Abs(input.Certificate.File)
			if err != nil {
				return failure(ui, err)
			}
		case "key":
			c.Certificate.Key, err = filepath.Abs(input.Certificate.Key)
			if err != nil {
				return failure(ui, err)
			}
		case "no-dns":
			value := !noDNS
			c.DNS.Publish = &value
		case "no-stun":
			value := !noSTUN
			c.STUN.Enabled = &value
		}
	}
	if !noService {
		if err = systemd.Check(); err != nil {
			return failure(ui, err)
		}
	}
	prompt := func(label string, value *string) error {
		if *value != "" {
			return nil
		}
		if !ui.interactive {
			return fmt.Errorf("缺少%s；非交互模式请通过命令选项提供", label)
		}
		fmt.Fprint(ui.out, label+"：")
		line, e := readLine(ctx, ui.in)
		if e != nil {
			return e
		}
		if line == "" {
			return fmt.Errorf("%s不能为空", label)
		}
		*value = line
		return nil
	}
	if err = prompt("中继域名（--domain）", &c.Domain); err != nil {
		return failure(ui, err)
	}
	c.Domain = strings.ToLower(strings.TrimSuffix(c.Domain, "."))
	if c.Certificate.File == "" {
		if err = prompt("证书联系邮箱（--email）", &c.Email); err != nil {
			return failure(ui, err)
		}
	}
	s, err := setup.Resolve(c, path)
	if err != nil {
		return failure(ui, err)
	}
	if !ui.interactive && (!yes || (s.AutomaticCertificate() && !accept)) {
		return failure(ui, errors.New("非交互初始化需要 --yes；自动签发还需要单独提供 --accept-terms"))
	}
	token := ""
	if s.NeedsCloudflare() {
		source := tokenFile
		if source == "" && c.Cloudflare.TokenFile != "" {
			source = s.TokenFile
		}
		if source == "" {
			if _, e := os.Stat(s.TokenFile); e == nil {
				source = s.TokenFile
			}
		}
		if source != "" || os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
			token, err = (cloudflare.Credentials{File: source}).Read()
		} else if ui.interactive && ui.secret != nil {
			fmt.Fprintln(ui.out, "Cloudflare Token 需要对应区域的 Zone:Read 与 DNS:Edit 权限。")
			fmt.Fprint(ui.out, "Cloudflare API Token（隐藏输入）：")
			token, err = ui.secret()
		} else {
			err = errors.New("缺少 Cloudflare 凭据，请指定 --token-file 或 CLOUDFLARE_API_TOKEN")
		}
		if err != nil {
			return failure(ui, err)
		}
	}
	workflow := setup.New()
	plan, err := workflow.Prepare(ctx, setup.Request{Config: c, Path: path, StateDir: dir, Token: token, Service: !noService, Start: !noStart && !noService, IdentityPath: identityPath, ImportCertificate: importCert, ImportKey: importKey})
	if err != nil {
		return failure(ui, err)
	}
	fmt.Fprintf(ui.out, "\n安装摘要\n域名：%s\nHTTPS：%s\n准入模式：%s\n中继区域：%d\n配置：%s\n状态：%s\n", plan.Settings.Domain, plan.Settings.HTTPSAddress(), plan.Settings.Access, plan.Settings.Region, path, dir)
	if plan.Settings.RelayEnabled && plan.Settings.UsesController() {
		endpoint, _ := url.Parse(plan.Settings.AdmissionURL)
		endpoint.RawQuery = "" // Query parameters may contain an operator-provided secret.
		policy := "拒绝接入"
		if plan.Settings.AdmissionFailOpen {
			policy = "允许接入"
		}
		fmt.Fprintf(ui.out, "准入控制器：%s\n控制器故障时：%s\n", endpoint.String(), policy)
	}
	if plan.Settings.MeshKeyFile != "" {
		fmt.Fprintf(ui.out, "节点互联：已设置密钥，%d 个出站节点\n", len(plan.Settings.MeshPeers))
	}
	if plan.ExistingListener {
		fmt.Fprintln(ui.out, "迁移：已核对原中继身份；安装后先停止旧服务，再启动 derper-go，不自动交接端口。")
	}
	if plan.AlternatePort {
		fmt.Fprintln(ui.out, "443 不可用，本次将保存并使用 :8443。")
	}
	if plan.Service {
		if plan.Start {
			fmt.Fprintln(ui.out, "操作：安装并启动 derper-go.service")
		} else {
			fmt.Fprintln(ui.out, "操作：安装 derper-go.service，暂不启动")
		}
	} else {
		fmt.Fprintln(ui.out, "操作：准备前台运行配置")
	}
	describeDNS(ui.out, plan.Changes)
	if plan.Settings.AutomaticCertificate() {
		fmt.Fprintln(ui.out, "证书机构：", plan.Settings.CA)
		fmt.Fprintln(ui.out, "服务条款：", plan.TermsURL)
	}
	if !yes {
		question := "确认上述安装及 DNS 接管？[y/N] "
		if plan.Settings.AutomaticCertificate() {
			question = "确认上述安装、DNS 接管，并接受所列证书机构服务条款？[y/N] "
		}
		if err = confirm(ctx, ui, question); err != nil {
			return failure(ui, err)
		}
		accept = true
	} else if plan.Settings.AutomaticCertificate() && !accept {
		return failure(ui, errors.New("--yes 不代表接受证书机构条款；请提供 --accept-terms"))
	}
	if err = workflow.Apply(ctx, plan, accept); err != nil {
		return failure(ui, fmt.Errorf("初始化未完成：%w；已保存的身份与证书会在重试时保留", err))
	}
	if noService {
		fmt.Fprintf(ui.out, "配置已准备。运行：derper-go run --config %q --state-dir %q\n", path, dir)
	} else if noStart {
		if identityPath != "" {
			fmt.Fprintln(ui.out, "迁移已准备，未启用新服务的开机启动。停止并禁用原服务后：sudo systemctl enable --now derper-go.service")
		} else {
			fmt.Fprintln(ui.out, "服务已安装。启动：sudo derper-go service start")
		}
	} else if !plan.Settings.RelayEnabled {
		fmt.Fprintln(ui.out, "HTTPS 服务已就绪，DERP 已关闭；使用 status 检查引导 DNS 缓存。")
	} else {
		fmt.Fprintln(ui.out, "中继已就绪。下一步：derper-go tailnet config，将输出片段合并到 Tailnet 策略。")
	}
	return 0
}
