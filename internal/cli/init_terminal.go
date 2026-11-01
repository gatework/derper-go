package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/gatework/derper-go/internal/setup"
)

// initTerminal renders initialization facts without interpreting deployment phases.
type initTerminal struct{ terminal }

func (u initTerminal) Read(ctx context.Context, need setup.Need) (string, error) {
	if need == setup.CloudflareToken {
		if u.secret == nil {
			return "", errors.New("缺少 Cloudflare 凭据，请指定 --token-file 或 CLOUDFLARE_API_TOKEN")
		}
		fmt.Fprintln(u.out, "Cloudflare Token 需要对应区域的 Zone:Read 与 DNS:Edit 权限。")
		fmt.Fprint(u.out, "Cloudflare API Token（隐藏输入）：")
		return u.secret()
	}
	fmt.Fprint(u.out, need.String()+"：")
	return readLine(ctx, u.in)
}
func (u initTerminal) Show(display setup.Display) {
	switch display.Kind {
	case setup.ContinuingInstallation:
		fmt.Fprintln(u.out, "检测到未完成的初始化，将继续完成安装。")
	case setup.ResumingInstallation:
		fmt.Fprintln(u.out, "继续启动已批准的服务，保留现有身份、证书和 DNS 归属。")
	case setup.InstallationSummary:
		u.summary(display.Summary)
	}
}
func (u initTerminal) summary(s setup.Summary) {
	fmt.Fprintf(u.out, "\n安装摘要\n域名：%s\nHTTPS：%s\n准入模式：%s\n中继区域：%d\n配置：%s\n状态：%s\n", s.Domain, s.HTTPSAddress, s.Admission, s.Region, s.ConfigPath, s.StateDir)
	if s.ControllerURL != "" {
		policy := "拒绝接入"
		if s.ControllerFailOpen {
			policy = "允许接入"
		}
		fmt.Fprintf(u.out, "准入控制器：%s\n控制器故障时：%s\n", s.ControllerURL, policy)
	}
	if s.MeshConfigured {
		fmt.Fprintf(u.out, "节点互联：已设置密钥，%d 个出站节点\n", s.MeshPeers)
	}
	if s.ExistingListener {
		fmt.Fprintln(u.out, "迁移：已核对原中继身份；安装后先停止旧服务，再启动 derper-go，不自动交接端口。")
	}
	if s.AlternatePort {
		fmt.Fprintln(u.out, "443 不可用，本次将保存并使用 :8443。")
	}
	if s.Service {
		if s.Start {
			fmt.Fprintln(u.out, "操作：安装并启动 derper-go.service")
		} else {
			fmt.Fprintln(u.out, "操作：安装 derper-go.service，暂不启动")
		}
	} else {
		fmt.Fprintln(u.out, "操作：准备前台运行配置")
	}
	describeDNS(u.out, s.Changes)
	if s.AutomaticCertificate {
		fmt.Fprintln(u.out, "证书机构：", s.CA)
		fmt.Fprintln(u.out, "服务条款：", s.TermsURL)
	}
}
func (u initTerminal) Confirm(ctx context.Context, scope setup.Confirmation) (setup.Consent, error) {
	question := "确认上述安装及 DNS 接管？[y/N] "
	if scope.TermsRequired {
		question = "确认上述安装、DNS 接管，并接受所列证书机构服务条款？[y/N] "
	}
	if err := confirm(ctx, u.terminal, question); err != nil {
		return setup.Consent{}, err
	}
	return setup.Consent{Install: true, Terms: scope.TermsRequired}, nil
}
func renderInitialization(ui terminal, r setup.Result) int {
	switch r.Outcome {
	case setup.ExistingDeployment:
		fmt.Fprintln(ui.out, "此部署已初始化，保留现有配置、身份与证书。")
		return result(ui, showStatus(ui, r.StateDir, false))
	case setup.RunningDeployment:
		return result(ui, showStatus(ui, r.StateDir, false))
	case setup.PreviewedDeployment:
		fmt.Fprintf(ui.out, "只读预览：部署阶段 %s；配置、身份和证书保留，未启动恢复操作。\n", r.Phase)
	case setup.PreviewedInstallation:
		fmt.Fprintln(ui.out, "只读预览完成，未保存配置、安装服务、签发证书或修改 DNS。")
	case setup.ForegroundPrepared:
		fmt.Fprintf(ui.out, "配置已准备。运行：derper-go run --config %q --state-dir %q\n", r.ConfigPath, r.StateDir)
	case setup.MigrationStaged:
		fmt.Fprintln(ui.out, "迁移已准备，未启用新服务的开机启动。停止并禁用原服务后：sudo systemctl enable --now derper-go.service")
	case setup.ServicePrepared:
		fmt.Fprintln(ui.out, "服务已安装。启动：sudo derper-go service start")
	case setup.BootstrapReady:
		fmt.Fprintln(ui.out, "HTTPS 服务已就绪，DERP 已关闭；使用 status 检查引导 DNS 缓存。")
	case setup.RelayReady:
		fmt.Fprintln(ui.out, "中继已就绪。下一步：derper-go tailnet config，将输出片段合并到 Tailnet 策略。")
	}
	return 0
}
