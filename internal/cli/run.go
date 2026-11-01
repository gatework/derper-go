// Package cli provides the Chinese-first command boundary; libraries never exit.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/gatework/derper-go/internal/certificate"
	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/daemon"
	"github.com/gatework/derper-go/internal/setup"
	"github.com/gatework/derper-go/internal/state"
	"github.com/gatework/derper-go/internal/systemd"
)

var Version = "dev"
var Commit = "unknown"

const help = `用法：derper-go <命令> [选项]

常用命令：
  init                  引导配置，确认后安装并启动服务
  run                   前台运行 DERP/STUN 中继
  status                查看中继、证书、DNS 和 Tailnet 状态
  doctor                检查 DNS、TLS、STUN 和本地 tailscaled
  tailnet config        输出 Tailnet 策略配置片段

进阶命令：
  config show|check|reload     查看、校验或重载配置；--dry-run 预览重载
  certificate status|import|renew
                        检查、导入或续签离线证书缓存
  dns plan|apply        预览域名记录变更，确认后发布
  service render|start|stop|restart|reload|logs
                        管理 derper-go.service
  version               查看程序与 Tailscale 版本

默认配置：/etc/derper-go/config.json。可用 -c 或 --config 指定。
使用 <命令> --help 查看选项。自动化请显式指定命令。
`

type terminal struct {
	in          io.Reader
	out, err    io.Writer
	interactive bool
	secret      func() (string, error)
}

func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	ui := terminal{in: in, out: out, err: errOut}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		ui.interactive = true
		ui.secret = func() (string, error) { defer fmt.Fprintln(out); return readSecret(ctx, f) }

	}
	return execute(ctx, args, ui)
}
func execute(ctx context.Context, args []string, ui terminal) (code int) {
	defer func() {
		if code != 0 && code != 5 && errors.Is(ctx.Err(), context.Canceled) {
			code = 130
		}
	}()

	if len(args) == 0 {
		if !ui.interactive {
			fmt.Fprint(ui.out, help)
			return 0
		}
		if _, err := os.Stat(config.DefaultPath); errors.Is(err, os.ErrNotExist) {
			args = []string{"init"}
		} else {
			args = []string{"status"}
		}
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(ui.out, help)
		return 0
	}
	if args[0] == "version" || args[0] == "--version" {
		if len(args) > 1 {
			fmt.Fprintln(ui.err, "version 不接受额外参数")
			return 2
		}
		upstream := "v1.104.4"
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, d := range info.Deps {
				if d.Path == "tailscale.com" {
					upstream = d.Version
				}
			}
		}
		fmt.Fprintf(ui.out, "derper-go %s (%s), tailscale.com %s\n", Version, Commit, upstream)
		return 0
	}
	if args[0] == "init" {
		return initialize(ctx, args[1:], ui)
	}
	name, rest := args[0], args[1:]
	switch name {
	case "config", "certificate", "dns", "tailnet", "service":
		if len(rest) == 0 {
			fmt.Fprint(ui.err, help)
			return 2
		}
		if rest[0] == "--help" || rest[0] == "-h" {
			fmt.Fprint(ui.out, help)
			return 0
		}
		name += "/" + rest[0]
		rest = rest[1:]
	}
	valid := map[string]bool{"run": true, "status": true, "doctor": true, "tailnet/config": true, "config/show": true, "config/check": true, "config/reload": true, "certificate/status": true, "certificate/import": true, "certificate/renew": true, "dns/plan": true, "dns/apply": true, "service/render": true, "service/start": true, "service/stop": true, "service/restart": true, "service/reload": true, "service/logs": true}
	if !valid[name] {
		fmt.Fprintf(ui.err, "未知命令：%s\n", name)
		return 2
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(ui.err)
	path, dir := config.DefaultPath, ""
	fs.StringVar(&path, "config", path, "配置文件")
	fs.StringVar(&path, "c", path, "配置文件")
	fs.StringVar(&dir, "state-dir", "", "状态目录（默认与部署位置对应）")
	jsonOutput, yes, force, effective, dryRun := false, false, false, false, false
	format, certPath, keyPath, binary := "policy", "", "", systemd.Binary
	switch name {
	case "config/reload", "service/reload":
		fs.BoolVar(&dryRun, "dry-run", false, "只读预览变化字段和重启要求")
	case "config/show":
		fs.BoolVar(&effective, "effective", false, "显示已生效的默认值和绝对路径")
	case "status", "doctor":
		fs.BoolVar(&jsonOutput, "json", false, "输出机器可读 JSON")
	case "tailnet/config":
		fs.StringVar(&format, "format", format, "policy 或 derpmap")
	case "dns/apply":
		fs.BoolVar(&yes, "yes", false, "批准本次预览中的变更与记录接管")
	case "certificate/import":
		fs.StringVar(&certPath, "file", "", "证书链 PEM 文件")
		fs.StringVar(&keyPath, "key", "", "私钥 PEM 文件")
	case "certificate/renew":
		fs.BoolVar(&force, "force", false, "提前续签（仍遵守 CA 重试时间）")
	case "service/render":
		fs.StringVar(&binary, "binary", binary, "安装后的程序绝对路径")
	}
	if err := fs.Parse(rest); err != nil {
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
		case "c", "config", "state-dir", "file", "key", "binary":
			if f.Value.String() == "" {
				emptyPath = f.Name
			}
		}
	})
	if emptyPath != "" {
		fmt.Fprintln(ui.err, "--"+emptyPath+" 不能为空")
		return 2
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
	if strings.HasPrefix(name, "service/") && name != "service/render" && (path != config.DefaultPath || dir != config.DefaultDataDir) {
		return failure(ui, errors.New("service 命令管理标准路径下的 derper-go.service；自定义部署请使用 config reload 或 systemctl"))
	}
	if name == "config/reload" || name == "service/reload" {
		if dryRun {
			plan, err := daemon.PreviewReload(ctx, dir, path)
			if len(plan.Changes) > 0 {
				fmt.Fprintln(ui.out, "变化字段：", strings.Join(plan.Changes, ", "))
			}
			if err == nil {
				fmt.Fprintln(ui.out, "预览通过，可热重载；手动证书会重新读取并验证。")
			}
			return result(ui, err)
		}
		err := daemon.Reload(ctx, dir, path)
		if err == nil {
			fmt.Fprintln(ui.out, "配置已重载，现有中继连接保持运行。")
		}
		return result(ui, err)
	}
	if strings.HasPrefix(name, "service/") && name != "service/render" {
		if path != config.DefaultPath || dir != config.DefaultDataDir {
			return failure(ui, errors.New("service 命令管理标准路径下的 derper-go.service；自定义单元请使用 systemctl"))
		}
		if name == "service/logs" {
			return result(ui, systemd.Logs(ctx, ui.out, ui.err))
		}
		if name == "service/start" || name == "service/restart" {
			c, e := config.Load(path)
			if e != nil {
				return failure(ui, e)
			}
			s, e := setup.Resolve(c, path)
			if e != nil {
				return failure(ui, e)
			}
			if e = daemon.Check(s); e != nil {
				return failure(ui, e)
			}
			if e = systemd.Refresh(ctx, s); e != nil {
				return failure(ui, e)
			}
		}
		return result(ui, systemd.Control(ctx, strings.TrimPrefix(name, "service/")))
	}

	c, err := config.Load(path)
	if err != nil {
		return failure(ui, err)
	}
	s, err := setup.Resolve(c, path)
	if err != nil {
		return failure(ui, err)
	}
	logger := slog.New(slog.NewTextHandler(ui.err, &slog.HandlerOptions{Level: logLevel(s.LogLevel)}))
	encode := func(v any) error { e := json.NewEncoder(ui.out); e.SetIndent("", "  "); return e.Encode(v) }
	locked := func(action func() error) error {
		store, err := state.Open(dir)
		if err != nil {
			return err
		}
		defer store.Close()
		err = action()
		if os.Geteuid() == 0 && dir == config.DefaultDataDir {
			err = errors.Join(err, systemd.RestoreStateOwnership())
		}
		return err
	}
	switch name {
	case "run":
		err = daemon.RunFile(ctx, s, dir, path, logger)
	case "status":
		err = showStatus(ui, dir, jsonOutput)
	case "config/show":
		if effective {
			c, err = c.Effective(filepath.Dir(path))
		}
		if err == nil {
			err = encode(c)
		}
	case "config/check":
		err = daemon.Check(s)
		if err == nil {
			fmt.Fprintln(ui.out, "配置有效")
		}
	case "tailnet/config":
		var b []byte
		b, err = daemon.ExportTailnetConfig(s, format)
		if err == nil {
			_, err = ui.out.Write(b)
		}
	case "doctor":
		probe, cancel := context.WithTimeout(ctx, 30*time.Second)
		checks := daemon.Doctor(probe, s)
		cancel()
		if jsonOutput {
			err = encode(checks)
		} else {
			for _, check := range checks {
				fmt.Fprintf(ui.out, "%s：%s（%s）\n", check.Name, verdict(check.OK), check.Detail)
			}
		}
		for _, check := range checks {
			if !check.OK {
				err = errors.New("部分检查未通过，请根据提示修复")
			}
		}
	case "dns/plan", "dns/apply":
		if !s.PublishDNS {
			err = errors.New("配置已关闭 DNS 发布")
			break
		}
		request, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		publisher := daemon.NewDNSPublisher(s, dir, nil)
		defer publisher.Close()
		changes, e := publisher.Plan(request)
		cancel()
		err = e
		if err != nil {
			break
		}
		if name == "dns/plan" {
			err = encode(changes)
			break
		}
		describeDNS(ui.out, changes)
		if !yes {
			if !ui.interactive {
				err = errors.New("非交互发布需要 --yes 明确批准本次预览")
				break
			}
			if err = confirm(ctx, ui, "确认发布上述记录，并接管标记为 adopt 的记录？[y/N] "); err != nil {
				break
			}
		}
		apply, cancelApply := context.WithTimeout(ctx, time.Minute)
		err = locked(func() error { return applyDNS(apply, publisher, changes) })
		cancelApply()
	case "certificate/status":
		var status certificate.Status
		if s.AutomaticCertificate() {
			status, err = certificate.CachedStatus(daemon.CertificateOptions(s, dir))
		} else {
			get, e := certificate.Manual(s.Domain, s.CertificateFile, s.CertificateKey)
			err = e
			if err == nil {
				pair, e := get(nil)
				err = e
				if err == nil {
					status = certificate.CertificateStatus(pair.Leaf, s.Domain)
				}
			}
		}
		if err == nil {
			err = encode(status)
		}
	case "certificate/import", "certificate/renew":
		if !s.AutomaticCertificate() {
			err = errors.New("此命令用于自动证书缓存；手动证书请更新配置引用的文件")
			break
		}
		err = locked(func() error {
			if name == "certificate/import" {
				if certPath == "" || keyPath == "" {
					return errors.New("需要 --file 与 --key")
				}
				return certificate.Import(daemon.CertificateOptions(s, dir), certPath, keyPath)
			}
			if e := state.CheckTerms(dir, s.Domain, s.CA); e != nil {
				return e
			}
			return certificate.Renew(ctx, daemon.CertificateOptions(s, dir), force)
		})
	case "service/render":
		var unit string
		unit, err = systemd.Render(binary, path, s)
		if err == nil {
			_, err = io.WriteString(ui.out, unit)
		}
	}
	if errors.Is(err, cloudflare.ErrUncertainWrite) {
		return failure(ui, err)
	}
	if err != nil && errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return 130
	}
	return result(ui, err)
}
func showStatus(ui terminal, dir string, jsonOutput bool) error {
	s, err := daemon.ReadStatus(dir)
	if errors.Is(err, os.ErrNotExist) {
		d, e := state.ReadDeployment(dir)
		if e != nil {
			return errors.New("尚未初始化，请运行 derper-go init")
		}
		if jsonOutput {
			return json.NewEncoder(ui.out).Encode(struct {
				Phase  string `json:"phase"`
				Active bool   `json:"active"`
				Ready  bool   `json:"ready"`
			}{Phase: d.Phase})
		}
		fmt.Fprintln(ui.out, "配置已准备，服务尚未运行")
		return nil
	}
	if err != nil {
		return err
	}
	if jsonOutput {
		return json.NewEncoder(ui.out).Encode(s)
	}
	fmt.Fprintf(ui.out, "域名：%s\n进程：%s\n中继：%s\n证书：%s %s\nDNS：%s %s\nTailnet：%s %s\n", s.Domain, verdict(s.Active), component(s.Relay.State), component(s.Certificate.State), s.Certificate.Detail, component(s.DNS.State), s.DNS.Detail, component(s.Tailnet.State), s.Tailnet.Detail)
	fmt.Fprintf(ui.out, "准入：%s %s\n节点互联：%s %s\n引导 DNS：%s %s\n", s.AdmissionMode, component(s.AdmissionHealth.State), component(s.Mesh.State), s.Mesh.Detail, component(s.Bootstrap.State), s.Bootstrap.Detail)
	if s.Error != "" {
		fmt.Fprintln(ui.out, "最近错误：", s.Error)
	}
	return nil
}
func component(s string) string {
	switch s {
	case "ready":
		return "就绪"
	case "degraded":
		return "异常"
	case "stopped":
		return "已停止"
	case "disabled":
		return "已关闭"
	case "configured":
		return "已配置，等待连接验证"
	case "public":
		return "公开访问"
	default:
		return "等待中"
	}
}
func verdict(ok bool) string {
	if ok {
		return "就绪"
	}
	return "未就绪"
}
func logLevel(s string) slog.Level {
	var level slog.Level
	_ = level.UnmarshalText([]byte(s))
	return level
}
func failure(ui terminal, err error) int {
	fmt.Fprintln(ui.err, err)
	if errors.Is(err, cloudflare.ErrUncertainWrite) {
		return 5
	}
	return 1
}
func result(ui terminal, err error) int {
	if err != nil {
		return failure(ui, err)
	}
	return 0
}

func confirm(ctx context.Context, ui terminal, prompt string) error {
	fmt.Fprint(ui.out, prompt)
	answer, err := readLine(ctx, ui.in)
	if err != nil {
		return fmt.Errorf("初始化已取消：%w", err)
	}
	if answer != "y" && answer != "Y" && answer != "yes" && answer != "是" {
		return errors.New("已取消，未执行变更")
	}
	return nil
}
