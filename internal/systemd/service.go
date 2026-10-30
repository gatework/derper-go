package systemd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/state"
)

const Binary = "/usr/local/bin/derper-go"
const UnitPath = "/etc/systemd/system/derper-go.service"
const managed = "# Managed by derper-go init\n"

func unitPath(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "%$\\\"") || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return "", errors.New("systemd 路径必须是绝对路径，且不含控制字符、%、$、反斜杠或双引号")
	}
	return strconv.Quote(path), nil
}
func Render(binary, path string, s config.Settings) (string, error) {
	b, err := unitPath(binary)
	if err != nil {
		return "", err
	}
	p, err := unitPath(path)
	if err != nil {
		return "", err
	}
	dependency := ""
	if s.Access == config.Tailnet {
		dependency = " tailscaled.service"
	}
	credential := ""
	if s.NeedsCloudflare() {
		if _, err := unitPath(s.TokenFile); err != nil {
			return "", err
		}
		credential = "LoadCredential=" + strconv.Quote("cloudflare-token:"+s.TokenFile) + "\n"
	}
	capabilities := "CapabilityBoundingSet=\n"
	if s.Port < 1024 || s.CaptivePortal || (s.STUNEnabled && s.STUNPort < 1024) {
		capabilities = "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
	}
	return managed + fmt.Sprintf(`[Unit]
Description=DERP and STUN relay
Wants=network-online.target%s
After=network-online.target%s
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=notify
NotifyAccess=main
User=derper-go
Group=derper-go
ExecStart=%s run --config %s
%sStateDirectory=derper-go
StateDirectoryMode=0700
UMask=0077
Environment=GOMEMLIMIT=96MiB
Restart=on-failure
RestartSec=30
TimeoutStartSec=15min
TimeoutStopSec=45
LimitNOFILE=65536
LimitCORE=0
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
%s
[Install]
WantedBy=multi-user.target
`, dependency, dependency, b, p, credential, capabilities), nil
}
func Check() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("安装服务需要 Linux root 权限，请使用 sudo derper-go init；前台运行可选择 --no-service")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("未检测到运行中的 systemd；可使用 init --no-service 准备前台配置")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("缺少 systemctl")
	}
	return checkUnit()
}
func Control(ctx context.Context, action string) error {
	switch action {
	case "start", "stop", "restart", "enable":
	default:
		return errors.New("不支持的服务操作")
	}
	output, err := exec.CommandContext(ctx, "systemctl", action, "derper-go.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("derper-go.service %s 失败：%w：%s", action, err, output)
	}
	return nil
}
func Logs(ctx context.Context, out, errOut io.Writer) error {
	cmd := exec.CommandContext(ctx, "journalctl", "-u", "derper-go.service", "-n", "100", "--no-pager")
	cmd.Stdout = out
	cmd.Stderr = errOut
	return cmd.Run()
}

// Install is invoked only after a durable setup journal and user confirmation.
func Install(ctx context.Context, path string, s config.Settings) error {
	if err := Check(); err != nil {
		return err
	}
	if path != config.DefaultPath {
		return errors.New("系统服务使用 /etc/derper-go/config.json；其他位置请使用 --no-service")
	}
	unit, err := Render(Binary, path, s)
	if err != nil {
		return err
	}

	account, err := user.Lookup("derper-go")
	if err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return err
		}
		output, e := exec.CommandContext(ctx, "useradd", "--system", "--home-dir", config.DefaultDataDir, "--no-create-home", "--shell", "/usr/sbin/nologin", "--user-group", "derper-go").CombinedOutput()
		if e != nil {
			return fmt.Errorf("创建服务用户失败：%w：%s", e, output)
		}
		account, err = user.Lookup("derper-go")
		if err != nil {
			return err
		}
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if uid == 0 || account.HomeDir != config.DefaultDataDir {
		return errors.New("现有 derper-go 用户不符合服务账户约定")
	}
	if err = os.Chown(filepath.Dir(path), 0, gid); err != nil {
		return err
	}
	if err = os.Chmod(filepath.Dir(path), 0750); err != nil {
		return err
	}
	if err = os.Chown(path, 0, gid); err != nil {
		return err
	}
	if err = os.Chmod(path, 0640); err != nil {
		return err
	}
	for _, file := range []string{s.CertificateFile, s.CertificateKey} {
		if file != "" {
			if err = os.Chown(file, 0, gid); err != nil {
				return err
			}
			if err = os.Chmod(file, 0640); err != nil {
				return err
			}
		}
	}
	if err = ownState(uid, gid); err != nil {
		return err
	}

	source, err := os.Executable()
	if err != nil {
		return err
	}
	if source != Binary {
		if err = copyExecutable(source, Binary); err != nil {
			return err
		}
	}
	if err = state.WriteFile(UnitPath, []byte(unit), 0644, false); err != nil {
		return err
	}
	output, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("重新加载 systemd 失败：%w：%s", err, output)
	}
	return Control(ctx, "enable")
}
func copyExecutable(source, target string) error {
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.CreateTemp(filepath.Dir(target), ".derper-go-*")
	if err != nil {
		return err
	}
	defer os.Remove(dst.Name())
	defer dst.Close()
	if _, err = io.Copy(dst, src); err != nil {
		return err
	}
	if err = dst.Chmod(0755); err != nil {
		return err
	}
	if err = dst.Sync(); err != nil {
		return err
	}
	if err = dst.Close(); err != nil {
		return err
	}
	if err = os.Rename(dst.Name(), target); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func OwnStateFile(path string) error {
	account, err := user.Lookup("derper-go")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}

// RestoreStateOwnership keeps root-run offline maintenance readable by the
// installed service. It only operates on the dedicated standard state directory.
func RestoreStateOwnership() error {
	account, err := user.Lookup("derper-go")
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return nil
		}
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if uid == 0 || account.HomeDir != config.DefaultDataDir {
		return errors.New("derper-go 服务账户无效")
	}
	return ownState(uid, gid)
}
func ownState(uid, gid int) error {
	return filepath.WalkDir(config.DefaultDataDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("状态目录包含符号链接或特殊文件")
		}
		return os.Chown(path, uid, gid)
	})
}

func checkUnit() error {
	if info, e := os.Lstat(UnitPath); e == nil {
		if !info.Mode().IsRegular() {
			return errors.New("已有 derper-go.service 不是普通文件")
		}
		b, e := os.ReadFile(UnitPath)
		if e != nil {
			return e
		}
		if !strings.HasPrefix(string(b), managed) {
			return errors.New("已有未受管理的 derper-go.service，请先人工处理")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}

	return nil
}
