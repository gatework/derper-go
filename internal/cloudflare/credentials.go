package cloudflare

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/gatework/derper-go/internal/fileio"
)

// Credentials names a secret source; its value is never part of configuration.
type Credentials struct {
	File        string
	Environment string
}

func (c Credentials) Read() (string, error) { return c.ReadEnv(os.Getenv) }

func (c Credentials) ReadEnv(getenv func(string) string) (string, error) {
	var value string
	if c.File != "" {
		b, err := fileio.ReadRegularFile(c.File, 8<<10)
		if err != nil {
			return "", errors.New("无法读取 Cloudflare 凭据文件，请检查路径和权限")
		}
		value = string(b)
	} else {
		name := c.Environment
		if name == "" {
			name = "CLOUDFLARE_API_TOKEN"
		}
		value = getenv(name)
	}
	return ValidateToken(value)
}

func ValidateToken(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 || len(value) > 8192 {
		return "", errors.New("凭据为空或格式无效，请重新输入 Cloudflare API Token")
	}
	return value, nil
}

// RuntimeCredentials uses the systemd snapshot when one was supplied.
func RuntimeCredentials(file string) Credentials {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		file = filepath.Join(dir, "cloudflare-token")
	}
	return Credentials{File: file}
}
