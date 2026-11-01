package cli

import (
	"bytes"
	"errors"
	"path/filepath"
	"slices"

	"github.com/gatework/derper-go/internal/certificate"
	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/daemon"
	"github.com/gatework/derper-go/internal/fileio"
	"github.com/gatework/derper-go/internal/state"
)

type existingInputs struct {
	tokenFile, identity, importCertificate, importKey string
	manualCertificate, manualKey                      bool
}

// checkExistingInputs treats explicitly repeated sources as assertions, never as
// permission to rotate credentials or replace an initialized relay identity.
func checkExistingInputs(current, requested config.Settings, dir string, input existingInputs) (config.Settings, error) {
	if input.tokenFile != "" {
		if !current.NeedsCloudflare() {
			return requested, errors.New("当前部署不使用 Cloudflare 凭据，请移除 --token-file")
		}
		source, err := (cloudflare.Credentials{File: input.tokenFile}).Read()
		if err != nil {
			return requested, err
		}
		deployed, err := (cloudflare.Credentials{File: current.TokenFile}).Read()
		if err != nil {
			return requested, err
		}
		if source != deployed {
			return requested, errors.New("提供的 Cloudflare 凭据与已有部署不同；请更新已配置的凭据文件，并对 systemd 服务执行 service restart")
		}
	}
	if input.identity != "" {
		source, err := fileio.ReadRegularFile(input.identity, 16<<10)
		if err != nil {
			return requested, err
		}
		deployed, err := fileio.ReadRegularFile(filepath.Join(dir, "identity.json"), 16<<10)
		if err != nil {
			return requested, err
		}
		incoming, err := state.DecodeIdentity(source)
		if err != nil {
			return requested, err
		}
		existing, err := state.DecodeIdentity(deployed)
		if err != nil {
			return requested, err
		}
		if !incoming.Equal(existing) {
			return requested, errors.New("导入身份与已有节点不同，拒绝覆盖；请使用独立状态目录准备新节点")
		}
	}
	if input.importCertificate != "" || input.importKey != "" {
		if input.importCertificate == "" || input.importKey == "" {
			return requested, errors.New("--import-certificate 与 --import-key 必须同时提供")
		}
		if !current.AutomaticCertificate() {
			return requested, errors.New("手动证书部署不使用缓存导入；请更新证书后执行 config reload")
		}
		same, err := certificate.MatchesCached(daemon.CertificateOptions(current, dir), input.importCertificate, input.importKey)
		if err != nil {
			return requested, err
		}
		if !same {
			return requested, errors.New("导入证书与已有缓存不同；请在停服维护时使用 certificate import")
		}
	}
	if input.manualCertificate || input.manualKey {
		if current.AutomaticCertificate() {
			return requested, errors.New("变更证书模式需要修改配置后执行 service restart")
		}
		oldGet, err := certificate.Manual(current.Domain, current.CertificateFile, current.CertificateKey)
		if err != nil {
			return requested, err
		}
		newGet, err := certificate.Manual(current.Domain, requested.CertificateFile, requested.CertificateKey)
		if err != nil {
			return requested, err
		}
		oldPair, err := oldGet(nil)
		if err != nil {
			return requested, err
		}
		newPair, err := newGet(nil)
		if err != nil {
			return requested, err
		}
		if !slices.EqualFunc(oldPair.Certificate, newPair.Certificate, bytes.Equal) {
			return requested, errors.New("手动证书与已有部署不同；请更新配置或证书后执行 config reload")
		}
		requested.CertificateFile, requested.CertificateKey = current.CertificateFile, current.CertificateKey
	}
	return requested, nil
}
