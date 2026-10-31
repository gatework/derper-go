package config

import (
	"errors"
	"reflect"
)

// CheckReload rejects changes that need new listeners, background workers,
// credentials or admission backends. Validation never partially applies changes.
func CheckReload(old, next Settings) error {
	if old.UsesController() != next.UsesController() {
		return errors.New("增删准入控制器需要 service restart")
	}
	normalize := func(s Settings) Settings {
		s.MaxConnections, s.ConnectionBurst, s.ConnectionRate = 0, 0, 0
		s.Homepage, s.AdmissionURL, s.AdmissionFailOpen, s.AdmissionTimeout = "", "", false, 0
		if !s.AutomaticCertificate() {
			s.CertificateFile, s.CertificateKey = "manual", "manual"
		}
		return s
	}
	if !reflect.DeepEqual(normalize(old), normalize(next)) {
		return errors.New("此变更需要 service restart；热重载仅支持连接额度/速率、主页、现有控制器策略、验证预算与手动证书")
	}
	return nil
}
