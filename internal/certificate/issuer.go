package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

func (m *Renewer) renew(parent context.Context) (result error) {
	m.certificateMu.Lock()
	defer m.certificateMu.Unlock()
	if err := m.checkRetry(); err != nil {
		return err
	}
	defer func() {
		if err := m.rememberRetry(result); err != nil {
			result = errors.Join(result, err)
		}
	}()
	ctx, cancel := context.WithTimeout(parent, m.issuanceTimeout())
	defer cancel()
	if err := m.dns.CheckZone(ctx, m.config.Domain); err != nil {
		return err
	}
	if err := m.cleanupPending(ctx); err != nil {
		return err
	}
	key, err := m.accountKey()
	if err != nil {
		return err
	}
	client := &acme.Client{Key: key, DirectoryURL: m.config.DirectoryURL, HTTPClient: m.http, UserAgent: "derper-go"}
	_, err = client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + m.config.Email}}, func(string) bool { return m.config.AcceptTerms })
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("register ACME account: %w", err)
	}
	bundle, err := m.issue(ctx, client)
	if err != nil {
		return err
	}
	if err = m.install(bundle); err != nil {
		return err
	}
	m.logger.Info("ACME certificate installed", "domain", m.config.Domain, "expires", m.current.Load().Leaf.NotAfter)
	return nil
}

func (m *Renewer) issue(ctx context.Context, client *acme.Client) ([]byte, error) {
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(m.config.Domain))
	if err != nil {
		return nil, fmt.Errorf("create ACME order: %w", err)
	}
	for _, authURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return nil, err
		}
		if auth.Identifier.Type != "dns" || auth.Identifier.Value != m.config.Domain || auth.Wildcard {
			return nil, fmt.Errorf("ACME returned unexpected authorization identifier")
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		if auth.Status != acme.StatusPending {
			return nil, fmt.Errorf("ACME authorization is %s", auth.Status)
		}
		var challenge *acme.Challenge
		for _, candidate := range auth.Challenges {
			if candidate.Type == "dns-01" {
				challenge = candidate
				break
			}
		}
		if challenge == nil {
			return nil, fmt.Errorf("ACME server did not offer DNS-01")
		}
		if err = m.authorize(ctx, client, authURL, challenge); err != nil {
			return nil, err
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("wait ACME order: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{m.config.Domain}}, key)
	if err != nil {
		return nil, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("finalize ACME order: %w", err)
	}
	var bundle []byte
	for _, der := range chain {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return append(bundle, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})...), nil
}

func (m *Renewer) authorize(ctx context.Context, client *acme.Client, authURL string, challenge *acme.Challenge) (err error) {
	value, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return err
	}
	name := "_acme-challenge." + m.config.Domain
	// 不跟随 DNS CNAME 到其他区域，避免在未授权区域创建验证记录。
	existing, err := m.dns.ListRecords(ctx, name)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if r.Type == "CNAME" {
			return fmt.Errorf("ACME challenge CNAME delegation is not supported")
		}
	}
	// 创建前持久化随机归属标记；即使 POST 响应丢失，也能精确找回本次记录。
	marker := make([]byte, 16)
	if _, err = rand.Read(marker); err != nil {
		return err
	}
	pending := record{Type: "TXT", Name: name, Content: value, TTL: 60, Comment: "derper-acme-" + hex.EncodeToString(marker)}
	journal := filepath.Join(m.cachePath, "pending-txt.json")
	data, _ := json.Marshal(pending)
	if err = atomicWrite(journal, data); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if cleanupErr := m.cleanupPending(cleanup); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("clean up ACME TXT: %w", cleanupErr))
		}
	}()
	// 日志保留 DNS 原始值兼容旧缓存；API 使用带引号的 TXT 表示。
	published := pending
	published.Content = strconv.Quote(value)
	pending.ID, err = m.dns.CreateRecord(ctx, published)
	if err != nil {
		return err
	}
	data, _ = json.Marshal(pending)
	if err = atomicWrite(journal, data); err != nil {
		return err
	}
	timeout := m.config.PropagationTimeout
	propagation, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		values, lookupErr := m.lookupTXT(propagation, name)
		if lookupErr == nil && slices.Contains(values, value) {
			break
		}
		if err = wait(propagation, 2*time.Second); err != nil {
			return fmt.Errorf("wait DNS-01 propagation: %w", err)
		}
	}
	if _, err = client.Accept(ctx, challenge); err != nil {
		return err
	}
	_, err = client.WaitAuthorization(ctx, authURL)
	return err
}

func (m *Renewer) cleanupPending(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	path := filepath.Join(m.cachePath, "pending-txt.json")
	b, err := readFile(path, 64<<10)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var pending record
	if err = json.Unmarshal(b, &pending); err != nil {
		return fmt.Errorf("invalid ACME cleanup journal: %w", err)
	}
	if pending.Type != "TXT" || pending.Name != "_acme-challenge."+m.config.Domain || (pending.ID == "" && !strings.HasPrefix(pending.Comment, "derper-acme-")) {
		return fmt.Errorf("invalid ACME cleanup journal record")
	}
	if err = m.dns.CheckZone(ctx, m.config.Domain); err != nil {
		return err
	}
	records, err := m.dns.ListRecords(ctx, pending.Name)
	if err != nil {
		return err
	}
	found := false
	for _, r := range records {
		if pending.ID != "" {
			if r.ID != pending.ID {
				continue
			}
		} else if r.Comment != pending.Comment {
			continue
		}
		// 只接受原始值或其精确编码，不剥除任意引号，避免删除已修改的内容。
		contentMatches := r.Content == pending.Content || r.Content == strconv.Quote(pending.Content)
		if r.Type != "TXT" || r.Name != pending.Name || !contentMatches || r.Comment != pending.Comment {
			return fmt.Errorf("pending ACME TXT was modified externally; cleanup refused")
		}
		if err = m.dns.DeleteRecord(ctx, r.ID); err != nil {
			return err
		}
		found = true
	}
	if !found && pending.ID == "" {
		// 不确定的 POST 可能仍在服务端执行；保留刚写入的意图供后续维护复核。
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if time.Since(info.ModTime()) < time.Minute {
			return fmt.Errorf("ACME TXT creation outcome is not yet settled; cleanup journal retained")
		}
	}
	return os.Remove(path)
}

func (m *Renewer) issuanceTimeout() time.Duration {
	propagation := m.config.PropagationTimeout
	return propagation + 10*time.Minute
}
