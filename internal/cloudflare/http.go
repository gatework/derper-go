package cloudflare

import (
	"errors"
	"net/http"
	"time"
)

func HTTPClient() *http.Client {
	transport := http.DefaultTransport
	if t, ok := transport.(*http.Transport); ok {
		transport = t.Clone()
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("不允许 HTTP 重定向") }}
}
