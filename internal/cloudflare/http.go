package cloudflare

import (
	"errors"
	"net/http"
	"time"
)

func HTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("不允许 HTTP 重定向") }}
}
