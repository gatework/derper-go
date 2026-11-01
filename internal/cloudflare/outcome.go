package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
)

var ErrUncertainWrite = errors.New("Cloudflare 写入结果不确定，已保留恢复日志；未重放写请求")
var ErrNotFound = errors.New("Cloudflare DNS record not found")

type UncertainError struct{ Cause error }

func (e *UncertainError) Error() string   { return ErrUncertainWrite.Error() + ": " + e.Cause.Error() }
func (e *UncertainError) Unwrap() []error { return []error{ErrUncertainWrite, e.Cause} }

func (e *Error) Is(target error) bool {
	if target != ErrNotFound || !e.Rejected || e.Status != 404 {
		return false
	}
	for _, code := range e.Codes {
		if code == 81044 {
			return true
		}
	}
	return false
}

// Close releases only a transport created by this client; injected clients are borrowed.
func (c *Client) Close() {
	if c.ownsHTTP {
		c.http.CloseIdleConnections()
	}
}

func (c *Client) GetRecord(ctx context.Context, id string) (Record, error) {
	res, err := c.request(ctx, http.MethodGet, c.path()+"/"+url.PathEscape(id), nil)
	if err != nil {
		return Record{}, err
	}
	var record Record
	if json.Unmarshal(res.Result, &record) != nil || record.ID != id || record.Name == "" || record.Type == "" {
		return Record{}, ErrProtocol
	}
	return record, nil
}

func sameRecord(a, b Record) bool {
	if a.Type != b.Type || a.Name != b.Name || a.TTL != b.TTL || a.Proxied != b.Proxied || a.Comment != b.Comment {
		return false
	}
	if a.Content == b.Content {
		return true
	}
	if a.Type == "A" || a.Type == "AAAA" {
		x, errX := netip.ParseAddr(a.Content)
		y, errY := netip.ParseAddr(b.Content)
		return errX == nil && errY == nil && x == y
	}
	if a.Type == "TXT" {
		x, y := a.Content, b.Content
		if text, err := strconv.Unquote(x); err == nil {
			x = text
		}
		if text, err := strconv.Unquote(y); err == nil {
			y = text
		}
		return x == y
	}
	return false
}
