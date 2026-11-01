// Package cloudflare provides bounded, context-aware DNS API operations.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gatework/derper-go/internal/retry"
)

type Client struct {
	zoneMu                 sync.Mutex
	baseURL, token, zoneID string
	http                   *http.Client
	tokenSource            func() (string, error)
	ownsHTTP               bool
}

// Error exposes status and retry timing without including upstream response bodies.
type Error struct {
	Status     int
	Kind       string
	Cause      error
	Codes      []int
	RetryAfter time.Duration
	Rejected   bool
}

func (e *Error) Error() string {
	return fmt.Sprintf("cloudflare %s error (HTTP %d), error codes %v", e.Kind, e.Status, e.Codes)
}

var ErrProtocol = errors.New("invalid Cloudflare response")

func (e *Error) Unwrap() error               { return e.Cause }
func RetryAfter(header string) time.Duration { return retry.After(header, time.Now()) }

type Record struct {
	Comment string `json:"comment,omitempty"`
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type response struct {
	bytes   int
	Success *bool           `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code int `json:"code"`
	} `json:"errors"`
	Info pageInfo `json:"result_info"`
}

func (c *Client) request(ctx context.Context, method, path string, body any) (*response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, &NotSentError{Cause: errors.New("cannot encode cloudflare request")}
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, &buf)
	if err != nil {
		return nil, &NotSentError{Cause: errors.New("invalid cloudflare request URL")}
	}
	token := c.token
	if c.tokenSource != nil {
		token, err = c.tokenSource()
		if err != nil {
			return nil, &NotSentError{Cause: err}
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if err := ctx.Err(); err != nil {
		return nil, &NotSentError{Cause: err}
	}
	return c.doRequest(req)
}

func (c *Client) doRequest(req *http.Request) (out *response, result error) {
	defer func() {
		if req.Method != http.MethodGet && result != nil {
			var api *Error
			if !errors.As(result, &api) || !api.Rejected {
				result = &UncertainError{Cause: result}
			}
		}
	}()
	res, err := c.http.Do(req)
	if err != nil {
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}
		return nil, &Error{Kind: "network"}
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil {
		cause := errors.New("cloudflare response read failed")
		if req.Context().Err() != nil {
			cause = req.Context().Err()
		}
		return nil, &Error{Status: res.StatusCode, Kind: "response", Cause: cause, RetryAfter: RetryAfter(res.Header.Get("Retry-After"))}
	}
	if len(data) > 1<<20 {
		return nil, &Error{Status: res.StatusCode, Kind: "response exceeds 1 MiB", Cause: ErrProtocol, RetryAfter: RetryAfter(res.Header.Get("Retry-After"))}
	}
	decoded := response{bytes: len(data)}
	decodeErr := json.Unmarshal(data, &decoded)
	if !utf8.Valid(data) {
		decodeErr = ErrProtocol
	}
	protocolError := decodeErr != nil || decoded.Success == nil
	if !protocolError && *decoded.Success && (len(decoded.Result) == 0 || bytes.Equal(decoded.Result, []byte("null"))) {
		protocolError = true
	}
	if protocolError || res.StatusCode < 200 || res.StatusCode >= 300 || !*decoded.Success {
		apiErr := &Error{Status: res.StatusCode, Kind: "api", RetryAfter: RetryAfter(res.Header.Get("Retry-After"))}
		if protocolError {
			apiErr.Kind, apiErr.Cause = "protocol", ErrProtocol
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			apiErr.Kind = "http"
		}
		if decodeErr == nil {
			for _, e := range decoded.Errors {
				apiErr.Codes = append(apiErr.Codes, e.Code)
			}
		}
		apiErr.Rejected = decodeErr == nil && decoded.Success != nil && !*decoded.Success && len(decoded.Errors) > 0 && res.StatusCode >= 400 && res.StatusCode < 500 && res.StatusCode != 408
		// Neither decoding errors nor upstream bodies may echo a credential.
		return nil, apiErr
	}
	resultBytes := bytes.TrimSpace(decoded.Result)
	want := byte('{')
	if req.Method == http.MethodGet && (req.URL.Path == "/client/v4/zones" || strings.HasSuffix(req.URL.Path, "/zones") || strings.HasSuffix(req.URL.Path, "/dns_records")) {
		want = '['
	}
	if len(resultBytes) == 0 || resultBytes[0] != want {
		return nil, &Error{Status: res.StatusCode, Kind: "protocol", Cause: ErrProtocol, RetryAfter: RetryAfter(res.Header.Get("Retry-After"))}
	}
	return &decoded, nil
}

func (c *Client) path() string {
	c.zoneMu.Lock()
	defer c.zoneMu.Unlock()
	return "/zones/" + url.PathEscape(c.zoneID) + "/dns_records"
}

func (c *Client) CheckZone(ctx context.Context, domain string) error {
	c.zoneMu.Lock()
	zoneID := c.zoneID
	c.zoneMu.Unlock()
	if zoneID == "" {
		name := domain
		for strings.Contains(name, ".") {
			query := url.Values{"name": {name}, "status": {"active"}, "per_page": {"50"}}
			res, err := c.request(ctx, http.MethodGet, "/zones?"+query.Encode(), nil)
			if err != nil {
				return err
			}
			var zones []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
			}
			if err = json.Unmarshal(res.Result, &zones); err != nil {
				return fmt.Errorf("decode cloudflare zones: %w", err)
			}
			if len(zones) > 1 || res.Info.TotalPages != nil && *res.Info.TotalPages > 1 {
				return fmt.Errorf("ambiguous cloudflare zone; configure zone_id explicitly")
			}
			if len(zones) == 1 {
				z := zones[0]
				if z.ID == "" || z.Name != name || z.Status != "active" {
					return fmt.Errorf("cloudflare returned an unexpected zone")
				}
				c.zoneMu.Lock()
				if c.zoneID != "" && c.zoneID != z.ID {
					c.zoneMu.Unlock()
					return fmt.Errorf("cloudflare zone changed during discovery")
				}
				c.zoneID = z.ID
				c.zoneMu.Unlock()
				return nil
			}
			_, name, _ = strings.Cut(name, ".")
		}
		return fmt.Errorf("no active cloudflare zone found for ACME domain")
	}

	res, err := c.request(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID), nil)
	if err != nil {
		return err
	}
	var zone struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err = json.Unmarshal(res.Result, &zone); err != nil {
		return fmt.Errorf("decode cloudflare zone: %w", err)
	}
	zone.Name = strings.ToLower(strings.TrimSuffix(zone.Name, "."))
	if zone.Name == "" || (domain != zone.Name && !strings.HasSuffix(domain, "."+zone.Name)) {
		return fmt.Errorf("ACME domain does not belong to configured cloudflare zone")
	}
	if zone.Status != "active" {
		return fmt.Errorf("cloudflare zone is not active")
	}
	return nil
}

func (c *Client) ListRecords(ctx context.Context, name string) ([]Record, error) {
	all := []Record{}
	seen := map[string]int{}
	pages := pageTracker{}
	var total int
	for page := 1; ; page++ {
		q := url.Values{"name": {name}, "page": {strconv.Itoa(page)}, "per_page": {"100"}}
		res, err := c.request(ctx, http.MethodGet, c.path()+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		total += res.bytes
		if total > 16<<20 {
			return nil, errors.New("cloudflare query exceeds 16 MiB")
		}
		var batch []Record
		if json.Unmarshal(res.Result, &batch) != nil {
			return nil, ErrProtocol
		}
		last, err := pages.observe(res.Info, page, len(batch))
		if err != nil {
			return nil, err
		}
		if page == 1 && res.Info.TotalCount != nil {
			// A remote count is only a bounded allocation hint, never a reason
			// to trust an incomplete response or allocate arbitrary memory.
			hint := min(*res.Info.TotalCount, 4096)
			if hint > len(batch) {
				all = make([]Record, 0, hint)
				seen = make(map[string]int, hint)
			}
		}
		fresh := 0
		for _, r := range batch {
			if r.ID == "" || r.Name != name || r.Type == "" {
				return nil, ErrProtocol
			}
			if index, ok := seen[r.ID]; ok {
				if all[index] != r {
					return nil, errors.New("cloudflare record changed during pagination")
				}
				continue
			}
			seen[r.ID] = len(all)
			fresh++
			all = append(all, r)
		}
		if last {
			if err := pages.complete(len(seen)); err != nil {
				return nil, err
			}
			return all, nil
		}
		if fresh == 0 {
			return nil, errors.New("cloudflare pagination did not advance")
		}
	}
}

func (c *Client) CreateRecord(ctx context.Context, r Record) (string, error) {
	res, err := c.request(ctx, http.MethodPost, c.path(), r)
	if err != nil {
		return "", err
	}
	var created Record
	if err = json.Unmarshal(res.Result, &created); err != nil {
		return "", &UncertainError{Cause: ErrProtocol}
	}
	if created.ID == "" || !sameRecord(created, r) {
		return "", &UncertainError{Cause: ErrProtocol}
	}
	return created.ID, nil
}

func (c *Client) DeleteRecord(ctx context.Context, id string) error {
	res, err := c.request(ctx, http.MethodDelete, c.path()+"/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	var result struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(res.Result, &result) != nil || result.ID != id {
		return &UncertainError{Cause: ErrProtocol}
	}
	return nil
}

const BaseURL = "https://api.cloudflare.com/client/v4"

// New constructs a client without network I/O. The HTTP client must have bounded timeouts.
func New(token, zoneID string, httpClient *http.Client) *Client {
	owned := httpClient == nil
	if owned {
		httpClient = HTTPClient()
	}
	return &Client{baseURL: BaseURL, token: token, zoneID: zoneID, http: httpClient, ownsHTTP: owned}
}

// NewSource rereads credentials at request time, enabling token rotation.
func NewSource(source func() (string, error), zoneID string, httpClient *http.Client) *Client {
	c := New("", zoneID, httpClient)
	c.tokenSource = source
	return c
}

// UpdateRecord updates explicitly supplied fields, preserving unrelated record metadata.
func (c *Client) UpdateRecord(ctx context.Context, id string, fields RecordUpdate) error {
	res, err := c.request(ctx, http.MethodPatch, c.path()+"/"+url.PathEscape(id), fields)
	if err != nil {
		return err
	}
	var result Record
	if json.Unmarshal(res.Result, &result) != nil || result.ID != id || result.Content != fields.Content || result.TTL != fields.TTL || result.Proxied != fields.Proxied || result.Comment != fields.Comment {
		return &UncertainError{Cause: ErrProtocol}
	}
	return nil
}

// RecordUpdate changes only address ownership fields, preserving unrelated metadata.
type RecordUpdate struct {
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}
