// Package cloudflare provides bounded, context-aware DNS API operations.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gatework/derper-go/internal/retry"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	zoneMu                 sync.Mutex
	baseURL, token, zoneID string
	http                   *http.Client
	tokenSource            func() (string, error)
}

// Error exposes status and retry timing without including upstream response bodies.
type Error struct {
	Status     int
	Kind       string
	Cause      error
	Codes      []int
	RetryAfter time.Duration
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
	Success *bool           `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code int `json:"code"`
	} `json:"errors"`
	Info struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c *Client) request(ctx context.Context, method, path string, body any) (*response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, &buf)
	if err != nil {
		return nil, err
	}
	token := c.token
	if c.tokenSource != nil {
		token, err = c.tokenSource()
		if err != nil {
			return nil, err
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare request: %w", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("cloudflare response: %w", err)
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("cloudflare response exceeds 1 MiB")
	}
	var out response
	decodeErr := json.Unmarshal(data, &out)
	protocolError := decodeErr != nil || out.Success == nil
	if !protocolError && *out.Success && (len(out.Result) == 0 || bytes.Equal(out.Result, []byte("null"))) {
		protocolError = true
	}
	if protocolError || res.StatusCode < 200 || res.StatusCode >= 300 || !*out.Success {
		apiErr := &Error{Status: res.StatusCode, Kind: "api", RetryAfter: RetryAfter(res.Header.Get("Retry-After"))}
		if protocolError {
			apiErr.Kind, apiErr.Cause = "protocol", ErrProtocol
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			apiErr.Kind = "http"
		}
		if decodeErr == nil {
			for _, e := range out.Errors {
				apiErr.Codes = append(apiErr.Codes, e.Code)
			}
		}
		// Neither decoding errors nor upstream bodies may echo a credential.
		return nil, apiErr
	}
	return &out, nil
}

func (c *Client) path() string {
	c.zoneMu.Lock()
	defer c.zoneMu.Unlock()
	return "/zones/" + url.PathEscape(c.zoneID) + "/dns_records"
}

func (c *Client) CheckZone(ctx context.Context, domain string) error {
	c.zoneMu.Lock()
	defer c.zoneMu.Unlock()
	if c.zoneID == "" {
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
			if len(zones) > 1 || res.Info.TotalPages > 1 {
				return fmt.Errorf("ambiguous cloudflare zone; configure zone_id explicitly")
			}
			if len(zones) == 1 {
				z := zones[0]
				if z.ID == "" || z.Name != name || z.Status != "active" {
					return fmt.Errorf("cloudflare returned an unexpected zone")
				}
				c.zoneID = z.ID
				return nil
			}
			_, name, _ = strings.Cut(name, ".")
		}
		return fmt.Errorf("no active cloudflare zone found for ACME domain")
	}

	res, err := c.request(ctx, http.MethodGet, "/zones/"+url.PathEscape(c.zoneID), nil)
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
	var all []Record
	for page := 1; page <= 100; page++ {
		q := url.Values{"name": {name}, "page": {strconv.Itoa(page)}, "per_page": {"100"}}
		res, err := c.request(ctx, http.MethodGet, c.path()+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var batch []Record
		if err = json.Unmarshal(res.Result, &batch); err != nil {
			return nil, fmt.Errorf("decode cloudflare records: %w", err)
		}
		all = append(all, batch...)
		if page >= res.Info.TotalPages {
			return all, nil
		}
	}
	return nil, fmt.Errorf("cloudflare Record pagination exceeds 100 pages")
}

func (c *Client) CreateRecord(ctx context.Context, r Record) (string, error) {
	res, err := c.request(ctx, http.MethodPost, c.path(), r)
	if err != nil {
		return "", err
	}
	var created Record
	if err = json.Unmarshal(res.Result, &created); err != nil {
		return "", fmt.Errorf("decode created cloudflare Record: %w", err)
	}
	if created.ID == "" {
		return "", fmt.Errorf("cloudflare created Record has no ID")
	}
	return created.ID, nil
}

func (c *Client) DeleteRecord(ctx context.Context, id string) error {
	_, err := c.request(ctx, http.MethodDelete, c.path()+"/"+url.PathEscape(id), nil)
	return err
}

const BaseURL = "https://api.cloudflare.com/client/v4"

// New constructs a client without network I/O. The HTTP client must have bounded timeouts.
func New(token, zoneID string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = HTTPClient()
	}
	return &Client{baseURL: BaseURL, token: token, zoneID: zoneID, http: httpClient}
}

// NewSource rereads credentials at request time, enabling token rotation.
func NewSource(source func() (string, error), zoneID string, httpClient *http.Client) *Client {
	c := New("", zoneID, httpClient)
	c.tokenSource = source
	return c
}

// UpdateRecord updates explicitly supplied fields, preserving unrelated record metadata.
func (c *Client) UpdateRecord(ctx context.Context, id string, fields RecordUpdate) error {
	_, err := c.request(ctx, http.MethodPatch, c.path()+"/"+url.PathEscape(id), fields)
	return err
}

// RecordUpdate changes only address ownership fields, preserving unrelated metadata.
type RecordUpdate struct {
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}
