// Package dns reconciles owned address records independently of ACME TXT records.
package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/fileio"
	"github.com/gatework/derper-go/internal/state"
)

type API interface {
	CheckZone(context.Context, string) error
	Records(context.Context, string) ([]cloudflare.Record, error)
	Create(context.Context, cloudflare.Record) (string, error)
	Patch(context.Context, string, any) error
}
type pending struct {
	Record cloudflare.Record `json:"record"`
	Since  time.Time         `json:"since"`
}
type journal struct {
	Owner   string                       `json:"owner"`
	Records map[string]cloudflare.Record `json:"records"`
	Pending map[string]pending           `json:"pending"`
}
type Change struct {
	Action string             `json:"action"`
	Before *cloudflare.Record `json:"before,omitempty"`
	After  cloudflare.Record  `json:"after"`
}
type Controller struct {
	Config config.Config
	API    API
	HTTP   *http.Client
}

func (c *Controller) load() (journal, error) {
	j := journal{Records: map[string]cloudflare.Record{}, Pending: map[string]pending{}}
	b, err := fileio.ReadRegularFile(filepath.Join(c.Config.StateDir, "dns.json"), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return j, err
	}
	if err = json.Unmarshal(b, &j); err != nil {
		return j, fmt.Errorf("decode DNS journal: %w", err)
	}
	if len(j.Owner) != 32 || j.Records == nil || j.Pending == nil {
		return j, errors.New("invalid DNS journal")
	}
	for typ, r := range j.Records {
		if (typ != "A" && typ != "AAAA") || r.Type != typ || r.Name != c.Config.Hostname || r.ID == "" || r.Comment != marker(j.Owner, typ) {
			return j, errors.New("DNS journal does not belong to this hostname")
		}
	}
	for typ, p := range j.Pending {
		if (typ != "A" && typ != "AAAA") || p.Record.Type != typ || p.Record.Name != c.Config.Hostname || p.Record.Comment != marker(j.Owner, typ) || p.Since.IsZero() {
			return j, errors.New("invalid pending DNS operation")
		}
	}
	return j, nil
}
func (c *Controller) save(j journal) error {
	return state.WriteJSON(filepath.Join(c.Config.StateDir, "dns.json"), j)
}
func marker(owner, typ string) string { return "derper-go:" + owner + ":" + typ }
func same(a, b cloudflare.Record) bool {
	return a.Type == b.Type && a.Name == b.Name && a.Content == b.Content && a.TTL == b.TTL && a.Proxied == b.Proxied && a.Comment == b.Comment
}

func (c *Controller) addresses(ctx context.Context) ([]cloudflare.Record, error) {
	v4 := c.Config.DNS.IPv4
	if c.Config.DNS.IPv4URL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Config.DNS.IPv4URL, nil)
		if err != nil {
			return nil, err
		}
		res, err := c.HTTP.Do(req)
		if err != nil {
			return nil, errors.New("public IPv4 discovery failed")
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("public IPv4 discovery HTTP %d", res.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, 65))
		if err != nil || len(b) > 64 {
			return nil, errors.New("invalid IPv4 discovery response")
		}
		v4 = strings.TrimSpace(string(b))
	}
	var records []cloudflare.Record
	for _, v := range []struct {
		typ, ip string
		v4      bool
	}{{"A", v4, true}, {"AAAA", c.Config.DNS.IPv6, false}} {
		if v.ip == "" {
			continue
		}
		ip, err := config.Address(v.ip, v.v4)
		if err != nil {
			return nil, err
		}
		records = append(records, cloudflare.Record{Type: v.typ, Name: c.Config.Hostname, Content: ip.String(), TTL: c.Config.DNS.TTL})
	}
	return records, nil
}

func (c *Controller) plan(ctx context.Context, j journal) ([]Change, error) {
	desired, err := c.addresses(ctx)
	if err != nil {
		return nil, err
	}
	if err = c.API.CheckZone(ctx, c.Config.Hostname); err != nil {
		return nil, err
	}
	records, err := c.API.Records(ctx, c.Config.Hostname)
	if err != nil {
		return nil, err
	}
	byType := map[string]cloudflare.Record{}
	for _, r := range records {
		if r.Name != c.Config.Hostname {
			return nil, errors.New("DNS API returned an unexpected hostname")
		}
		if r.Type == "CNAME" || r.Type == "NS" {
			return nil, fmt.Errorf("conflicting %s record", r.Type)
		}
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		if _, ok := byType[r.Type]; ok {
			return nil, fmt.Errorf("multiple %s records require manual resolution", r.Type)
		}
		if r.ID == "" {
			return nil, errors.New("DNS record has no ID")
		}
		byType[r.Type] = r
	}
	changes := make([]Change, 0, len(desired))
	for _, want := range desired {
		want.Comment = marker(j.Owner, want.Type)
		current, exists := byType[want.Type]
		if !exists {
			if _, owned := j.Records[want.Type]; owned {
				return nil, fmt.Errorf("managed %s record was deleted externally", want.Type)
			}
			if p, ok := j.Pending[want.Type]; ok && time.Since(p.Since) < 2*time.Minute {
				return nil, fmt.Errorf("%s creation outcome is pending; retry after two minutes", want.Type)
			}
			changes = append(changes, Change{Action: "create", After: want})
			continue
		}
		before := current
		change := Change{Before: &before, After: want}
		previous, owned := j.Records[want.Type]
		if p, ok := j.Pending[want.Type]; ok && same(current, p.Record) && (!owned || current.ID == previous.ID) {
			change.Action = "recover"
			change.After = current
		} else if owned {
			if current.ID != previous.ID || !same(current, previous) {
				return nil, fmt.Errorf("managed %s record changed externally; resolve the conflict before applying", want.Type)
			}
			change.Action = "update"
			if same(current, want) {
				change.Action = "noop"
			}
		} else {
			change.Action = "adopt"
		}
		changes = append(changes, change)
	}
	return changes, nil
}

// Plan performs no writes, including when the state directory does not exist yet.
func (c *Controller) Plan(ctx context.Context) ([]Change, error) {
	j, err := c.load()
	if err != nil {
		return nil, err
	}
	return c.plan(ctx, j)
}

// Apply requires the caller to hold the process state lock. Adoption is restricted
// to explicitly named records whose address/TTL/proxy settings already match.
func (c *Controller) Apply(ctx context.Context, adoptIDs ...string) ([]Change, error) {
	if c.Config.DNS.Mode != "manage" {
		return nil, errors.New("dns apply requires dns.mode=manage")
	}
	j, err := c.load()
	if err != nil {
		return nil, err
	}
	if j.Owner == "" {
		j.Owner, err = state.NewOwner()
		if err != nil {
			return nil, err
		}
		if err = c.save(j); err != nil {
			return nil, err
		}
	}
	changes, err := c.plan(ctx, j)
	if err != nil {
		return nil, err
	}
	// Check all adoptions before making the first remote change.
	adoptSet := map[string]bool{}
	for _, id := range adoptIDs {
		if id != "" {
			adoptSet[id] = true
		}
	}
	for _, ch := range changes {
		if ch.Action == "adopt" {
			before := *ch.Before
			before.Comment = ch.After.Comment
			if !adoptSet[ch.Before.ID] || !same(before, ch.After) {
				return nil, fmt.Errorf("%s record %s is not owned; match its address/TTL/proxy and use --adopt-record-id", ch.After.Type, ch.Before.ID)
			}
		}
	}
	for _, ch := range changes {
		if ch.Action == "noop" {
			continue
		}
		desired := ch.After
		if ch.Action == "recover" {
			j.Records[desired.Type] = desired
			delete(j.Pending, desired.Type)
			if err = c.save(j); err != nil {
				return changes, err
			}
			continue
		}
		j.Pending[desired.Type] = pending{Record: desired, Since: time.Now().UTC()}
		if err = c.save(j); err != nil {
			return changes, err
		}
		switch ch.Action {
		case "create":
			desired.ID, err = c.API.Create(ctx, desired)
		default:
			desired.ID = ch.Before.ID
			err = c.API.Patch(ctx, desired.ID, map[string]any{"content": desired.Content, "ttl": desired.TTL, "proxied": false, "comment": desired.Comment})
		}
		if err != nil {
			return changes, err
		}
		j.Records[desired.Type] = desired
		delete(j.Pending, desired.Type)
		if err = c.save(j); err != nil {
			return changes, err
		}
	}
	return changes, nil
}

// Run maintains DNS without terminating an otherwise usable relay on API errors.
func (c *Controller) Run(ctx context.Context, log *slog.Logger) {
	interval := time.Duration(c.Config.DNS.Interval)
	retry := min(interval, 30*time.Second)
	delay := time.Duration(0)
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		attempt, cancel := context.WithTimeout(ctx, time.Minute)
		var err error
		if c.Config.DNS.Mode == "manage" {
			_, err = c.Apply(attempt, "")
		} else {
			var changes []Change
			changes, err = c.Plan(attempt)
			if err == nil {
				for _, ch := range changes {
					if ch.Before == nil || ch.Before.Content != ch.After.Content || ch.Before.Proxied {
						err = errors.New("observed DNS does not match configured addresses")
						break
					}
				}
			}
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Warn("DNS maintenance failed", "error", err)
			delay = retry
			var apiErr *cloudflare.Error
			if errors.As(err, &apiErr) {
				delay = max(delay, apiErr.RetryAfter)
			}
			retry = min(interval, 15*time.Minute, retry*2)
		} else {
			delay = interval
			retry = min(interval, 30*time.Second)
		}
		delay += time.Duration(rand.Int64N(max(int64(delay/10), 1)))
	}
}
