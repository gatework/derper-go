// Package dns reconciles owned address records independently of ACME TXT records.
package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/fileio"
	"github.com/gatework/derper-go/internal/retry"
	"github.com/gatework/derper-go/internal/state"
)

type API interface {
	CheckZone(context.Context, string) error
	ListRecords(context.Context, string) ([]cloudflare.Record, error)
	CreateRecord(context.Context, cloudflare.Record) (string, error)
	UpdateRecord(context.Context, string, cloudflare.RecordUpdate) error
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

// Options holds DNS intent and its private journal location.
type Options struct {
	Domain, StateDir, IPv4, IPv6 string
	Publish, AutoIPv4            bool
	Approved                     []cloudflare.Record
}
type Publisher struct {
	options  Options
	api      API
	discover func(context.Context) (string, error)
}

func New(options Options, api API) *Publisher {
	options.Approved = append([]cloudflare.Record(nil), options.Approved...)
	return &Publisher{options: options, api: api, discover: DiscoverIPv4}
}

func (c *Publisher) load() (journal, error) {
	j := journal{Records: map[string]cloudflare.Record{}, Pending: map[string]pending{}}
	b, err := fileio.ReadRegularFile(filepath.Join(c.options.StateDir, "dns.json"), 1<<20)
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
		if (typ != "A" && typ != "AAAA") || r.Type != typ || r.Name != c.options.Domain || r.ID == "" || r.Comment != marker(j.Owner, typ) {
			return j, errors.New("DNS journal does not belong to this hostname")
		}
	}
	for typ, p := range j.Pending {
		if (typ != "A" && typ != "AAAA") || p.Record.Type != typ || p.Record.Name != c.options.Domain || p.Record.Comment != marker(j.Owner, typ) || p.Since.IsZero() {
			return j, errors.New("invalid pending DNS operation")
		}
	}
	return j, nil
}
func (c *Publisher) save(j journal) error {
	return state.WriteJSON(filepath.Join(c.options.StateDir, "dns.json"), j)
}
func marker(owner, typ string) string { return "derper-go:" + owner + ":" + typ }
func same(a, b cloudflare.Record) bool {
	return a.Type == b.Type && a.Name == b.Name && a.Content == b.Content && a.TTL == b.TTL && a.Proxied == b.Proxied && a.Comment == b.Comment
}

func (c *Publisher) addresses(ctx context.Context) ([]cloudflare.Record, error) {
	v4 := c.options.IPv4
	if c.options.AutoIPv4 {
		var err error
		v4, err = c.discover(ctx)
		if err != nil {
			return nil, err
		}
	}

	var records []cloudflare.Record
	for _, v := range []struct {
		typ, ip string
		v4      bool
	}{{"A", v4, true}, {"AAAA", c.options.IPv6, false}} {
		if v.ip == "" {
			continue
		}
		ip, err := config.Address(v.ip, v.v4)
		if err != nil {
			return nil, err
		}
		records = append(records, cloudflare.Record{Type: v.typ, Name: c.options.Domain, Content: ip.String(), TTL: 1})
	}
	return records, nil
}

func (c *Publisher) plan(ctx context.Context, j journal) ([]Change, error) {
	desired, err := c.addresses(ctx)
	if err != nil {
		return nil, err
	}
	if err = c.api.CheckZone(ctx, c.options.Domain); err != nil {
		return nil, err
	}
	records, err := c.api.ListRecords(ctx, c.options.Domain)
	if err != nil {
		return nil, err
	}
	byType := map[string]cloudflare.Record{}
	for _, r := range records {
		if r.Name != c.options.Domain {
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
			if current.Comment != "" {
				return nil, fmt.Errorf("%s 记录已有所有者标记，需要先人工解除归属", want.Type)
			}
			change.Action = "adopt"
		}
		changes = append(changes, change)
	}
	return changes, nil
}

// Plan performs no writes, including when the state directory does not exist yet.
func (c *Publisher) Plan(ctx context.Context) ([]Change, error) {
	j, err := c.load()
	if err != nil {
		return nil, err
	}
	return c.plan(ctx, j)
}

// Apply requires the caller to hold the process state lock. Adoption is restricted
// to explicitly approved, unchanged record snapshots without an owner marker.
func (c *Publisher) Apply(ctx context.Context, approved ...cloudflare.Record) ([]Change, error) {
	if !c.options.Publish {
		return nil, errors.New("DNS 发布已关闭")
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
	approvedSet := map[string]cloudflare.Record{}
	for _, r := range approved {
		approvedSet[r.ID] = r
	}

	for _, ch := range changes {
		if ch.Action == "adopt" {
			before := *ch.Before
			approved, ok := approvedSet[before.ID]
			if !ok || !same(approved, before) || before.Comment != "" {
				return nil, fmt.Errorf("%s 记录尚未批准接管或确认后已发生变化，请重新执行 dns plan", ch.After.Type)
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
			desired.ID, err = c.api.CreateRecord(ctx, desired)
		default:
			desired.ID = ch.Before.ID
			err = c.api.UpdateRecord(ctx, desired.ID, cloudflare.RecordUpdate{Content: desired.Content, TTL: desired.TTL, Proxied: false, Comment: desired.Comment})
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
func (c *Publisher) Run(ctx context.Context, log *slog.Logger, report func(error)) {
	interval := 5 * time.Minute
	backoff := min(interval, 30*time.Second)
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
		_, err = c.Apply(attempt, c.options.Approved...)

		cancel()
		if ctx.Err() != nil {
			return
		}
		if report != nil {
			report(err)
		}
		if err != nil {
			log.Warn("DNS maintenance failed", "error", err)
			delay = backoff
			var apiErr *cloudflare.Error
			if errors.As(err, &apiErr) {
				delay = max(delay, apiErr.RetryAfter)
			}
			backoff = retry.Next(backoff, interval)
		} else {
			delay = interval
			backoff = min(interval, 30*time.Second)
		}
		delay = retry.Jitter(delay)
	}
}
