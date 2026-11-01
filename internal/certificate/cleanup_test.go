package certificate

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/derper-go/internal/cloudflare"
	"github.com/gatework/derper-go/internal/state"
)

func TestKnownTXTCleanupRequiresExactRecordOrProvenAbsence(t *testing.T) {
	for _, tc := range []struct {
		body    string
		status  int
		removed bool
	}{
		{`{"success":false,"errors":[{"code":81044}]}`, 404, true},
		{`<html>not found</html>`, 404, false},
		{`{"success":false,"errors":[{"code":7003}]}`, 404, false},
		{`{"success":true,"result":{"id":"other","type":"TXT","name":"_acme-challenge.relay.example.com"}}`, 200, false},
		{`{"success":true,"result":{"id":"owned","type":"TXT","name":"_acme-challenge.relay.example.com","content":"external","comment":"derper-acme-fixture"}}`, 200, false},
	} {
		t.Run(tc.body, func(t *testing.T) {
			options := renewalOptions(t)
			fixture := newACMEFixture(t, options.Domain)
			m := fixture.manager(t, options)
			defer m.Close()
			if err := m.openCache(); err != nil {
				t.Fatal(err)
			}
			transport := m.http.Transport
			reads := 0
			m.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if strings.HasSuffix(r.URL.Path, "/dns_records/owned") && r.Method == http.MethodGet {
					reads++
					return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
				}
				return transport.RoundTrip(r)
			})
			m.dns = cloudflare.NewSource(m.token, m.options.Cloudflare.ZoneID, m.http)
			path := filepath.Join(m.cachePath, "pending-txt.json")
			pending := record{ID: "owned", Type: "TXT", Name: "_acme-challenge." + options.Domain, Content: "expected", Comment: "derper-acme-fixture"}
			if err := state.WriteJSON(path, pending); err != nil {
				t.Fatal(err)
			}
			err := m.cleanupPending(t.Context())
			_, statErr := os.Stat(path)
			if (err == nil) != tc.removed || errors.Is(statErr, os.ErrNotExist) != tc.removed || reads != 1 {
				t.Fatal(err, statErr, reads)
			}
			fixture.mu.Lock()
			deletes := fixture.deleteAttempts
			fixture.mu.Unlock()
			if deletes != 0 {
				t.Fatal("deleted an unverified record")
			}
		})
	}
}
