package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestMissingPaginationContinuesUntilEmpty(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 2 {
			fmt.Fprint(w, `{"success":true,"result":[]}`)
			return
		}
		fmt.Fprintf(w, `{"success":true,"result":[{"id":"%d","name":"relay.example.com","type":"TXT"}]}`, calls)
	}))
	defer s.Close()
	c := New("fixture", "zone", s.Client())
	c.baseURL = s.URL
	records, err := c.ListRecords(t.Context(), "relay.example.com")
	if err != nil || len(records) != 2 || calls != 3 {
		t.Fatal(len(records), calls, err)
	}
}

func TestQueryBudgetAndChangingStatistics(t *testing.T) {
	for _, mode := range []string{"budget", "count", "changing", "wrong-name"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				name, content, total, count := "relay.example.com", "x", 20, 1
				if mode == "budget" {
					content = strings.Repeat("x", 900<<10)
				}
				if mode == "count" {
					count = 2
				}
				if mode == "changing" && page > 1 {
					total = 21
				}
				if mode == "wrong-name" {
					name = "other.example.com"
				}
				fmt.Fprintf(w, `{"success":true,"result":[{"id":"%d","name":%q,"type":"TXT","content":%q}],"result_info":{"page":%d,"count":%d,"total_pages":%d}}`, page, name, content, page, count, total)
			}))
			defer s.Close()
			c := New("fixture", "zone", s.Client())
			c.baseURL = s.URL
			if _, err := c.ListRecords(t.Context(), "relay.example.com"); err == nil {
				t.Fatal("invalid query accepted", mode, calls)
			}
		})
	}
}

func TestRecordAbsenceRequiresCloudflareProof(t *testing.T) {
	for _, body := range []string{`{"success":false,"errors":[{"code":81044}]}`, `{"success":false,"errors":[{"code":7003}]}`, `<html>not found</html>`} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404); fmt.Fprint(w, body) }))
		c := New("fixture", "zone", s.Client())
		c.baseURL = s.URL
		_, err := c.GetRecord(t.Context(), "record")
		s.Close()
		if errors.Is(err, ErrNotFound) != (strings.Contains(body, "81044")) {
			t.Fatal(body, err)
		}
	}
}

func TestPaginationBeyondOneHundredPages(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		fmt.Fprintf(w, `{"success":true,"result":[{"id":"%d","name":"relay.example.com","type":"TXT"}],"result_info":{"page":%d,"count":1,"total_pages":105,"total_count":105}}`, page, page)
	}))
	defer s.Close()
	c := New("fixture", "zone", s.Client())
	c.baseURL = s.URL
	all, err := c.ListRecords(t.Context(), "relay.example.com")
	if err != nil || len(all) != 105 {
		t.Fatal(len(all), err)
	}
}

func TestWriteFailureClassificationAndNoReplay(t *testing.T) {
	for _, tc := range []struct {
		body      string
		status    int
		uncertain bool
	}{
		{`{"success":false,"errors":[{"code":10000,"message":"fixture-secret"}]}`, 403, false},
		{`{"success":false,"errors":[{}]}`, 403, true},
		{`<html>fixture-secret</html>`, 403, true},
		{`{"success":false,"errors":[{"code":1000}]}`, 503, true},
	} {
		calls := 0
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.body)
		}))
		c := New("fixture", "zone", s.Client())
		c.baseURL = s.URL
		err := c.DeleteRecord(t.Context(), "expected")
		s.Close()
		if errors.Is(err, ErrUncertainWrite) != tc.uncertain || calls != 1 {
			t.Fatal(calls, err)
		}
	}
}

func TestMutationsRejectWrongIdentity(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":{"id":"wrong"}}`)
	}))
	defer s.Close()
	c := New("fixture", "zone", s.Client())
	c.baseURL = s.URL
	if err := c.UpdateRecord(context.Background(), "expected", RecordUpdate{}); err == nil {
		t.Fatal("update accepted wrong ID")
	}
	if err := c.DeleteRecord(context.Background(), "expected"); err == nil {
		t.Fatal("delete accepted wrong ID")
	}
}

func TestEarlyEmptyPageIsNotComplete(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"page":1,"total_pages":2,"total_count":1}}`)
	}))
	defer s.Close()
	c := New("fixture", "zone", s.Client())
	c.baseURL = s.URL
	if _, err := c.ListRecords(t.Context(), "relay.example.com"); err == nil {
		t.Fatal("incomplete list accepted")
	}
}
