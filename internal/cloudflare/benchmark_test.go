package cloudflare

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

type pageFixture []string

func (pages pageFixture) RoundTrip(r *http.Request) (*http.Response, error) {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 || page > len(pages) {
		return nil, fmt.Errorf("unexpected fixture page")
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, ContentLength: int64(len(pages[page-1])), Body: io.NopCloser(strings.NewReader(pages[page-1])), Request: r}, nil
}

// Includes bounded response decoding, record collection and pagination. No real
// network or fixture construction is included in the timed interval.
func BenchmarkListRecords(b *testing.B) {
	for _, count := range []int{2, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			pages := make(pageFixture, (count+99)/100)
			for page := range pages {
				var body strings.Builder
				body.WriteString(`{"success":true,"result":[`)
				for n := 0; n < 100 && page*100+n < count; n++ {
					if n > 0 {
						body.WriteByte(',')
					}
					fmt.Fprintf(&body, `{"id":"%032x","name":"relay.example.com","type":"TXT","content":"%s","ttl":60}`, page*100+n, strings.Repeat("x", 128))
				}
				fmt.Fprintf(&body, `],"result_info":{"total_pages":%d,"total_count":%d}}`, len(pages), count)
				pages[page] = body.String()
			}
			c := New("fixture", "zone", &http.Client{Transport: pages})
			b.ReportAllocs()
			for b.Loop() {
				records, err := c.ListRecords(b.Context(), "relay.example.com")
				if err != nil || len(records) != count {
					b.Fatal(len(records), err)
				}
			}
		})
	}
}
