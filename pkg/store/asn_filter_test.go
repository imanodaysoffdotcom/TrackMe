package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestASNValues verifies the idx:asnset dropdown index: LookupASN resolves +
// caches an ASN and records it once; ASNValues returns the distinct display
// strings, and an empty store returns [] (not null).
func TestASNValues(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if b, _ := s.ASNValues(ctx); string(b) != "[]" {
		t.Errorf("ASNValues on empty store = %s, want []", b)
	}

	// Stub the ip-api provider so LookupASN resolves + caches + indexes.
	resp := map[string]string{
		"8.8.8.8": `{"status":"success","as":"AS15169 Google LLC","asname":"GOOGLE","isp":"Google LLC","countryCode":"US"}`,
		"1.1.1.1": `{"status":"success","as":"AS13335 Cloudflare, Inc.","asname":"CLOUDFLARENET","isp":"Cloudflare","countryCode":"US"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(resp[strings.TrimPrefix(r.URL.Path, "/")]))
	}))
	defer srv.Close()
	old := asnAPIURL
	asnAPIURL = srv.URL + "/"
	defer func() { asnAPIURL = old }()

	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "8.8.8.8"} { // 8.8.8.8 twice → one entry
		if _, err := s.LookupASN(ctx, ip); err != nil {
			t.Fatal(err)
		}
	}

	vb, err := s.ASNValues(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var vals []string
	_ = json.Unmarshal(vb, &vals)
	if len(vals) != 2 {
		t.Fatalf("ASNValues = %v, want 2 distinct ASNs", vals)
	}
	joined := strings.Join(vals, " | ")
	for _, want := range []string{"AS15169", "AS13335", "GOOGLE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ASNValues missing %q: %v", want, vals)
		}
	}
}

// TestListClientsASNFilter verifies the /api/clients ASN filter matches across
// the AS number, operator name and org, and excludes clients whose IP has no
// cached ASN while the filter is active.
func TestListClientsASNFilter(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	seedClient(t, s, "rand-att", "t13d_att", "11.11.11.11")
	seedClient(t, s, "rand-goog", "t13d_goog", "22.22.22.22")
	seedClient(t, s, "rand-none", "t13d_none", "33.33.33.33") // no cached ASN

	setASN := func(ip string, info ASNInfo) {
		b, _ := json.Marshal(info)
		if err := s.rdb.Set(ctx, "asn:"+ip, b, 0).Err(); err != nil {
			t.Fatal(err)
		}
	}
	setASN("11.11.11.11", ASNInfo{IP: "11.11.11.11", ASN: "AS7018", ASName: "ATT-INTERNET4", Org: "AT&T Services", Available: true})
	setASN("22.22.22.22", ASNInfo{IP: "22.22.22.22", ASN: "AS15169", ASName: "GOOGLE", Org: "Google LLC", Available: true})
	// 33.33.33.33 intentionally has no asn:<ip> entry.

	total := func(asnQ string) int {
		out, err := s.ListClients(ctx, 1, 100, "", "", "", "", "", true, false, "", "", nil, asnQ)
		if err != nil {
			t.Fatal(err)
		}
		var r struct {
			Total int `json:"total"`
		}
		_ = json.Unmarshal(out, &r)
		return r.Total
	}

	cases := []struct {
		q    string
		want int
		desc string
	}{
		{"", 3, "no asn filter → all clients"},
		{"7018", 1, "by AS number substring"},
		{"AS7018", 1, "by full AS number"},
		{"att", 1, "by operator name (case-insensitive)"},
		{"at&t", 1, "by org substring"},
		{"google", 1, "by other operator"},
		{"15169", 1, "by other AS number"},
		{"nonesuch", 0, "no ASN matches"},
	}
	for _, c := range cases {
		if got := total(c.q); got != c.want {
			t.Errorf("%s (asn=%q): total=%d, want %d", c.desc, c.q, got, c.want)
		}
	}
}
