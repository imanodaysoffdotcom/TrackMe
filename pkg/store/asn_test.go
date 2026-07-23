package store

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestParseIPAPI(t *testing.T) {
	body := []byte(`{"status":"success","country":"United States","countryCode":"US","isp":"Google LLC","org":"Google Public DNS","as":"AS15169 Google LLC","asname":"GOOGLE","query":"8.8.8.8"}`)
	got := parseIPAPI("8.8.8.8", body)
	if got.ASN != "AS15169" {
		t.Errorf("ASN = %q, want AS15169", got.ASN)
	}
	if got.ASName != "GOOGLE" || got.ISP != "Google LLC" || got.CountryCode != "US" {
		t.Errorf("fields wrong: %+v", got)
	}
	if !got.Available {
		t.Error("expected Available=true")
	}

	// A failure response (e.g. private range) yields an unavailable record.
	fail := parseIPAPI("10.0.0.1", []byte(`{"status":"fail","message":"private range","query":"10.0.0.1"}`))
	if fail.Available || fail.ASN != "" {
		t.Errorf("expected unavailable for failed lookup, got %+v", fail)
	}

	// `as` with no org and an empty asname still extracts the AS number.
	only := parseIPAPI("1.1.1.1", []byte(`{"status":"success","as":"AS13335","asname":"","isp":"Cloudflare"}`))
	if only.ASN != "AS13335" {
		t.Errorf("ASN = %q, want AS13335", only.ASN)
	}
}

func TestLookupASNCachesAndGuards(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	// Stub the free API and count hits.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"status":"success","as":"AS15169 Google LLC","asname":"GOOGLE","isp":"Google LLC","countryCode":"US"}`))
	}))
	defer srv.Close()
	old := asnAPIURL
	asnAPIURL = srv.URL + "/"
	defer func() { asnAPIURL = old }()

	// First lookup hits the API and caches.
	if _, err := s.LookupASN(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("api hits = %d, want 1", hits)
	}
	if !mr.Exists("asn:8.8.8.8") {
		t.Error("result was not cached")
	}
	// Second lookup is served from cache (no new API hit).
	if _, err := s.LookupASN(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("api hits = %d after cache, want 1", hits)
	}

	// HasIP guard: unknown vs seen.
	if s.HasIP(ctx, "9.9.9.9") {
		t.Error("HasIP true for never-seen IP")
	}
	s.rdb.ZAdd(ctx, "idx:ip:9.9.9.9", redis.Z{Score: 1, Member: "ck"})
	if !s.HasIP(ctx, "9.9.9.9") {
		t.Error("HasIP false for seen IP")
	}
}

// When the primary provider rate-limits us (429), the request is fulfilled in
// real time by the fallback, and the primary is parked in a cooldown.
func TestFetchASNFallsBackOnRateLimit(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	primaryHits, fbHits := 0, 0
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits++
		w.Header().Set("X-Ttl", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("rate limit exceeded"))
	}))
	defer primary.Close()
	fb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fbHits++
		_, _ = w.Write([]byte(`{"success":true,"country":"United States","country_code":"US","connection":{"asn":13335,"org":"Cloudflare, Inc.","isp":"Cloudflare"}}`))
	}))
	defer fb.Close()

	oldP, oldF := asnAPIURL, asnFallbackURL
	asnAPIURL, asnFallbackURL = primary.URL+"/", fb.URL+"/"
	defer func() { asnAPIURL, asnFallbackURL = oldP, oldF }()

	b, err := s.LookupASN(ctx, "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	var info ASNInfo
	if json.Unmarshal(b, &info) != nil {
		t.Fatal("bad json")
	}
	if info.Source != "ipwho.is" || info.ASN != "AS13335" {
		t.Errorf("expected fallback ipwho.is/AS13335, got %+v", info)
	}
	if primaryHits != 1 || fbHits != 1 {
		t.Errorf("hits: primary=%d fallback=%d, want 1/1", primaryHits, fbHits)
	}
	if !mr.Exists("asn:cooldown:ip-api.com") {
		t.Error("expected ip-api.com cooldown after 429")
	}

	// While the primary is cooling down, a new (uncached) lookup skips it entirely.
	primaryHits, fbHits = 0, 0
	if _, err := s.LookupASN(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if primaryHits != 0 {
		t.Errorf("primary was hit %d times while cooling down, want 0", primaryHits)
	}
	if fbHits != 1 {
		t.Errorf("fallback hit %d times, want 1", fbHits)
	}
}

// When the first two providers both rate-limit, the chain reaches the third
// (ipapi.co) and still fulfills the request.
func TestFetchASNChainsToThirdProvider(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	var h1, h2, h3 int
	limited := func(hits *int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*hits++
			w.WriteHeader(http.StatusTooManyRequests)
		}))
	}
	p1 := limited(&h1)
	defer p1.Close()
	p2 := limited(&h2)
	defer p2.Close()
	p3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h3++
		_, _ = w.Write([]byte(`{"asn":"AS15169","org":"GOOGLE","country_name":"United States","country_code":"US"}`))
	}))
	defer p3.Close()

	oa, ob, oc := asnAPIURL, asnFallbackURL, asnFallback2URL
	asnAPIURL, asnFallbackURL, asnFallback2URL = p1.URL+"/", p2.URL+"/", p3.URL+"/"
	defer func() { asnAPIURL, asnFallbackURL, asnFallback2URL = oa, ob, oc }()

	b, err := s.LookupASN(ctx, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	var info ASNInfo
	if json.Unmarshal(b, &info) != nil {
		t.Fatal("bad json")
	}
	if info.Source != "ipapi.co" || info.ASN != "AS15169" || info.ASName != "GOOGLE" {
		t.Errorf("expected ipapi.co/AS15169/GOOGLE, got %+v", info)
	}
	if h1 != 1 || h2 != 1 || h3 != 1 {
		t.Errorf("hits p1=%d p2=%d p3=%d, want 1/1/1", h1, h2, h3)
	}
}

func TestASNBackfillTargetsAndLock(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	// Stub the providers so the background warm-up never touches the real network.
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","as":"AS1 Example","isp":"Example"}`))
	}))
	defer stub.Close()
	oa, ob, oc := asnAPIURL, asnFallbackURL, asnFallback2URL
	asnAPIURL, asnFallbackURL, asnFallback2URL = stub.URL+"/", stub.URL+"/", stub.URL+"/"
	defer func() { asnAPIURL, asnFallbackURL, asnFallback2URL = oa, ob, oc }()

	// Three observed IPs; one already cached.
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		s.rdb.ZAdd(ctx, "idx:ip:"+ip, redis.Z{Score: 1, Member: "ck"})
	}
	s.rdb.Set(ctx, "asn:2.2.2.2", `{"ip":"2.2.2.2","available":true}`, 0)

	all, todo, err := s.asnBackfillTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || len(todo) != 2 { // only the two uncached need warming
		t.Errorf("all=%d todo=%d, want 3/2", len(all), len(todo))
	}

	// A held lock blocks a run (deterministic — no goroutine timing involved).
	s.rdb.Set(ctx, "asn:backfill:lock", "1", time.Minute)
	if _, _, err := s.BackfillASN(ctx, 0); err == nil {
		t.Error("expected rejection while the backfill lock is held")
	}
	s.rdb.Del(ctx, "asn:backfill:lock")

	// Happy path reports the right counts.
	sched, total, err := s.BackfillASN(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sched != 2 || total != 3 {
		t.Errorf("scheduled=%d total=%d, want 2/3", sched, total)
	}
}
