package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/pagpeter/trackme/pkg/types"
)

// seedSPHBI writes a client whose SPHBI has a given kind + 18-byte hex image.
func seedSPHBI(t *testing.T, s *Store, rnd, ja4, kind, hexImg string) types.Response {
	t.Helper()
	r := types.Response{
		IP: "1.2.3.4:5", HTTPVersion: "h2", Method: "GET", Path: "/", UserAgent: "ua-" + rnd,
		TLS:   &types.TLSDetails{JA3: "j", JA3Hash: "jh", JA4: ja4, JA4_r: ja4 + "_r", PeetPrint: "pp", PeetPrintHash: "pph", ClientRandom: rnd},
		Http2: &types.Http2Details{AkamaiFingerprint: "ak", AkamaiFingerprintHash: "akh"},
		SPHBI: &types.SPHBIDetails{Kind: kind, Hex: hexImg, Size: 12},
	}
	if err := s.writeVisit(context.Background(), r); err != nil {
		t.Fatalf("writeVisit: %v", err)
	}
	return r
}

func TestSimilarClients(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	zero := strings.Repeat("00", 18)
	q := seedSPHBI(t, s, "q", "t13d_q", "ipv4", zero)                                // query: all zeros
	near := seedSPHBI(t, s, "near", "t13d_n", "ipv4", strings.Repeat("00", 17)+"01") // 1 bit differs
	far := seedSPHBI(t, s, "far", "t13d_f", "ipv4", strings.Repeat("00", 17)+"ff")   // 8 bits differ
	seedSPHBI(t, s, "other", "t13d_o", "quic", zero)                                 // different kind — excluded

	b, err := s.SimilarClients(ctx, ClientKey(q), 10)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Kind      string `json:"kind"`
		Neighbors []struct {
			Key      string `json:"client_key"`
			Distance int    `json:"distance"`
			Sim      int    `json:"similarity"`
		} `json:"neighbors"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Kind != "ipv4" {
		t.Errorf("kind = %q, want ipv4", out.Kind)
	}
	if len(out.Neighbors) != 2 {
		t.Fatalf("got %d neighbors, want 2 (near, far; self + quic excluded)", len(out.Neighbors))
	}
	if out.Neighbors[0].Key != ClientKey(near) || out.Neighbors[0].Distance != 1 {
		t.Errorf("nearest = %+v, want near d=1", out.Neighbors[0])
	}
	if out.Neighbors[1].Key != ClientKey(far) || out.Neighbors[1].Distance != 8 {
		t.Errorf("second = %+v, want far d=8", out.Neighbors[1])
	}
	if out.Neighbors[0].Sim != (144-1)*100/144 {
		t.Errorf("similarity = %d, want %d", out.Neighbors[0].Sim, (144-1)*100/144)
	}
	for _, nb := range out.Neighbors {
		if nb.Key == ClientKey(q) {
			t.Error("query client returned as its own neighbor")
		}
	}
}

// newTestStore returns a Store backed by an in-memory miniredis (no real Redis,
// no prod impact).
func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return &Store{rdb: rdb}, mr
}

func seedClient(t *testing.T, s *Store, clientRandom, ja4, ip string) types.Response {
	t.Helper()
	res := types.Response{
		IP:          ip + ":5555",
		HTTPVersion: "h2",
		Method:      "GET",
		Path:        "/",
		UserAgent:   "test-agent",
		TLS: &types.TLSDetails{
			JA3: "ja3", JA3Hash: "ja3h", JA4: ja4, JA4_r: ja4 + "_r",
			PeetPrint: "pp", PeetPrintHash: "pph", ClientRandom: clientRandom,
		},
		Http2: &types.Http2Details{AkamaiFingerprint: "ak", AkamaiFingerprintHash: "akh"},
	}
	if err := s.writeVisit(context.Background(), res); err != nil {
		t.Fatalf("writeVisit: %v", err)
	}
	return res
}

func TestDeleteClientRemovesAllKeysAndIndexes(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	res := seedClient(t, s, "rand-aaa", "t13d_aaa", "1.2.3.4")
	ck := ClientKey(res)

	// Precondition: the client, its conn, and all index memberships exist.
	if !mr.Exists("client:" + ck) {
		t.Fatal("seed failed: client hash missing")
	}
	if !mr.Exists("conn:rand-aaa") {
		t.Fatal("seed failed: conn missing")
	}

	n, err := s.DeleteClient(ctx, ck)
	if err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if n != 1 {
		t.Errorf("connections_removed = %d, want 1", n)
	}

	// Every per-client key and index membership must be gone.
	for _, k := range []string{"client:" + ck, "client:" + ck + ":ips", "client:" + ck + ":ports", "client:" + ck + ":conns", "conn:rand-aaa"} {
		if mr.Exists(k) {
			t.Errorf("key %q still exists after delete", k)
		}
	}
	if score, _ := s.rdb.ZScore(ctx, "idx:clients", ck).Result(); score != 0 {
		t.Error("idx:clients still references the deleted client")
	}
	if score, _ := s.rdb.ZScore(ctx, "idx:ip:1.2.3.4", ck).Result(); score != 0 {
		t.Error("idx:ip still references the deleted client")
	}
	if score, _ := s.rdb.ZScore(ctx, "idx:ja4:t13d_aaa", ck).Result(); score != 0 {
		t.Error("idx:ja4 still references the deleted client")
	}

	// Deleting a missing client is a no-op.
	if n, err := s.DeleteClient(ctx, "does-not-exist"); err != nil || n != 0 {
		t.Errorf("delete of missing client = (%d,%v), want (0,nil)", n, err)
	}
}

func TestDeleteClientLeavesOtherClientsIntact(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	a := ClientKey(seedClient(t, s, "rand-a", "t13d_a", "1.1.1.1"))
	b := ClientKey(seedClient(t, s, "rand-b", "t13d_b", "2.2.2.2"))

	if _, err := s.DeleteClient(ctx, a); err != nil {
		t.Fatal(err)
	}
	if !mrExistsClient(s, ctx, b) {
		t.Error("deleting client A removed client B")
	}
	if mrExistsClient(s, ctx, a) {
		t.Error("client A still present after delete")
	}
}

func mrExistsClient(s *Store, ctx context.Context, ck string) bool {
	n, _ := s.rdb.Exists(ctx, "client:"+ck).Result()
	return n == 1
}

func TestListClientsQueryParamFilter(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	a := seedClient(t, s, "rand-a", "t13d_a", "1.1.1.1")
	a.Path = "/?dee=money"
	_ = s.writeVisit(ctx, a)
	a.Path = "/api/clients?page=1" // /api noise — must be ignored by the filter
	_ = s.writeVisit(ctx, a)
	b := seedClient(t, s, "rand-b", "t13d_b", "2.2.2.2")
	b.Path = "/?foo=bar"
	_ = s.writeVisit(ctx, b)

	total := func(qp, qv string) int {
		out, err := s.ListClients(ctx, 1, 100, "", "", "", "", "", true, false, qp, qv, nil, "")
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
		qp, qv string
		want   int
		desc   string
	}{
		{"dee", "", 1, "by param name"},
		{"dee", "money", 1, "param + matching value"},
		{"dee", "wrong", 0, "param + wrong value"},
		{"", "bar", 1, "by value only"},
		{"page", "", 0, "param only in an /api/ path is ignored"},
		{"", "", 2, "no query filter returns all"},
	}
	for _, c := range cases {
		if got := total(c.qp, c.qv); got != c.want {
			t.Errorf("%s (qparam=%q qvalue=%q): total=%d, want %d", c.desc, c.qp, c.qv, got, c.want)
		}
	}
}

func TestScrapingHeaderFacet(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	visit := func(rnd, ja4, ip, path string) {
		r := seedClient(t, s, rnd, ja4, ip)
		r.Path = path
		_ = s.writeVisit(ctx, r)
	}
	visit("rand-a", "t13d_a", "1.1.1.1", "/?scraping-header=alpha")
	visit("rand-b", "t13d_b", "2.2.2.2", "/?scraping-header=beta")
	visit("rand-c", "t13d_c", "3.3.3.3", "/?scraping-header=alpha")        // shares alpha with A
	visit("rand-d", "t13d_d", "4.4.4.4", "/api/x?scraping-header=ignored") // /api/ must be ignored

	// QueryValues exposes the distinct non-/api/ values for the dropdown.
	vb, err := s.QueryValues(ctx, "scraping-header")
	if err != nil {
		t.Fatal(err)
	}
	var vals []string
	_ = json.Unmarshal(vb, &vals)
	set := map[string]bool{}
	for _, v := range vals {
		set[v] = true
	}
	if len(vals) != 2 || !set["alpha"] || !set["beta"] || set["ignored"] {
		t.Errorf("QueryValues = %v, want exactly {alpha, beta}", vals)
	}
	if nb, _ := s.QueryValues(ctx, "not-a-facet"); string(nb) != "[]" {
		t.Errorf("non-facet QueryValues = %s, want []", nb)
	}

	total := func(sh ...string) int {
		out, err := s.ListClients(ctx, 1, 100, "", "", "", "", "", true, false, "", "", sh, "")
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
		sh   []string
		want int
		desc string
	}{
		{[]string{"alpha"}, 2, "single value"},
		{[]string{"beta"}, 1, "other value"},
		{[]string{"alpha", "beta"}, 3, "multi-select is OR"},
		{[]string{"nope"}, 0, "unknown value"},
		{[]string{"ignored"}, 0, "value only on an /api/ path is excluded"},
	}
	for _, c := range cases {
		if got := total(c.sh...); got != c.want {
			t.Errorf("%s (shvalues=%v): total=%d, want %d", c.desc, c.sh, got, c.want)
		}
	}
}

func TestJA4Values(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Empty store → empty JSON array (not null).
	if b, _ := s.JA4Values(ctx); string(b) != "[]" {
		t.Errorf("JA4Values on empty store = %s, want []", b)
	}

	seedClient(t, s, "rand-a", "t13d1516h2_aaaa", "1.1.1.1")
	seedClient(t, s, "rand-b", "t13d1517h2_bbbb", "2.2.2.2")
	seedClient(t, s, "rand-c", "t13d1516h2_aaaa", "3.3.3.3") // same JA4 as A — must appear once

	vb, err := s.JA4Values(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var vals []string
	_ = json.Unmarshal(vb, &vals)
	set := map[string]bool{}
	for _, v := range vals {
		set[v] = true
	}
	// Unique across all collected clients: 3 visits, 2 distinct fingerprints.
	if len(vals) != 2 || !set["t13d1516h2_aaaa"] || !set["t13d1517h2_bbbb"] {
		t.Errorf("JA4Values = %v, want exactly the 2 distinct fingerprints (deduped)", vals)
	}
}

// A request's ?query must survive in recent_paths even when a later request on the
// same client (e.g. the page's /api/asn fetch) overwrites the per-connection path.
func TestRecentPathsRetainQuery(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	res := seedClient(t, s, "rand-q", "t13d_q", "9.9.9.9") // seeds with path "/"
	res.Path = "/?dee=money"
	if err := s.writeVisit(ctx, res); err != nil {
		t.Fatal(err)
	}
	res.Path = "/api/asn" // a later request on the same client
	if err := s.writeVisit(ctx, res); err != nil {
		t.Fatal(err)
	}

	b, err := s.GetClient(ctx, ClientKey(res))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		RecentPaths []struct {
			Path string `json:"path"`
		} `json:"recent_paths"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range d.RecentPaths {
		got = append(got, p.Path)
	}
	found := false
	for _, p := range got {
		if p == "/?dee=money" {
			found = true
		}
	}
	if !found {
		t.Errorf("recent_paths lost the query path; got %v", got)
	}
}

func TestDeleteAllWipesEverything(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	seedClient(t, s, "rand-1", "t13d_1", "1.1.1.1")
	seedClient(t, s, "rand-2", "t13d_2", "2.2.2.2")
	// An experiment row + collected index entry too.
	s.rdb.HSet(ctx, "exp:tok1", "ja4", "x")
	s.rdb.SAdd(ctx, "idx:experiments", "tok1")

	if len(mr.Keys()) == 0 {
		t.Fatal("seed failed: no keys")
	}
	n, err := s.DeleteAll(ctx)
	if err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	if n == 0 {
		t.Error("DeleteAll reported 0 keys removed")
	}
	if remaining := mr.Keys(); len(remaining) != 0 {
		t.Errorf("keys remain after DeleteAll: %v", remaining)
	}
}
