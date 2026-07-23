package store

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/bits"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/pagpeter/trackme/pkg/geo"
	"github.com/pagpeter/trackme/pkg/types"
)

const (
	visitsStream  = "visits"
	visitsMaxLen  = 200000 // approximate cap on the full event log
	connTTL       = 90 * 24 * time.Hour
	connsKeep     = 1000   // newest connections retained per client
	pathsKeep     = 50     // newest distinct request paths retained per client
	collectedKeep = 100000 // newest trusted-collection requests indexed
	writeTimeout  = 5 * time.Second
	queueCapacity = 4096
)

// Store persists fingerprinted visits to Redis (off the request path) and serves
// the historical read queries.
type Store struct {
	rdb     *redis.Client
	ch      chan types.Response
	dropped int64
}

// New connects to Redis, verifies it, and starts the background writer.
func New(addr, password string) (*Store, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: 0})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, err
	}
	s := &Store{rdb: rdb, ch: make(chan types.Response, queueCapacity)}
	go s.writer()
	return s, nil
}

// Enqueue hands a finished Response to the async writer without blocking the
// request path. On a full queue the visit is dropped (counted), never blocked.
func (s *Store) Enqueue(res types.Response) {
	if s == nil {
		return
	}
	select {
	case s.ch <- res:
	default:
		if n := atomic.AddInt64(&s.dropped, 1); n%100 == 1 {
			log.Printf("store: write queue full, dropped %d visits", n)
		}
	}
}

func (s *Store) writer() {
	for res := range s.ch {
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		if err := s.writeVisit(ctx, res); err != nil {
			log.Printf("store: writeVisit error: %v", err)
		}
		cancel()
	}
}

func akamaiOf(res types.Response) (string, string) {
	if res.Http2 != nil {
		return res.Http2.AkamaiFingerprint, res.Http2.AkamaiFingerprintHash
	}
	if res.Http3 != nil {
		return res.Http3.AkamaiFingerprint, res.Http3.AkamaiFingerprintHash
	}
	return "", ""
}

// writeVisit performs the per-request fan-out across the three Redis views.
func (s *Store) writeVisit(ctx context.Context, res types.Response) error {
	ts := time.Now().Unix()
	connKey := ConnKey(res)
	clientKey := ClientKey(res)
	ip := HostOf(res.IP)
	port := PortOf(res.IP)

	resJSON, _ := json.Marshal(res)
	sphbiJSON := ""
	if res.SPHBI != nil {
		if b, err := json.Marshal(res.SPHBI); err == nil {
			sphbiJSON = string(b)
		}
	}
	var ja3, ja3h, ja4, ja4r, pp, pph string
	if res.TLS != nil {
		ja3, ja3h = res.TLS.JA3, res.TLS.JA3Hash
		ja4, ja4r = res.TLS.JA4, res.TLS.JA4_r
		pp, pph = res.TLS.PeetPrint, res.TLS.PeetPrintHash
	}
	clientRandom := ""
	if res.TLS != nil {
		clientRandom = res.TLS.ClientRandom
	}
	ak, akh := akamaiOf(res)

	connK := "conn:" + connKey
	clientK := "client:" + clientKey

	pipe := s.rdb.Pipeline()
	pipe.XAdd(ctx, &redis.XAddArgs{
		Stream: visitsStream, MaxLen: visitsMaxLen, Approx: true,
		Values: map[string]interface{}{
			"connKey": connKey, "clientKey": clientKey, "ip": ip, "port": port,
			"ja4": ja4, "method": res.Method, "path": res.Path, "ts": ts, "json": string(resJSON),
		},
	})
	// Per-connection record (HASH, 90-day TTL). http_version/client_random/path
	// stored explicitly because Response.Path is json:"-".
	pipe.HSet(ctx, connK, "json", string(resJSON), "http_version", res.HTTPVersion,
		"client_random", clientRandom, "path", res.Path, "last_seen", ts)
	pipe.HSetNX(ctx, connK, "first_seen", ts)
	pipe.HIncrBy(ctx, connK, "req_count", 1)
	pipe.Expire(ctx, connK, connTTL)
	// Per-unique-client rollup (kept indefinitely).
	pipe.HSet(ctx, clientK,
		"ja3", ja3, "ja3_hash", ja3h, "ja4", ja4, "ja4_r", ja4r,
		"peetprint", pp, "peetprint_hash", pph, "akamai", ak, "akamai_hash", akh,
		"http_version", res.HTTPVersion, "user_agent", res.UserAgent,
		"ja4t", res.TCPIP.JA4T,
		"sphbi_json", sphbiJSON, "last_seen", ts)
	pipe.HSetNX(ctx, clientK, "first_seen", ts)
	visitCmd := pipe.HIncrBy(ctx, clientK, "visit_count", 1)
	pipe.SAdd(ctx, clientK+":ips", ip)
	pipe.SAdd(ctx, clientK+":ports", port)
	ipCardCmd := pipe.SCard(ctx, clientK+":ips")
	pipe.ZAdd(ctx, clientK+":conns", redis.Z{Score: float64(ts), Member: connKey})
	pipe.ZRemRangeByRank(ctx, clientK+":conns", 0, -(connsKeep + 1))
	// Per-request paths (deduped, newest pathsKeep). Unlike the per-connection
	// `path` (overwritten when requests share a connection), this keeps each
	// distinct request target — so a visit's ?query survives for the UI.
	if res.Path != "" && res.Path != "--" {
		pipe.ZAdd(ctx, clientK+":paths", redis.Z{Score: float64(ts), Member: res.Path})
		pipe.ZRemRangeByRank(ctx, clientK+":paths", 0, -(pathsKeep + 1))
		// Real-time facet index: record distinct values of faceted query params so
		// new values become filter options with no intervention or code change.
		if qi := strings.IndexByte(res.Path, '?'); qi >= 0 && !strings.HasPrefix(res.Path, "/api/") {
			if vals, err := url.ParseQuery(res.Path[qi+1:]); err == nil {
				for name, vv := range vals {
					if !facetParams[strings.ToLower(name)] {
						continue
					}
					fk := "idx:qval:" + strings.ToLower(name)
					for _, v := range vv {
						if v != "" {
							pipe.ZAdd(ctx, fk, redis.Z{Score: float64(ts), Member: v})
						}
					}
					pipe.ZRemRangeByRank(ctx, fk, 0, -(qvalCap + 1))
				}
			}
		}
	}
	pipe.ZAdd(ctx, "idx:clients", redis.Z{Score: float64(ts), Member: clientKey})
	if ip != "" {
		pipe.ZAdd(ctx, "idx:ip:"+ip, redis.Z{Score: float64(ts), Member: clientKey})
	}
	if ja4 != "" {
		pipe.ZAdd(ctx, "idx:ja4:"+ja4, redis.Z{Score: float64(ts), Member: clientKey})
		// Distinct-JA4 set for the filter dropdown: one ZSET of every JA4 seen
		// (score = recency, member = the fingerprint), so the option list grows
		// automatically and each fingerprint is listed once across all clients.
		pipe.ZAdd(ctx, "idx:ja4set", redis.Z{Score: float64(ts), Member: ja4})
		pipe.ZRemRangeByRank(ctx, "idx:ja4set", 0, -(ja4Cap + 1))
	}
	// SPHBI similarity index: per-kind clientKey -> 18-byte hex image, so the
	// "similar clients" feature can brute-force Hamming-scan within a kind. The
	// clientKey already incorporates the SPHBI, so this entry is stable.
	if res.SPHBI != nil && res.SPHBI.Kind != "" && res.SPHBI.Hex != "" {
		pipe.HSet(ctx, "idx:sphbi:"+res.SPHBI.Kind, clientKey, res.SPHBI.Hex)
	}
	// Controlled-experiment binding: token -> this connection's exact fingerprint.
	// Causal — the token rode in the request that produced this very res.
	if res.Exp != "" {
		sphbiHex, sphbiKind, sphbiBits := "", "", ""
		if res.SPHBI != nil {
			sphbiHex, sphbiKind, sphbiBits = res.SPHBI.Hex, res.SPHBI.Kind, res.SPHBI.Bits
		}
		pipe.HSet(ctx, "exp:"+res.Exp,
			"sphbi_hex", sphbiHex, "sphbi_kind", sphbiKind, "sphbi_bits", sphbiBits,
			"ja3", ja3, "ja3_hash", ja3h, "ja4", ja4, "ja4_r", ja4r,
			"peetprint", pp, "peetprint_hash", pph, "akamai", ak, "akamai_hash", akh,
			"ja4t", res.TCPIP.JA4T,
			"user_agent", res.UserAgent, "ip", ip, "source_port", port,
			"http_version", res.HTTPVersion, "captured_ts", ts)
		pipe.SAdd(ctx, "idx:experiments", res.Exp)
	}
	// Trusted request-parameter capture: the full request (incl. body) is already
	// in resJSON (Response.Request), so the conn record holds request+fingerprint
	// together. Also store it as an explicit conn field so GetClient can surface it
	// per-connection cheaply (no full-JSON parse). Index it for the training-data
	// pull; trim to the newest set so the index can't grow unbounded as old conn
	// records expire.
	if res.Request != nil {
		if rb, err := json.Marshal(res.Request); err == nil {
			pipe.HSet(ctx, connK, "request_json", string(rb))
		}
		pipe.HIncrBy(ctx, clientK, "collected_count", 1) // list-view discoverability badge
		pipe.ZAdd(ctx, "idx:collected", redis.Z{Score: float64(ts), Member: connKey})
		pipe.ZRemRangeByRank(ctx, "idx:collected", 0, -(collectedKeep + 1))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}

	// Second flush: rebuild the denormalized summary with the now-known counts.
	visitCount := visitCmd.Val()
	ipCount := ipCardCmd.Val()
	firstSeen, _ := s.rdb.HGet(ctx, clientK, "first_seen").Int64()
	summary := SummaryJSON(res, visitCount, ipCount, ts, firstSeen)
	return s.rdb.HSet(ctx, clientK, "summary_json", summary, "ip_count", ipCount).Err()
}

// facetScrapingHeader is the query parameter whose distinct values power the
// multi-select facet filter.
const facetScrapingHeader = "scraping-header"

// facetParams are the query-parameter names whose distinct values are indexed for
// the faceted (multi-select) filter. New VALUES are discovered automatically in
// real time; adding a new facet PARAM here is the only code change one needs.
var facetParams = map[string]bool{facetScrapingHeader: true}

// qvalCap bounds the distinct values kept per faceted param (newest-first).
const qvalCap = 1000

// ja4Cap bounds the distinct JA4 fingerprints kept for the filter dropdown
// (newest-first). Generous so the picker reflects essentially everything we've
// collected; the search box in the dropdown keeps a long list usable.
const ja4Cap = 5000

// asnSetCap bounds the distinct ASNs kept for the filter dropdown (newest-first).
const asnSetCap = 2000

// pathsMatchFacet reports whether any non-/api/ path carries the exact query
// parameter `param` (lowercased) with a value in valueSet (exact match).
func pathsMatchFacet(paths []string, param string, valueSet map[string]bool) bool {
	for _, p := range paths {
		if strings.HasPrefix(p, "/api/") {
			continue
		}
		qi := strings.IndexByte(p, '?')
		if qi < 0 {
			continue
		}
		vals, err := url.ParseQuery(p[qi+1:])
		if err != nil {
			continue
		}
		for name, vv := range vals {
			if strings.ToLower(name) != param {
				continue
			}
			for _, v := range vv {
				if valueSet[v] {
					return true
				}
			}
		}
	}
	return false
}

// QueryValues returns the distinct observed values of a faceted query parameter,
// newest-first, as a JSON array — the option list for the multi-select filter. A
// non-faceted (or unseen) param yields an empty array.
func (s *Store) QueryValues(ctx context.Context, param string) ([]byte, error) {
	param = strings.ToLower(param)
	if !facetParams[param] {
		return []byte("[]"), nil
	}
	vals, err := s.rdb.ZRevRange(ctx, "idx:qval:"+param, 0, qvalCap-1).Result()
	if err != nil {
		return nil, err
	}
	if vals == nil {
		vals = []string{}
	}
	return json.Marshal(vals)
}

// JA4Values returns the distinct JA4 fingerprints collected so far, newest-first,
// as a JSON array — the option list for the JA4 filter dropdown. The set grows
// automatically as new fingerprints arrive and each value appears exactly once
// across all clients (capped at ja4Cap most-recent distinct fingerprints).
func (s *Store) JA4Values(ctx context.Context) ([]byte, error) {
	vals, err := s.rdb.ZRevRange(ctx, "idx:ja4set", 0, ja4Cap-1).Result()
	if err != nil {
		return nil, err
	}
	if vals == nil {
		vals = []string{}
	}
	return json.Marshal(vals)
}

// ASNValues returns the distinct ASN display strings ("<asn> · <operator>") seen
// across all clients, newest-first (capped at asnSetCap). Backs the ASN filter
// dropdown. Mirrors JA4Values.
func (s *Store) ASNValues(ctx context.Context) ([]byte, error) {
	vals, err := s.rdb.ZRevRange(ctx, "idx:asnset", 0, asnSetCap-1).Result()
	if err != nil {
		return nil, err
	}
	if vals == nil {
		vals = []string{}
	}
	return json.Marshal(vals)
}

// asnMatchesAny reports whether any of ips has a cached ASN whose number, name,
// org or ISP contains q (q already lowercased). Clients with no cached ASN never
// match, so they are excluded while an ASN filter is active.
func asnMatchesAny(ips []string, q string, byIP map[string]ASNInfo) bool {
	for _, ip := range ips {
		info, ok := byIP[ip]
		if !ok {
			continue
		}
		for _, f := range []string{info.ASN, info.ASName, info.Org, info.ISP} {
			if f != "" && strings.Contains(strings.ToLower(f), q) {
				return true
			}
		}
	}
	return false
}

// pathsMatchQuery reports whether any of paths (excluding the page's own /api/
// calls) carries a URL query parameter whose name contains qparam AND value
// contains qvalue, on the same parameter. Either filter may be empty (matches
// any). qparam/qvalue are expected lowercased.
func pathsMatchQuery(paths []string, qparam, qvalue string) bool {
	for _, p := range paths {
		if strings.HasPrefix(p, "/api/") {
			continue
		}
		qi := strings.IndexByte(p, '?')
		if qi < 0 {
			continue
		}
		vals, err := url.ParseQuery(p[qi+1:])
		if err != nil {
			continue
		}
		for name, vv := range vals {
			if qparam != "" && !strings.Contains(strings.ToLower(name), qparam) {
				continue
			}
			for _, v := range vv {
				if qvalue == "" || strings.Contains(strings.ToLower(v), qvalue) {
					return true
				}
			}
		}
	}
	return false
}

// ListClients returns a paginated client list. Default order is most-recent-first
// (sortBy "" / "last_seen", desc). Optional filters: kind (exact ipv4/ipv6/quic),
// ipQ (substring vs any of the client's IPs), ja4Q (substring vs JA4),
// uaQ (substring vs User-Agent), collectedOnly (only clients with >=1 captured
// request), qparam/qvalue (substring vs a URL query parameter name/value seen in
// the client's request paths), shvalues (faceted multi-select: keep clients whose
// `scraping-header` query value is exactly one of these). Filtering and sorting
// span the whole dataset, not just one page.
func (s *Store) ListClients(ctx context.Context, page, perPage int, kind, ipQ, ja4Q, uaQ, sortBy string, desc, collectedOnly bool, qparam, qvalue string, shvalues []string, asnQ string) ([]byte, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 25
	}
	// Scan EVERY tagged client (0..-1), NOT just the newest 5,000. Bounding to
	// the newest 5,000 silently truncated the tab once the DB grew past the cap
	// (observed at 6,588 clients): the reported `total`, pagination, sort, and the
	// kind/ja4/ua/ip filters all only saw the newest 5,000, so the oldest ~1,500
	// clients were unreachable and "earliest"-sort returned the wrong record — with
	// no error shown. `total = len(cands)` is now the true population (no filter) or
	// the true filtered count. Mirrors GroupedUniqueByScrapingHeader's full scan.
	keys, err := s.rdb.ZRevRange(ctx, "idx:clients", 0, -1).Result()
	if err != nil {
		return nil, err
	}

	shSet := map[string]bool{} // selected scraping-header values (exact match)
	for _, v := range shvalues {
		if v = strings.TrimSpace(v); v != "" {
			shSet[v] = true
		}
	}
	queryFilter := qparam != "" || qvalue != "" || len(shSet) > 0
	pipe := s.rdb.Pipeline()
	sumCmds := make([]*redis.StringCmd, len(keys))
	ipCmds := make([]*redis.StringSliceCmd, len(keys))
	collCmds := make([]*redis.StringCmd, len(keys))
	var pathCmds []*redis.StringSliceCmd
	if queryFilter {
		pathCmds = make([]*redis.StringSliceCmd, len(keys))
	}
	for i, k := range keys {
		sumCmds[i] = pipe.HGet(ctx, "client:"+k, "summary_json")
		ipCmds[i] = pipe.SMembers(ctx, "client:"+k+":ips")
		collCmds[i] = pipe.HGet(ctx, "client:"+k, "collected_count")
		if queryFilter {
			pathCmds[i] = pipe.ZRange(ctx, "client:"+k+":paths", 0, -1)
		}
	}
	_, _ = pipe.Exec(ctx)

	kind, ipQ, ja4Q, uaQ = strings.ToLower(kind), strings.ToLower(ipQ), strings.ToLower(ja4Q), strings.ToLower(uaQ)
	qparam, qvalue = strings.ToLower(qparam), strings.ToLower(qvalue)
	asnQ = strings.ToLower(asnQ)

	// ASN filter: resolve each observed IP's cached ASN once (asn:<ip>), then
	// substring-match the AS number / operator name below. Only cached ASNs
	// count; a client with no cached ASN is excluded while the filter is set.
	var asnByIP map[string]ASNInfo
	if asnQ != "" {
		ipset := map[string]struct{}{}
		for i := range keys {
			for _, ip := range ipCmds[i].Val() {
				ipset[ip] = struct{}{}
			}
		}
		asnByIP = make(map[string]ASNInfo, len(ipset))
		if len(ipset) > 0 {
			ap := s.rdb.Pipeline()
			order := make([]string, 0, len(ipset))
			cmds := make([]*redis.StringCmd, 0, len(ipset))
			for ip := range ipset {
				order = append(order, ip)
				cmds = append(cmds, ap.Get(ctx, "asn:"+ip))
			}
			_, _ = ap.Exec(ctx)
			for j, ip := range order {
				if v, e := cmds[j].Result(); e == nil && v != "" {
					var info ASNInfo
					if json.Unmarshal([]byte(v), &info) == nil {
						asnByIP[ip] = info
					}
				}
			}
		}
	}

	type cand struct {
		raw    map[string]json.RawMessage
		last   int64
		first  int64
		visits int64
		ipc    int64
		ja4    string
		ua     string
		kind   string
	}
	cands := make([]cand, 0, len(keys))
	for i, k := range keys {
		raw, err := sumCmds[i].Result()
		if err != nil || raw == "" {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &m) != nil {
			continue
		}
		ips, _ := ipCmds[i].Result()
		sort.Strings(ips) // deterministic display IP
		ck, _ := json.Marshal(k)
		m["client_key"] = ck
		dispIP := ""
		if len(ips) > 0 {
			dispIP = ips[0]
		}
		ipJSON, _ := json.Marshal(dispIP)
		m["ip"] = ipJSON
		// Count of captured (trusted-collection) requests, for the list-view badge
		// and the "only captured" filter.
		collected := int64(0)
		if cc, _ := collCmds[i].Result(); cc != "" {
			collected, _ = strconv.ParseInt(cc, 10, 64)
		}
		if collected > 0 {
			m["collected"] = json.RawMessage(strconv.FormatInt(collected, 10))
		}
		if collectedOnly && collected == 0 {
			continue
		}

		c := cand{raw: m}
		_ = json.Unmarshal(m["last_seen"], &c.last)
		_ = json.Unmarshal(m["first_seen"], &c.first)
		_ = json.Unmarshal(m["visit_count"], &c.visits)
		_ = json.Unmarshal(m["ip_count"], &c.ipc)
		_ = json.Unmarshal(m["ja4"], &c.ja4)
		_ = json.Unmarshal(m["user_agent"], &c.ua)
		var sp struct {
			Kind string `json:"kind"`
		}
		if m["sphbi"] != nil {
			_ = json.Unmarshal(m["sphbi"], &sp)
		}
		c.kind = sp.Kind

		if kind != "" && strings.ToLower(c.kind) != kind {
			continue
		}
		if ja4Q != "" && !strings.Contains(strings.ToLower(c.ja4), ja4Q) {
			continue
		}
		if uaQ != "" && !strings.Contains(strings.ToLower(c.ua), uaQ) {
			continue
		}
		if ipQ != "" {
			matched := false
			for _, ip := range ips {
				if strings.Contains(strings.ToLower(ip), ipQ) {
					if mj, e := json.Marshal(ip); e == nil {
						m["ip"] = mj // surface the IP that matched the filter
					}
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if asnQ != "" && !asnMatchesAny(ips, asnQ, asnByIP) {
			continue
		}
		if queryFilter {
			paths := pathCmds[i].Val()
			if (qparam != "" || qvalue != "") && !pathsMatchQuery(paths, qparam, qvalue) {
				continue
			}
			if len(shSet) > 0 && !pathsMatchFacet(paths, facetScrapingHeader, shSet) {
				continue
			}
		}
		cands = append(cands, c)
	}

	less := func(a, b cand) bool {
		switch sortBy {
		case "first_seen":
			return a.first < b.first
		case "visits":
			return a.visits < b.visits
		case "ips":
			return a.ipc < b.ipc
		case "kind":
			return a.kind < b.kind
		case "ja4":
			return a.ja4 < b.ja4
		case "ua":
			return a.ua < b.ua
		default: // last_seen
			return a.last < b.last
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if desc {
			return less(cands[j], cands[i])
		}
		return less(cands[i], cands[j])
	})

	total := len(cands)
	startIdx := (page - 1) * perPage
	if startIdx > total {
		startIdx = total
	}
	endIdx := startIdx + perPage
	if endIdx > total {
		endIdx = total
	}
	clients := make([]json.RawMessage, 0, perPage)
	for _, c := range cands[startIdx:endIdx] {
		if merged, err := json.Marshal(c.raw); err == nil {
			clients = append(clients, merged)
		}
	}
	out := map[string]interface{}{
		"total": total, "page": page, "per_page": perPage, "clients": clients,
	}
	return json.Marshal(out)
}

// pathsFacetValues returns the distinct values of facet param `param` present in
// the non-/api/ query strings of `paths` — the value-extracting counterpart of
// pathsMatchFacet (which only returns a bool).
func pathsFacetValues(paths []string, param string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range paths {
		if strings.HasPrefix(p, "/api/") {
			continue
		}
		qi := strings.IndexByte(p, '?')
		if qi < 0 {
			continue
		}
		vals, err := url.ParseQuery(p[qi+1:])
		if err != nil {
			continue
		}
		for name, vv := range vals {
			if strings.ToLower(name) != param {
				continue
			}
			for _, v := range vv {
				if v != "" && !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// GroupedUniqueByScrapingHeader powers the Comparative tab's "unique images per
// scraping-header group" view. It scans the entire client population ONCE
// (newest-first) and returns, per distinct scraping-header value, the
// DE-DUPLICATED set of SPHBI images (one representative client per distinct
// kind+bits image). This replaces the old frontend behaviour of issuing one
// /api/clients scan PER value — turning O(values x clients) work over N HTTP
// round-trips into O(clients) over a single round-trip.
//
// It mirrors ListClients' scan+filter so the same filter bar applies identically;
// the scan is duplicated (rather than shared) to keep the hot, well-tested
// ListClients path untouched.
func (s *Store) GroupedUniqueByScrapingHeader(ctx context.Context, kind, ja4Q, uaQ, qparam, qvalue string, shvalues []string, groupCap int) ([]byte, error) {
	if groupCap < 1 {
		groupCap = 50
	}
	// Explicitly selected scraping-header values (exact match, mirrors ListClients).
	// When non-empty the caller wants ONLY these groups, and they must NEVER be
	// dropped by the groupCap truncation below — otherwise a selected value whose
	// group sorts past rank `groupCap` during the newest-first scan would vanish and
	// the UI would render "no groups match" even though its images exist in Redis.
	shSet := map[string]bool{}
	for _, v := range shvalues {
		if v = strings.TrimSpace(v); v != "" {
			shSet[v] = true
		}
	}
	// Scan EVERY tagged client (0..-1), NOT just the newest 5,000. The grouped
	// view's whole purpose is to surface every distinct labelled image regardless of
	// age; bounding it to the newest 5,000 made older scraper captures silently
	// vanish once the DB grew past the cap (observed at 6,304 clients). One pass over
	// all clients; for a far larger dataset a write-time index (idx:sphbiuniq:<value>)
	// would replace the scan entirely.
	keys, err := s.rdb.ZRevRange(ctx, "idx:clients", 0, -1).Result()
	if err != nil {
		return nil, err
	}

	// Only TWO reads per client (summary + paths). The IP and "only-collected"
	// filters are intentionally not supported in this view, which keeps the single
	// scan as cheap as possible; kind/ja4/ua/qparam/qvalue still apply.
	pipe := s.rdb.Pipeline()
	sumCmds := make([]*redis.StringCmd, len(keys))
	pathCmds := make([]*redis.StringSliceCmd, len(keys))
	for i, k := range keys {
		sumCmds[i] = pipe.HGet(ctx, "client:"+k, "summary_json")
		pathCmds[i] = pipe.ZRange(ctx, "client:"+k+":paths", 0, -1)
	}
	_, _ = pipe.Exec(ctx)

	kind, ja4Q, uaQ = strings.ToLower(kind), strings.ToLower(ja4Q), strings.ToLower(uaQ)
	qparam, qvalue = strings.ToLower(qparam), strings.ToLower(qvalue)

	type grp struct {
		order   int
		total   int             // distinct images in this group (may exceed len(clients))
		seen    map[string]bool // dedup key = kind + ":" + bits
		clients []json.RawMessage
	}
	const imgCap = 200 // max RENDERED images per group; the true distinct count is still reported as `total`
	groups := map[string]*grp{}
	nextOrder := 0

	for i, k := range keys {
		raw, e := sumCmds[i].Result()
		if e != nil || raw == "" {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &m) != nil {
			continue
		}
		var sp struct {
			Kind string `json:"kind"`
			Bits string `json:"bits"`
			Size int    `json:"size"`
		}
		if m["sphbi"] == nil || json.Unmarshal(m["sphbi"], &sp) != nil || sp.Bits == "" {
			continue // only clients that actually carry an image belong here
		}
		if kind != "" && strings.ToLower(sp.Kind) != kind {
			continue
		}
		if ja4Q != "" {
			var ja4 string
			_ = json.Unmarshal(m["ja4"], &ja4)
			if !strings.Contains(strings.ToLower(ja4), ja4Q) {
				continue
			}
		}
		if uaQ != "" {
			var ua string
			_ = json.Unmarshal(m["user_agent"], &ua)
			if !strings.Contains(strings.ToLower(ua), uaQ) {
				continue
			}
		}
		paths := pathCmds[i].Val()
		if (qparam != "" || qvalue != "") && !pathsMatchQuery(paths, qparam, qvalue) {
			continue
		}
		facetVals := pathsFacetValues(paths, facetScrapingHeader)
		if len(facetVals) == 0 {
			continue
		}

		// Slim representative card: ONLY what the Comparative grid renders — client_key,
		// a minimal sphbi {bits,kind,size}, and user_agent. The full summary sphbi also
		// carries hex + an 11-field byte breakdown (~1 KB/card) that must NOT be shipped
		// here, or the response balloons (766 images × ~1 KB ≈ 800 KB).
		ckJSON, _ := json.Marshal(k)
		slimSphbi, _ := json.Marshal(map[string]interface{}{"bits": sp.Bits, "kind": sp.Kind, "size": sp.Size})
		card := map[string]json.RawMessage{"client_key": ckJSON, "sphbi": slimSphbi}
		if ua, ok := m["user_agent"]; ok {
			card["user_agent"] = ua
		}
		merged, mErr := json.Marshal(card)
		if mErr != nil {
			continue
		}
		imgKey := sp.Kind + ":" + sp.Bits
		for _, v := range facetVals {
			g := groups[v]
			if g == nil {
				g = &grp{order: nextOrder, seen: map[string]bool{}}
				nextOrder++
				groups[v] = g
			}
			if g.seen[imgKey] {
				continue
			}
			g.seen[imgKey] = true
			g.total++
			if len(g.clients) < imgCap { // keep the true count, but cap what we render
				g.clients = append(g.clients, merged)
			}
		}
	}

	// Order groups by first appearance (newest client first, since the scan is
	// newest-first), then cap.
	values := make([]string, 0, len(groups))
	for v := range groups {
		values = append(values, v)
	}
	sort.Slice(values, func(a, b int) bool { return groups[values[a]].order < groups[values[b]].order })
	truncated := false
	if len(shSet) > 0 {
		// A selection is active: return EXACTLY the requested groups, in scan order,
		// with no cap truncation. The response size is bounded by what the user chose
		// (× imgCap per group), so the groupCap ceiling does not apply here.
		sel := values[:0]
		for _, v := range values {
			if shSet[v] {
				sel = append(sel, v)
			}
		}
		values = sel
	} else if len(values) > groupCap {
		values = values[:groupCap]
		truncated = true
	}
	type outGroup struct {
		Value   string            `json:"value"`
		Total   int               `json:"total"`
		Clients []json.RawMessage `json:"clients"`
	}
	outGroups := make([]outGroup, 0, len(values))
	for _, v := range values {
		outGroups = append(outGroups, outGroup{Value: v, Total: groups[v].total, Clients: groups[v].clients})
	}
	return json.Marshal(map[string]interface{}{"groups": outGroups, "truncated": truncated})
}

// browserstackSweep is the scraping-header value the BrowserStack device sweep tags
// every request with; clients carrying it are the "BrowserStack device" side of the
// Visual Analysis graph (everything else is a scraper).
const browserstackSweep = "browserstack-device-sweep"

// bsDevice identifies one BrowserStack device from a device-sweep request's query
// params (the sweep tags every request with device/os/os_version).
type bsDevice struct{ device, os, osVersion string }

// bsDeviceLabel renders a device as "device · os ver" for a right-hand graph node.
func bsDeviceLabel(d bsDevice) string {
	label := strings.TrimSpace(d.device)
	if meta := strings.TrimSpace(d.os + " " + d.osVersion); meta != "" {
		if label != "" {
			label += " · " + meta
		} else {
			label = meta
		}
	}
	if label == "" {
		label = browserstackSweep
	}
	return label
}

// pathBrowserstackDevices returns EVERY distinct BrowserStack device represented in a
// client's non-/api/ device-sweep paths. A single clientKey can hold several device
// paths because ClientKey excludes device/os/os_version, so devices with identical
// UA+JA4+PeetPrint+Akamai+SPHBI+TCP-options collapse into one client; returning all of
// them keeps the Visual Analysis right side from silently dropping every device but the
// first. Param-name matching is case-insensitive; values are returned verbatim.
func pathBrowserstackDevices(paths []string) []bsDevice {
	get := func(vals url.Values, key string) string {
		for k, vv := range vals {
			if strings.ToLower(k) == key && len(vv) > 0 {
				return vv[0]
			}
		}
		return ""
	}
	seen := map[string]bool{}
	out := []bsDevice{}
	for _, p := range paths {
		if strings.HasPrefix(p, "/api/") {
			continue
		}
		qi := strings.IndexByte(p, '?')
		if qi < 0 {
			continue
		}
		vals, err := url.ParseQuery(p[qi+1:])
		if err != nil {
			continue
		}
		if !strings.EqualFold(get(vals, facetScrapingHeader), browserstackSweep) {
			continue
		}
		d := bsDevice{get(vals, "device"), get(vals, "os"), get(vals, "os_version")}
		key := d.device + "\x1f" + d.os + "\x1f" + d.osVersion
		if !seen[key] {
			seen[key] = true
			out = append(out, d)
		}
	}
	return out
}

// vaNodeOut is one node of the Visual Analysis graph: a distinct SPHBI image
// (kind:bits) plus the distinct scraper/device labels that produced it.
type vaNodeOut struct {
	Bits      string   `json:"bits"`
	Kind      string   `json:"kind"`
	Size      int      `json:"size"`
	Labels    []string `json:"labels"`
	Count     int      `json:"count"` // number of distinct labels (scrapers / devices)
	UserAgent string   `json:"user_agent,omitempty"`
	ClientKey string   `json:"client_key"`
	Device    string   `json:"device,omitempty"`
	OS        string   `json:"os,omitempty"`
	OSVersion string   `json:"os_version,omitempty"`
}

// SPHBIByJA4 powers the Visual Analysis tab. For one exact JA4 fingerprint it scans
// the entire client population once (newest-first) and returns the distinct SPHBI
// images linked to that JA4, split into scrapers (left) and BrowserStack devices
// (right), de-duplicated by kind:bits per side. One node per distinct image carries
// the set of contributing scraper names (left) or "device · os ver" strings (right),
// so an image shared by several tools/devices collapses to a single multi-label node
// — surfacing which clients are indistinguishable by SPHBI under the same JA4.
func (s *Store) SPHBIByJA4(ctx context.Context, ja4 string, capN int) ([]byte, error) {
	if capN < 1 || capN > 400 {
		capN = 400 // floor + hard ceiling: matches the UI's "capped at 400/side" promise
	}
	keys, err := s.rdb.ZRevRange(ctx, "idx:clients", 0, -1).Result()
	if err != nil {
		return nil, err
	}
	pipe := s.rdb.Pipeline()
	sumCmds := make([]*redis.StringCmd, len(keys))
	pathCmds := make([]*redis.StringSliceCmd, len(keys))
	for i, k := range keys {
		sumCmds[i] = pipe.HGet(ctx, "client:"+k, "summary_json")
		pathCmds[i] = pipe.ZRange(ctx, "client:"+k+":paths", 0, -1)
	}
	_, _ = pipe.Exec(ctx)

	target := strings.ToLower(ja4)

	type acc struct {
		kind, bits      string
		size            int
		ua, ck          string
		labels          map[string]bool
		device, os, osv string // representative device (right side)
		order           int
	}
	left := map[string]*acc{}
	right := map[string]*acc{}
	lorder, rorder := 0, 0
	add := func(m map[string]*acc, orderp *int, kind, bits string, size int, ua, ck, label, device, os, osv string) {
		key := kind + ":" + bits
		a := m[key]
		if a == nil {
			a = &acc{kind: kind, bits: bits, size: size, ua: ua, ck: ck, labels: map[string]bool{}, device: device, os: os, osv: osv, order: *orderp}
			*orderp++
			m[key] = a
		}
		if label != "" {
			a.labels[label] = true
		}
	}

	for i, k := range keys {
		raw, e := sumCmds[i].Result()
		if e != nil || raw == "" {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &m) != nil {
			continue
		}
		var cj string
		_ = json.Unmarshal(m["ja4"], &cj)
		if strings.ToLower(cj) != target {
			continue
		}
		var sp struct {
			Kind string `json:"kind"`
			Bits string `json:"bits"`
			Size int    `json:"size"`
		}
		if m["sphbi"] == nil || json.Unmarshal(m["sphbi"], &sp) != nil || sp.Bits == "" {
			continue // only clients that actually carry an image belong on the graph
		}
		var ua string
		_ = json.Unmarshal(m["user_agent"], &ua)

		for _, v := range pathsFacetValues(pathCmds[i].Val(), facetScrapingHeader) {
			if strings.EqualFold(v, browserstackSweep) {
				// One clientKey can sweep MANY devices (device/os are not in ClientKey),
				// so emit a label for EVERY distinct device on this client, not just the
				// first — otherwise the right side silently drops co-collapsed devices.
				devs := pathBrowserstackDevices(pathCmds[i].Val())
				if len(devs) == 0 {
					add(right, &rorder, sp.Kind, sp.Bits, sp.Size, ua, k, browserstackSweep, "", "", "")
					continue
				}
				for _, dv := range devs {
					add(right, &rorder, sp.Kind, sp.Bits, sp.Size, ua, k, bsDeviceLabel(dv), dv.device, dv.os, dv.osVersion)
				}
			} else {
				add(left, &lorder, sp.Kind, sp.Bits, sp.Size, ua, k, v, "", "", "")
			}
		}
	}

	build := func(m map[string]*acc, limit int) ([]vaNodeOut, int, bool) {
		nodes := make([]*acc, 0, len(m))
		for _, a := range m {
			nodes = append(nodes, a)
		}
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].order < nodes[j].order })
		total := len(nodes)
		truncated := false
		if len(nodes) > limit {
			nodes = nodes[:limit]
			truncated = true
		}
		out := make([]vaNodeOut, 0, len(nodes))
		for _, a := range nodes {
			labels := make([]string, 0, len(a.labels))
			for l := range a.labels {
				labels = append(labels, l)
			}
			sort.Strings(labels)
			out = append(out, vaNodeOut{
				Bits: a.bits, Kind: a.kind, Size: a.size, Labels: labels, Count: len(labels),
				UserAgent: a.ua, ClientKey: a.ck, Device: a.device, OS: a.os, OSVersion: a.osv,
			})
		}
		return out, total, truncated
	}
	leftOut, leftTotal, leftTrunc := build(left, capN)
	rightOut, rightTotal, rightTrunc := build(right, capN)

	return json.Marshal(map[string]interface{}{
		"ja4":             ja4,
		"left":            leftOut,
		"right":           rightOut,
		"left_total":      leftTotal,
		"right_total":     rightTotal,
		"left_truncated":  leftTrunc,
		"right_truncated": rightTrunc,
	})
}

// JA4ImageSummary lists the JA4 fingerprints that actually produce a non-empty Visual
// Analysis graph — i.e. that have at least one client carrying BOTH an SPHBI image and
// a scraping-header label — each with its distinct-image count per side (scrapers /
// BrowserStack devices), richest first. This is the dropdown source for the Visual
// Analysis tab: unlike /api/ja4values (every JA4 ever seen, used by the filter bars),
// it omits JA4s whose clients have no image or no scraping-header, so selecting an
// entry can never render an empty graph. One scan over all clients (newest-first).
func (s *Store) JA4ImageSummary(ctx context.Context) ([]byte, error) {
	keys, err := s.rdb.ZRevRange(ctx, "idx:clients", 0, -1).Result()
	if err != nil {
		return nil, err
	}
	pipe := s.rdb.Pipeline()
	sumCmds := make([]*redis.StringCmd, len(keys))
	pathCmds := make([]*redis.StringSliceCmd, len(keys))
	for i, k := range keys {
		sumCmds[i] = pipe.HGet(ctx, "client:"+k, "summary_json")
		pathCmds[i] = pipe.ZRange(ctx, "client:"+k+":paths", 0, -1)
	}
	_, _ = pipe.Exec(ctx)

	type agg struct {
		left  map[string]bool // distinct kind:bits images from scraper clients
		right map[string]bool // distinct kind:bits images from browserstack clients
	}
	m := map[string]*agg{}
	for i := range keys {
		raw, e := sumCmds[i].Result()
		if e != nil || raw == "" {
			continue
		}
		var sm map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &sm) != nil {
			continue
		}
		var sp struct {
			Kind string `json:"kind"`
			Bits string `json:"bits"`
		}
		if sm["sphbi"] == nil || json.Unmarshal(sm["sphbi"], &sp) != nil || sp.Bits == "" {
			continue
		}
		facetVals := pathsFacetValues(pathCmds[i].Val(), facetScrapingHeader)
		if len(facetVals) == 0 {
			continue // image but no scraping-header label → no node in the graph
		}
		var ja4 string
		if json.Unmarshal(sm["ja4"], &ja4) != nil || ja4 == "" {
			continue
		}
		a := m[ja4]
		if a == nil {
			a = &agg{left: map[string]bool{}, right: map[string]bool{}}
			m[ja4] = a
		}
		imgKey := sp.Kind + ":" + sp.Bits
		for _, v := range facetVals {
			if strings.EqualFold(v, browserstackSweep) {
				a.right[imgKey] = true
			} else {
				a.left[imgKey] = true
			}
		}
	}

	type ja4Summary struct {
		JA4   string `json:"ja4"`
		Left  int    `json:"left"`
		Right int    `json:"right"`
	}
	list := make([]ja4Summary, 0, len(m))
	for ja4, a := range m {
		list = append(list, ja4Summary{JA4: ja4, Left: len(a.left), Right: len(a.right)})
	}
	// Richest first; ja4 ascending as a stable tiebreak.
	sort.Slice(list, func(i, j int) bool {
		ti, tj := list[i].Left+list[i].Right, list[j].Left+list[j].Right
		if ti != tj {
			return ti > tj
		}
		return list[i].JA4 < list[j].JA4
	})
	return json.Marshal(list)
}

// GetClient returns the full detail record for one clientKey as JSON bytes.
func (s *Store) GetClient(ctx context.Context, key string) ([]byte, error) {
	clientK := "client:" + key
	pipe := s.rdb.Pipeline()
	hAll := pipe.HGetAll(ctx, clientK)
	ipsCmd := pipe.SMembers(ctx, clientK+":ips")
	portsCmd := pipe.SMembers(ctx, clientK+":ports")
	pathsCmd := pipe.ZRevRangeWithScores(ctx, clientK+":paths", 0, pathsKeep-1)
	connsCmd := pipe.ZRevRangeByScoreWithScores(ctx, clientK+":conns", &redis.ZRangeBy{
		Min: "-inf", Max: "+inf", Offset: 0, Count: 100,
	})
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}
	h := hAll.Val()
	if len(h) == 0 {
		return nil, errors.New("client not found")
	}
	conns := connsCmd.Val()

	// Fetch per-connection light fields + the latest connection's full JSON.
	pipe2 := s.rdb.Pipeline()
	fetches := make([]*redis.SliceCmd, len(conns))
	for i, z := range conns {
		ck, _ := z.Member.(string)
		fetches[i] = pipe2.HMGet(ctx, "conn:"+ck, "http_version", "client_random", "path", "request_json")
	}
	var latestJSON *redis.StringCmd
	if len(conns) > 0 {
		ck, _ := conns[0].Member.(string)
		latestJSON = pipe2.HGet(ctx, "conn:"+ck, "json")
	}
	_, _ = pipe2.Exec(ctx)

	connections := make([]map[string]interface{}, 0, len(conns))
	for i, z := range conns {
		v := fetches[i].Val()
		if len(v) < 3 {
			continue
		}
		cn := map[string]interface{}{
			"ts":            int64(z.Score),
			"http_version":  asStr(v[0]),
			"client_random": asStr(v[1]),
			"path":          asStr(v[2]),
		}
		// Captured request parameters (trusted-collection connections only).
		if len(v) >= 4 {
			if rj := asStr(v[3]); rj != "" {
				cn["request"] = json.RawMessage(rj)
			}
		}
		connections = append(connections, cn)
	}

	var tcpip interface{}
	var quic interface{}
	var tlsFull interface{}   // full latest TLS block (extensions/ciphers) for Stack Analysis
	var qosfVal interface{}   // latest QOSF (kernel signal) for Stack Analysis on stored QUIC clients
	if latestJSON != nil {
		if js, err := latestJSON.Result(); err == nil && js != "" {
			var lr types.Response
			if json.Unmarshal([]byte(js), &lr) == nil {
				tcpip = lr.TCPIP
				if lr.TLS != nil {
					tlsFull = lr.TLS
					quic = lr.TLS.QUICTransportParameters
				}
				if lr.QOSF != nil {
					qosfVal = lr.QOSF
				}
			}
		}
	}

	var sphbi interface{}
	if sj := h["sphbi_json"]; sj != "" {
		sphbi = json.RawMessage(sj)
	}

	geoPoints := make([]geo.Point, 0)
	seenGeo := make(map[string]bool)
	for _, ip := range ipsCmd.Val() {
		if seenGeo[ip] {
			continue
		}
		seenGeo[ip] = true
		if p, ok := geo.Lookup(ip); ok {
			geoPoints = append(geoPoints, p)
		}
	}

	recentPaths := make([]map[string]interface{}, 0, len(pathsCmd.Val()))
	for _, z := range pathsCmd.Val() {
		if p, ok := z.Member.(string); ok {
			recentPaths = append(recentPaths, map[string]interface{}{"path": p, "ts": int64(z.Score)})
		}
	}

	detail := map[string]interface{}{
		"client_key":              key,
		"first_seen":              atoiSafe(h["first_seen"]),
		"last_seen":               atoiSafe(h["last_seen"]),
		"visit_count":             atoiSafe(h["visit_count"]),
		"ip_count":                atoiSafe(h["ip_count"]),
		"ja3":                     h["ja3"],
		"ja3_hash":                h["ja3_hash"],
		"ja4":                     h["ja4"],
		"ja4_r":                   h["ja4_r"],
		"ja4t":                    h["ja4t"],
		"peetprint":               h["peetprint"],
		"peetprint_hash":          h["peetprint_hash"],
		"akamai_fingerprint":      h["akamai"],
		"akamai_fingerprint_hash": h["akamai_hash"],
		"http_version":            h["http_version"],
		"user_agent":              h["user_agent"],
		"ips":                     ipsCmd.Val(),
		"geo":                     geoPoints,
		"ports":                   portsCmd.Val(),
		"connections":             connections,
		"recent_paths":            recentPaths,
		"sphbi":                   sphbi,
		"tcpip":                   tcpip,
		"qosf":                    qosfVal,
	}
	// Prefer the full latest TLS block (extensions/ciphers, for Stack Analysis); fall
	// back to the quic-transport-params-only shape when no latest TLS was captured.
	if tlsFull != nil {
		detail["tls"] = tlsFull
	} else {
		detail["tls"] = map[string]interface{}{"quic_transport_parameters": quic}
	}
	return json.Marshal(detail)
}

func asStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func atoiSafe(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// ListCollected returns the most recent trusted-collection requests, newest
// first, as a paginated JSON object. Each item is the full connection Response
// JSON — which embeds both the captured request (method/target/query/headers/
// body) and the fingerprint it was observed with — ready for a training pull.
// Index entries whose connection record has since expired are skipped.
func (s *Store) ListCollected(ctx context.Context, page, perPage int) ([]byte, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}
	total, _ := s.rdb.ZCard(ctx, "idx:collected").Result()
	start := int64((page - 1) * perPage)
	stop := start + int64(perPage) - 1
	keys, err := s.rdb.ZRevRange(ctx, "idx:collected", start, stop).Result()
	if err != nil {
		return nil, err
	}
	pipe := s.rdb.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))
	for i, k := range keys {
		cmds[i] = pipe.HGet(ctx, "conn:"+k, "json")
	}
	_, _ = pipe.Exec(ctx)
	items := make([]json.RawMessage, 0, len(keys))
	for i := range keys {
		js, err := cmds[i].Result()
		if err != nil || js == "" {
			continue
		}
		items = append(items, json.RawMessage(js))
	}
	out := map[string]interface{}{
		"total": total, "page": page, "per_page": perPage, "collected": items,
	}
	return json.Marshal(out)
}

// GetExp returns the captured fingerprint row for one experiment token.
func (s *Store) GetExp(ctx context.Context, token string) ([]byte, error) {
	h, err := s.rdb.HGetAll(ctx, "exp:"+token).Result()
	if err != nil {
		return nil, err
	}
	if len(h) == 0 {
		return nil, errors.New("token not found")
	}
	h["token"] = token
	return json.Marshal(h)
}

// ListExp returns every experiment row (token -> fingerprint) as a JSON array,
// for joining against the orchestrator's manifest.
func (s *Store) ListExp(ctx context.Context) ([]byte, error) {
	tokens, err := s.rdb.SMembers(ctx, "idx:experiments").Result()
	if err != nil {
		return nil, err
	}
	pipe := s.rdb.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(tokens))
	for i, t := range tokens {
		cmds[i] = pipe.HGetAll(ctx, "exp:"+t)
	}
	_, _ = pipe.Exec(ctx)
	rows := make([]map[string]string, 0, len(tokens))
	for i, t := range tokens {
		h := cmds[i].Val()
		if len(h) == 0 {
			continue
		}
		h["token"] = t
		rows = append(rows, h)
	}
	return json.Marshal(rows)
}

// DeleteClient removes one client and every record unique to it: the rollup hash,
// its ip/port/conn sets, each of its connection records (and their idx:collected
// entries), and its memberships in idx:clients / idx:ip:* / idx:ja4:*. Returns
// the number of connection records removed. Idempotent (deleting a missing client
// is a no-op returning 0).
func (s *Store) DeleteClient(ctx context.Context, clientKey string) (int, error) {
	clientK := "client:" + clientKey
	conns, _ := s.rdb.ZRange(ctx, clientK+":conns", 0, -1).Result()
	ips, _ := s.rdb.SMembers(ctx, clientK+":ips").Result()
	ja4, _ := s.rdb.HGet(ctx, clientK, "ja4").Result()

	pipe := s.rdb.Pipeline()
	for _, ck := range conns {
		pipe.Del(ctx, "conn:"+ck)
		pipe.ZRem(ctx, "idx:collected", ck)
	}
	for _, ip := range ips {
		pipe.ZRem(ctx, "idx:ip:"+ip, clientKey)
	}
	if ja4 != "" {
		pipe.ZRem(ctx, "idx:ja4:"+ja4, clientKey)
	}
	pipe.Del(ctx, clientK, clientK+":ips", clientK+":ports", clientK+":conns", clientK+":paths")
	pipe.ZRem(ctx, "idx:clients", clientKey)
	for _, kd := range []string{"ipv4", "ipv6", "quic"} {
		pipe.HDel(ctx, "idx:sphbi:"+kd, clientKey)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return len(conns), nil
}

// DeleteAll wipes the entire TrackMe history keyspace — every client, connection,
// index, experiment capture, and the visit stream — via batched SCAN+DEL (no
// FLUSHDB, so anything outside these prefixes is untouched). Returns the number of
// keys removed. New traffic after the call repopulates from scratch.
func (s *Store) DeleteAll(ctx context.Context) (int, error) {
	total := 0
	for _, pat := range []string{"client:*", "conn:*", "idx:*", "exp:*"} {
		var cursor uint64
		for {
			keys, cur, err := s.rdb.Scan(ctx, cursor, pat, 1000).Result()
			if err != nil {
				return total, err
			}
			if len(keys) > 0 {
				if err := s.rdb.Del(ctx, keys...).Err(); err != nil {
					return total, err
				}
				total += len(keys)
			}
			cursor = cur
			if cursor == 0 {
				break
			}
		}
	}
	if n, _ := s.rdb.Del(ctx, visitsStream).Result(); n > 0 {
		total += int(n)
	}
	return total, nil
}

// ASNInfo is the autonomous-system (network operator) info for an IP.
type ASNInfo struct {
	IP          string `json:"ip"`
	ASN         string `json:"asn,omitempty"`     // e.g. "AS15169"
	ASName      string `json:"as_name,omitempty"` // e.g. "GOOGLE"
	ISP         string `json:"isp,omitempty"`
	Org         string `json:"org,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Available   bool   `json:"available"`
	Source      string `json:"source,omitempty"` // which provider answered
}

// ASN provider endpoints. Vars (not consts) so tests can stub them. All three are
// free and key-less, with different rate-limit profiles for redundancy: ip-api.com
// is primary (richest data, HTTP-only, ~45 req/min/IP); ipwho.is and ipapi.co are
// HTTPS fallbacks (~10k/mo and ~1k/day respectively).
var (
	asnAPIURL       = "http://ip-api.com/json/"
	asnFallbackURL  = "https://ipwho.is/"
	asnFallback2URL = "https://ipapi.co/"
)

var asnHTTP = &http.Client{Timeout: 4 * time.Second}

const (
	asnCacheTTL       = 30 * 24 * time.Hour
	asnCooldownMax    = 5 * time.Minute // cap on a provider's rate-limit cooldown
	asnDefaultCoolTTL = 60 * time.Second
)

// asnProvider is one ASN data source: build() forms the request URL, parse() turns
// its response into ASNInfo.
type asnProvider struct {
	name  string
	build func(ip string) string
	parse func(ip string, body []byte) ASNInfo
}

// asnProviders is the ordered fallback chain. Built per-call so a stubbed URL var
// is picked up at request time.
func asnProviders() []asnProvider {
	return []asnProvider{
		{
			name: "ip-api.com",
			build: func(ip string) string {
				return asnAPIURL + url.PathEscape(ip) + "?fields=status,message,country,countryCode,isp,org,as,asname,query"
			},
			parse: parseIPAPI,
		},
		{
			name:  "ipwho.is",
			build: func(ip string) string { return asnFallbackURL + url.PathEscape(ip) },
			parse: parseIPWhois,
		},
		{
			name:  "ipapi.co",
			build: func(ip string) string { return asnFallback2URL + url.PathEscape(ip) + "/json/" },
			parse: parseIPAPICo,
		},
	}
}

// parseIPAPI converts an ip-api.com JSON response into ASNInfo.
func parseIPAPI(ip string, body []byte) ASNInfo {
	var r struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		ASName      string `json:"asname"`
	}
	info := ASNInfo{IP: ip}
	if json.Unmarshal(body, &r) != nil || r.Status != "success" {
		return info
	}
	info.ISP, info.Org = r.ISP, r.Org
	info.Country, info.CountryCode = r.Country, r.CountryCode
	info.ASName = r.ASName
	if r.AS != "" {
		// "AS15169 Google LLC" -> ASN "AS15169"; remainder backfills ASName.
		parts := strings.SplitN(r.AS, " ", 2)
		info.ASN = parts[0]
		if info.ASName == "" && len(parts) == 2 {
			info.ASName = parts[1]
		}
	}
	info.Available = info.ASN != "" || info.ISP != ""
	return info
}

// parseIPWhois converts an ipwho.is JSON response into ASNInfo.
func parseIPWhois(ip string, body []byte) ASNInfo {
	var r struct {
		Success     bool   `json:"success"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	info := ASNInfo{IP: ip}
	if json.Unmarshal(body, &r) != nil || !r.Success {
		return info
	}
	if r.Connection.ASN > 0 {
		info.ASN = "AS" + strconv.Itoa(r.Connection.ASN)
	}
	info.ASName = r.Connection.Org // ipwho.is has no short handle; use the org
	info.ISP, info.Org = r.Connection.ISP, r.Connection.Org
	info.Country, info.CountryCode = r.Country, r.CountryCode
	info.Available = info.ASN != "" || info.ISP != ""
	return info
}

// parseIPAPICo converts an ipapi.co JSON response into ASNInfo. Its `asn` field is
// already in "AS15169" form; `org` is the AS organization. A rate-limited/over-quota
// response carries `error: true` (and usually HTTP 429, handled by the caller).
func parseIPAPICo(ip string, body []byte) ASNInfo {
	var r struct {
		Error       bool   `json:"error"`
		ASN         string `json:"asn"`
		Org         string `json:"org"`
		Country     string `json:"country_name"`
		CountryCode string `json:"country_code"`
	}
	info := ASNInfo{IP: ip}
	if json.Unmarshal(body, &r) != nil || r.Error {
		return info
	}
	info.ASN = r.ASN
	info.ASName, info.Org = r.Org, r.Org
	info.Country, info.CountryCode = r.Country, r.CountryCode
	info.Available = info.ASN != "" || info.Org != ""
	return info
}

// fetchASN walks the provider chain, switching to the next provider the instant one
// is rate-limited (HTTP 429) or errors — so the caller's request is still fulfilled
// from a fallback. A rate-limited provider is parked in a short Redis cooldown
// (TTL from its Retry-After/X-Ttl header) so subsequent lookups skip it until it
// recovers.
func (s *Store) fetchASN(ctx context.Context, ip string) ASNInfo {
	for _, p := range asnProviders() {
		if s.asnCoolingDown(ctx, p.name) {
			continue
		}
		info, status, cool := s.tryASNProvider(ctx, p, ip)
		if cool > 0 {
			_ = s.rdb.Set(ctx, "asn:cooldown:"+p.name, status, cool).Err()
		}
		if info.Available {
			return info
		}
	}
	return ASNInfo{IP: ip}
}

// tryASNProvider performs one provider request. The returned cooldown is non-zero
// only when the provider rate-limited us (HTTP 429), telling the caller to park it.
func (s *Store) tryASNProvider(ctx context.Context, p asnProvider, ip string) (ASNInfo, int, time.Duration) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.build(ip), nil)
	if err != nil {
		return ASNInfo{IP: ip}, 0, 0
	}
	resp, err := asnHTTP.Do(req)
	if err != nil {
		return ASNInfo{IP: ip}, 0, 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusTooManyRequests {
		return ASNInfo{IP: ip}, resp.StatusCode, asnRetryAfter(resp)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ASNInfo{IP: ip}, resp.StatusCode, 0
	}
	info := p.parse(ip, body)
	info.Source = p.name
	return info, resp.StatusCode, 0
}

// asnRetryAfter reads how long to back off from a 429 response (ip-api uses X-Ttl,
// others use Retry-After), bounded by asnCooldownMax.
func asnRetryAfter(resp *http.Response) time.Duration {
	ttl := asnDefaultCoolTTL
	for _, h := range []string{"X-Ttl", "Retry-After"} {
		if v := resp.Header.Get(h); v != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
				ttl = time.Duration(n) * time.Second
				break
			}
		}
	}
	if ttl > asnCooldownMax {
		ttl = asnCooldownMax
	}
	return ttl
}

// asnCoolingDown reports whether a provider is currently parked after a 429.
func (s *Store) asnCoolingDown(ctx context.Context, name string) bool {
	n, _ := s.rdb.Exists(ctx, "asn:cooldown:"+name).Result()
	return n == 1
}

// HasIP reports whether ip has been observed (exists in idx:ip:<ip>). Guards the
// ASN endpoint so it can't be used as an open lookup proxy for arbitrary IPs.
func (s *Store) HasIP(ctx context.Context, ip string) bool {
	n, _ := s.rdb.Exists(ctx, "idx:ip:"+ip).Result()
	return n == 1
}

// LookupASN returns ASN info for ip as JSON, caching successful results in Redis
// (asn:<ip>, 30-day TTL) so the free API is queried at most once per IP.
func (s *Store) LookupASN(ctx context.Context, ip string) ([]byte, error) {
	cacheK := "asn:" + ip
	if cached, err := s.rdb.Get(ctx, cacheK).Bytes(); err == nil && len(cached) > 0 {
		return cached, nil
	}
	info := s.fetchASN(ctx, ip)
	b, _ := json.Marshal(info)
	if info.Available {
		_ = s.rdb.Set(ctx, cacheK, b, asnCacheTTL).Err()
		// Distinct-ASN set for the filter dropdown: one ZSET of every ASN seen
		// (score = recency, member = "<asn> · <operator>"), so the option list
		// grows automatically and each ASN appears once. Mirrors idx:ja4set.
		if info.ASN != "" {
			label := info.ASN
			if info.ASName != "" {
				label += " · " + info.ASName
			}
			_ = s.rdb.ZAdd(ctx, "idx:asnset", redis.Z{Score: float64(time.Now().Unix()), Member: label}).Err()
			_ = s.rdb.ZRemRangeByRank(ctx, "idx:asnset", 0, -(asnSetCap+1)).Err()
		}
	}
	return b, nil
}

// asnBackfillTargets scans every observed client IP (idx:ip:*) and splits them into
// all-seen and not-yet-cached.
func (s *Store) asnBackfillTargets(ctx context.Context) (all, todo []string, err error) {
	var cursor uint64
	for {
		keys, cur, e := s.rdb.Scan(ctx, cursor, "idx:ip:*", 500).Result()
		if e != nil {
			return nil, nil, e
		}
		for _, k := range keys {
			ip := strings.TrimPrefix(k, "idx:ip:")
			all = append(all, ip)
			if n, _ := s.rdb.Exists(ctx, "asn:"+ip).Result(); n == 0 {
				todo = append(todo, ip)
			}
		}
		cursor = cur
		if cursor == 0 {
			break
		}
	}
	return all, todo, nil
}

// BackfillASN warms the ASN cache for every observed client IP that isn't cached
// yet, resolving them in the background paced to respect provider rate limits.
// Returns (scheduled, total). A Redis lock (30-min TTL) prevents overlapping runs.
func (s *Store) BackfillASN(ctx context.Context, pace time.Duration) (scheduled, total int, err error) {
	ok, _ := s.rdb.SetNX(ctx, "asn:backfill:lock", "1", 30*time.Minute).Result()
	if !ok {
		return 0, 0, errors.New("a backfill is already running")
	}
	all, todo, e := s.asnBackfillTargets(ctx)
	if e != nil {
		s.rdb.Del(ctx, "asn:backfill:lock")
		return 0, 0, e
	}
	go func() {
		bg := context.Background()
		defer s.rdb.Del(bg, "asn:backfill:lock")
		for _, ip := range todo {
			_, _ = s.LookupASN(bg, ip) // caches as a side effect
			if pace > 0 {
				time.Sleep(pace)
			}
		}
		log.Printf("asn backfill: warmed %d of %d IPs", len(todo), len(all))
	}()
	return len(todo), len(all), nil
}

// --- SPHBI image similarity (exact brute-force Hamming k-NN, no ML) ---
//
// Each SPHBI is 144 bits = 18 bytes (the `hex` field). We pack it into 3x uint64
// (zero-padded) so Hamming distance is three XORs + popcounts — microseconds even
// for 100k candidates. Comparisons are within-kind only (ipv4/ipv6/quic images use
// different byte semantics and are not comparable).

func packSPHBI(hexStr string) ([3]uint64, bool) {
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) == 0 {
		return [3]uint64{}, false
	}
	var buf [24]byte // 3x uint64, zero-padded (image is 18 bytes)
	copy(buf[:], b)
	return [3]uint64{
		binary.BigEndian.Uint64(buf[0:8]),
		binary.BigEndian.Uint64(buf[8:16]),
		binary.BigEndian.Uint64(buf[16:24]),
	}, true
}

func hammingSPHBI(a, b [3]uint64) int {
	return bits.OnesCount64(a[0]^b[0]) + bits.OnesCount64(a[1]^b[1]) + bits.OnesCount64(a[2]^b[2])
}

// SimilarClients returns the n clients whose SPHBI image is closest (smallest
// Hamming distance) to clientKey's image, within the same kind — an exact
// brute-force XOR+popcount scan of idx:sphbi:<kind>. Returns JSON
// {kind, query_key, neighbors:[{client_key, distance, similarity, sphbi, user_agent, last_seen}]}.
func (s *Store) SimilarClients(ctx context.Context, clientKey string, n int) ([]byte, error) {
	if n < 1 || n > 100 {
		n = 12
	}
	empty := []byte(`{"kind":"","query_key":"","neighbors":[]}`)
	sj, err := s.rdb.HGet(ctx, "client:"+clientKey, "sphbi_json").Result()
	if err != nil || sj == "" {
		return empty, nil
	}
	var q struct {
		Kind string `json:"kind"`
		Hex  string `json:"hex"`
	}
	if json.Unmarshal([]byte(sj), &q) != nil || q.Kind == "" || q.Hex == "" {
		return empty, nil
	}
	qVec, ok := packSPHBI(q.Hex)
	if !ok {
		return empty, nil
	}
	pool, err := s.rdb.HGetAll(ctx, "idx:sphbi:"+q.Kind).Result()
	if err != nil {
		return nil, err
	}
	type cand struct {
		key  string
		dist int
	}
	cands := make([]cand, 0, len(pool))
	for k, hx := range pool {
		if k == clientKey {
			continue
		}
		if v, ok := packSPHBI(hx); ok {
			cands = append(cands, cand{key: k, dist: hammingSPHBI(qVec, v)})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].dist != cands[j].dist {
			return cands[i].dist < cands[j].dist
		}
		return cands[i].key < cands[j].key // deterministic tie-break
	})
	if len(cands) > n {
		cands = cands[:n]
	}

	pipe := s.rdb.Pipeline()
	sumCmds := make([]*redis.StringCmd, len(cands))
	for i, c := range cands {
		sumCmds[i] = pipe.HGet(ctx, "client:"+c.key, "summary_json")
	}
	_, _ = pipe.Exec(ctx)

	neighbors := make([]map[string]interface{}, 0, len(cands))
	for i, c := range cands {
		m := map[string]interface{}{
			"client_key": c.key,
			"distance":   c.dist,
			"similarity": (144 - c.dist) * 100 / 144,
		}
		if raw, e := sumCmds[i].Result(); e == nil && raw != "" {
			var sm map[string]json.RawMessage
			if json.Unmarshal([]byte(raw), &sm) == nil {
				for _, f := range []string{"sphbi", "user_agent", "last_seen"} {
					if v, ok := sm[f]; ok {
						m[f] = v
					}
				}
			}
		}
		neighbors = append(neighbors, m)
	}
	return json.Marshal(map[string]interface{}{
		"kind": q.Kind, "query_key": clientKey, "neighbors": neighbors,
	})
}
