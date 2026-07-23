package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pagpeter/trackme/pkg/store"
	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
)

// RouteHandler is the function signature for route handlers
type RouteHandler func(types.Response, url.Values) ([]byte, string, error)

var (
	ErrTLSNotAvailable = errors.New("TLS details not available")
)

func staticFile(file string) RouteHandler {
	return func(types.Response, url.Values) ([]byte, string, error) {
		b, err := utils.ReadFile(file)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read file %s: %w", file, err)
		}
		return b, "text/html", nil
	}
}

func apiAll(res types.Response, _ url.Values) ([]byte, string, error) {
	return []byte(res.ToJson()), "application/json", nil
}

func apiTLS(res types.Response, _ url.Values) ([]byte, string, error) {
	return []byte(types.Response{
		TLS: res.TLS,
	}.ToJson()), "application/json", nil
}

func apiClean(res types.Response, _ url.Values) ([]byte, string, error) {
	akamai := "-"
	hash := "-"
	if res.HTTPVersion == "h2" && res.Http2 != nil {
		akamai = res.Http2.AkamaiFingerprint
		hash = utils.GetMD5Hash(res.Http2.AkamaiFingerprint)
	} else if res.HTTPVersion == "h3" && res.Http3 != nil {
		akamai = res.Http3.AkamaiFingerprint
		hash = res.Http3.AkamaiFingerprintHash
	}

	smallRes := types.SmallResponse{
		Akamai:      akamai,
		AkamaiHash:  hash,
		HTTPVersion: res.HTTPVersion,
	}

	if res.TLS != nil {
		smallRes.JA3 = res.TLS.JA3
		smallRes.JA3Hash = res.TLS.JA3Hash
		smallRes.JA4 = res.TLS.JA4
		smallRes.JA4_r = res.TLS.JA4_r
		smallRes.PeetPrint = res.TLS.PeetPrint
		smallRes.PeetPrintHash = res.TLS.PeetPrintHash
	}

	return []byte(smallRes.ToJson()), "application/json", nil
}

func apiRaw(res types.Response, _ url.Values) ([]byte, string, error) {
	if res.TLS == nil {
		return nil, "", ErrTLSNotAvailable
	}
	return []byte(fmt.Sprintf(`{"raw": "%s", "raw_b64": "%s"}`, res.TLS.RawBytes, res.TLS.RawB64)), "application/json", nil
}

func index(r types.Response, v url.Values) ([]byte, string, error) {
	res, ct, err := staticFile("static/index.html")(r, v)
	if err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal response: %w", err)
	}
	return []byte(strings.ReplaceAll(string(res), "/*DATA*/", string(data))), ct, nil
}

func (srv *Server) getAllPaths() map[string]RouteHandler {
	paths := map[string]RouteHandler{
		"/":          index,
		"/explore":   staticFile("static/explore.html"),
		"/api/all":   apiAll,
		"/api/tls":   apiTLS,
		"/api/clean": apiClean,
		"/api/raw":   apiRaw,
	}
	// Historical client-history endpoints, only when the store is up.
	if st := srv.GetStore(); st != nil {
		cfg := srv.GetConfig()
		allowed := func(res types.Response) bool { return cfg.IsHistoryPublic() || res.IsAdmin }

		paths["/api/clients"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			page := atoiDefault(q.Get("page"), 1)
			per := atoiDefault(q.Get("per_page"), 25)
			b, err := st.ListClients(context.Background(), page, per,
				q.Get("kind"), q.Get("ip"), q.Get("ja4"), q.Get("ua"), q.Get("sort"), q.Get("dir") != "asc",
				q.Get("collected") == "1", q.Get("qparam"), q.Get("qvalue"), q["shvalues"], q.Get("asn"))
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Distinct values of a faceted query param (default scraping-header), for the
		// multi-select filter's options. Read-only, same gate as the other history.
		paths["/api/qvalues"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			param := q.Get("param")
			if param == "" {
				param = "scraping-header"
			}
			b, err := st.QueryValues(context.Background(), param)
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Distinct JA4 fingerprints collected so far, for the JA4 filter dropdown.
		// Grows automatically as new fingerprints arrive. Read-only, same gate.
		paths["/api/ja4values"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			b, err := st.JA4Values(context.Background())
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Distinct ASNs seen ("<asn> · <operator>"), for the ASN filter dropdown.
		// Grows automatically as ASNs are resolved/cached. Read-only, same gate.
		paths["/api/asnvalues"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			b, err := st.ASNValues(context.Background())
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Comparative tab "unique images per scraping-header group": one server-side
		// pass returns every group's de-duplicated SPHBI images, so the UI makes a
		// single request instead of one /api/clients scan per scraping-header value.
		// Honors the same filter bar (kind/ip/ja4/ua/qparam/qvalue/collected).
		paths["/api/sphbi/grouped"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			b, err := st.GroupedUniqueByScrapingHeader(context.Background(),
				q.Get("kind"), q.Get("ja4"), q.Get("ua"),
				q.Get("qparam"), q.Get("qvalue"), q["shvalues"],
				atoiDefault(q.Get("cap"), 50))
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Visual Analysis tab: for one EXACT JA4 fingerprint, the distinct SPHBI
		// images linked to it, split into scrapers (left) and BrowserStack devices
		// (right). Same read gate as the other history endpoints.
		paths["/api/sphbi/by-ja4"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			ja4 := q.Get("ja4")
			if ja4 == "" {
				return []byte(`{"error":"missing required parameter: ja4"}`), "application/json", nil
			}
			b, err := st.SPHBIByJA4(context.Background(), ja4, atoiDefault(q.Get("cap"), 400))
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Dropdown source for the Visual Analysis tab: only the JA4s that have ≥1
		// labeled SPHBI image (so a selection never renders an empty graph), with
		// per-side image counts. Distinct from /api/ja4values (all JA4s, filter bars).
		paths["/api/sphbi/ja4values"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			b, err := st.JA4ImageSummary(context.Background())
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Nearest SPHBI images (exact Hamming k-NN, within-kind) for one client.
		paths["/api/client/similar"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			key := q.Get("key")
			if key == "" {
				return []byte(`{"error":"missing required parameter: key"}`), "application/json", nil
			}
			b, err := st.SimilarClients(context.Background(), key, atoiDefault(q.Get("n"), 12))
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		paths["/api/client"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			key := q.Get("key")
			if key == "" {
				return []byte(`{"error":"missing required parameter: key"}`), "application/json", nil
			}
			b, err := st.GetClient(context.Background(), key)
			if err != nil {
				return []byte(`{"error":"client not found"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Controlled-experiment export: one token's captured fingerprint, and the
		// full dump for joining with the orchestrator manifest.
		paths["/api/exp"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			token := q.Get("token")
			if token == "" {
				return []byte(`{"error":"missing required parameter: token"}`), "application/json", nil
			}
			b, err := st.GetExp(context.Background(), token)
			if err != nil {
				return []byte(`{"error":"token not found"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		paths["/api/exp/all"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			b, err := st.ListExp(context.Background())
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Trusted request-parameter capture export: the captured requests (params +
		// body) joined to the fingerprint they were seen with, for model-training
		// pulls. Same read gate as the other history endpoints.
		paths["/api/collected"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if !allowed(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			page := atoiDefault(q.Get("page"), 1)
			per := atoiDefault(q.Get("per_page"), 50)
			b, err := st.ListCollected(context.Background(), page, per)
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// ASN (network operator) lookup via a free API, cached in Redis. No ?ip=
		// resolves the caller's own IP (current-client view); an explicit ?ip= is
		// only honored for IPs we've actually observed, so this can't be abused as an
		// open lookup proxy for arbitrary addresses.
		paths["/api/asn"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			caller := store.HostOf(res.IP)
			target := q.Get("ip")
			if target == "" {
				target = caller
			} else if target != caller && !st.HasIP(context.Background(), target) {
				return []byte(`{"error":"unknown ip"}`), "application/json", nil
			}
			if target == "" {
				return []byte(`{"error":"missing ip"}`), "application/json", nil
			}
			b, err := st.LookupASN(context.Background(), target)
			if err != nil {
				return []byte(`{"error":"asn lookup failed"}`), "application/json", nil
			}
			return b, "application/json", nil
		}

		// Backfill: warm the ASN cache for every observed client IP, in the
		// background. Admin op (consumes the free-API quota), so password-gated like
		// the deletes; POST only.
		paths["/api/asn/backfill"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if res.Method != "POST" {
				return []byte(`{"error":"use POST"}`), "application/json", nil
			}
			if !srv.DeleteEnabled() {
				return []byte(`{"error":"disabled (no admin password configured)"}`), "application/json", nil
			}
			if !srv.deleteAuthorized(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			scheduled, total, err := st.BackfillASN(context.Background(), 1400*time.Millisecond)
			if err != nil {
				return []byte(fmt.Sprintf(`{"error":%q}`, err.Error())), "application/json", nil
			}
			return []byte(fmt.Sprintf(`{"total_ips":%d,"scheduled":%d,"already_cached":%d}`, total, scheduled, total-scheduled)), "application/json", nil
		}

		// Destructive deletes — password-gated (X-Delete-Password), POST only. These
		// use their own DeletePassword gate, NOT the read `allowed` gate, so they stay
		// locked even when the history view is public.
		paths["/api/client/delete"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if res.Method != "POST" {
				return []byte(`{"error":"use POST"}`), "application/json", nil
			}
			if !srv.DeleteEnabled() {
				return []byte(`{"error":"delete is disabled (no DELETE_PASSWORD configured)"}`), "application/json", nil
			}
			if !srv.deleteAuthorized(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			key := q.Get("key")
			if key == "" {
				return []byte(`{"error":"missing required parameter: key"}`), "application/json", nil
			}
			n, err := st.DeleteClient(context.Background(), key)
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return []byte(fmt.Sprintf(`{"deleted_client":%q,"connections_removed":%d}`, key, n)), "application/json", nil
		}

		paths["/api/clients/delete_all"] = func(res types.Response, q url.Values) ([]byte, string, error) {
			if res.Method != "POST" {
				return []byte(`{"error":"use POST"}`), "application/json", nil
			}
			if !srv.DeleteEnabled() {
				return []byte(`{"error":"delete is disabled (no DELETE_PASSWORD configured)"}`), "application/json", nil
			}
			if !srv.deleteAuthorized(res) {
				return []byte(`{"error":"forbidden"}`), "application/json", nil
			}
			n, err := st.DeleteAll(context.Background())
			if err != nil {
				return []byte(`{"error":"redis unavailable"}`), "application/json", nil
			}
			return []byte(fmt.Sprintf(`{"deleted_keys":%d}`, n)), "application/json", nil
		}
	}
	return paths
}

// atoiDefault parses s as an int, returning def on empty/invalid input.
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
