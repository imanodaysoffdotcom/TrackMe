package server

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pagpeter/trackme/pkg/tls"
	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
)

func Log(msg string) {
	t := time.Now()
	formatted := t.Format("2006-01-02 15:04:05")
	fmt.Printf("[%v] %v\n", formatted, msg)
}

func cleanIP(ip string) string {
	return strings.Replace(strings.Replace(ip, "]", "", -1), "[", "", -1)
}

// Router returns bytes, content type, and error that should be sent to the client
func Router(path string, res types.Response, srv *Server) ([]byte, string, error) {
	if v, ok := srv.GetTCPFingerprints().Load(res.IP); ok {
		res.TCPIP = v.(types.TCPIPDetails)
	}
	if v, ok := srv.GetSPHBI().Load(res.IP); ok {
		res.SPHBI = v.(*types.SPHBIDetails)
	} else if host, _, err := net.SplitHostPort(res.IP); err == nil {
		// Fall back to the latest SYN from this user's IP (e.g. for HTTP/3 connections).
		if v, ok := srv.GetSPHBI().Load(host); ok {
			res.SPHBI = v.(*types.SPHBIDetails)
		}
	}
	// JA4T (TCP client fingerprint) is correlated from the SYN the same way as the
	// SPHBI: exact IP:port, then a fallback to the latest SYN from this user's IP.
	if v, ok := srv.GetJA4T().Load(res.IP); ok {
		res.TCPIP.JA4T = v.(string)
	} else if host, _, err := net.SplitHostPort(res.IP); err == nil {
		if v, ok := srv.GetJA4T().Load(host); ok {
			res.TCPIP.JA4T = v.(string)
		}
	}
	res.Donate = "Please consider donating to keep this API running. Visit https://tls.peet.ws"
	if res.TLS != nil {
		// Use QUIC JA4 for HTTP/3 connections
		if res.HTTPVersion == "h3" {
			res.TLS.JA4 = tls.CalculateJa4QUIC(res.TLS)
			res.TLS.JA4_r = tls.CalculateJa4QUIC_r(res.TLS)
			// QUIC has no TCP SYN: build the SPHBI from the transport parameters instead.
			if img := tls.BuildQUICSPHBI(res.TLS.QUICTransportParameters); img != nil {
				res.SPHBI = img
			}
			// QOSF (QUIC OS Fingerprint): computed ONLY here (QUIC-only), alongside —
			// never replacing — the QUIC JA4/SPHBI. The OS-bearing kernel + QUIC
			// long-header fields come from the packet tap (keyed by IP:port, then a
			// fallback to the latest observation from this IP, exactly like the SPHBI);
			// nil when the tap did not observe the flow (socket-only degradation).
			var kern *types.QOSFKernel
			if v, ok := srv.GetQOSFKernel().Load(res.IP); ok {
				kern = v.(*types.QOSFKernel)
			} else if host, _, err := net.SplitHostPort(res.IP); err == nil {
				if v, ok := srv.GetQOSFKernel().Load(host); ok {
					kern = v.(*types.QOSFKernel)
				}
			}
			var quicVersion uint32
			if res.Http3 != nil {
				quicVersion = res.Http3.Version
			}
			if q := tls.CalculateQOSF(res.TLS.QUICTransportParameters, quicVersion, res.IP, kern); q != nil {
				// Cross-layer check: the kernel TTL (segment A) reveals the real OS,
				// which a userspace QUIC mimic (uQUIC) can't forge — flag it against
				// the OS the User-Agent claims.
				q.Consistency = tls.InferConsistency(kern, res.UserAgent)
				res.QOSF = q
			}
		} else {
			res.TLS.JA4 = tls.CalculateJa4(res.TLS)
			res.TLS.JA4_r = tls.CalculateJa4_r(res.TLS)
		}
		Log(fmt.Sprintf("%v %v %v %v %v", cleanIP(res.IP), res.Method, res.HTTPVersion, res.Path, res.TLS.JA3Hash))
	} else {
		Log(fmt.Sprintf("%v %v %v %v %v", cleanIP(res.IP), res.Method, res.HTTPVersion, res.Path, "-"))
	}

	// Parse the path + query up front so the experiment tag is available before
	// the visit is enqueued.
	u, err := url.Parse("https://tls.peet.ws" + path)
	var m url.Values
	if err != nil || u == nil {
		m = make(url.Values)
	} else {
		m, err = url.ParseQuery(u.RawQuery)
		if err != nil {
			m = make(url.Values)
		}
	}

	// Controlled-experiment tag: capture ?exp= (HMAC-valid when a secret is set)
	// BEFORE enqueueing, so the store binds it to this connection's fingerprint.
	// Unsigned/garbage values from internet scanners are dropped.
	if exp := m.Get("exp"); exp != "" {
		if secret := srv.GetConfig().ExpSecret; secret == "" || tls.ValidExp(exp, secret) != "" {
			res.Exp = exp
		}
	}

	// Owner detection for gating the historical endpoints (no-op while public).
	res.IsAdmin = srv.computeAdmin(res)

	// Persist the fully-assembled fingerprint to Redis (async, non-blocking).
	// Only fingerprinted requests; plain :80 redirect hits have no TLS.
	if res.TLS != nil {
		if st := srv.GetStore(); st != nil {
			st.Enqueue(res)
		}
	}

	paths := srv.getAllPaths()
	if u != nil {
		if val, ok := paths[u.Path]; ok {
			return val(res, m)
		}
	}
	// 404
	b, err := utils.ReadFile("static/404.html")
	if err != nil {
		return []byte(`{"error": "page not found"}`), "application/json", nil
	}
	return []byte(b), "text/html", nil
}
