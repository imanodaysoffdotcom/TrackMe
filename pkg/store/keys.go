// Package store persists fingerprinted client visits to Redis and serves the
// historical "Previous Clients" read queries. Key derivation and serialization
// live here (pure, unit-tested); the Redis client + async writer live in store.go.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"

	"github.com/pagpeter/trackme/pkg/types"
)

// ConnKey uniquely identifies one connection: the TLS/QUIC ClientRandom when
// present (unique per handshake), else a hash of ip:port (non-TLS fallback).
func ConnKey(res types.Response) string {
	if res.TLS != nil && res.TLS.ClientRandom != "" {
		return res.TLS.ClientRandom
	}
	sum := sha256.Sum256([]byte(res.IP))
	return "nc_" + hex.EncodeToString(sum[:8])
}

// ClientKey groups a client/stack across connections, ports and IPs: a hash of
// the stable fingerprint traits, deliberately excluding IP/port/ClientRandom so
// the same browser collapses to one key while distinct stacks behind one NAT
// stay separate.
func ClientKey(res types.Response) string {
	var ja4, pp, ak string
	if res.TLS != nil {
		ja4, pp = res.TLS.JA4, res.TLS.PeetPrint
	}
	if res.Http2 != nil {
		ak = res.Http2.AkamaiFingerprint
	} else if res.Http3 != nil {
		ak = res.Http3.AkamaiFingerprint
	}
	sphbiHex := ""
	if res.SPHBI != nil {
		sphbiHex = res.SPHBI.Hex
	}
	tcpOpts := res.TCPIP.TCP.OptionsOrder
	// \x1f (unit separator) avoids accidental field-boundary collisions.
	parts := strings.Join([]string{ja4, pp, ak, res.UserAgent, sphbiHex, tcpOpts}, "\x1f")
	sum := sha256.Sum256([]byte(parts))
	return hex.EncodeToString(sum[:])
}

// PortOf extracts the source port from "ip:port" (the form of Response.IP).
func PortOf(ipport string) string {
	if _, p, err := net.SplitHostPort(ipport); err == nil {
		return p
	}
	return ""
}

// HostOf extracts the bare IP from "ip:port" (handles IPv6 literals).
func HostOf(ipport string) string {
	if h, _, err := net.SplitHostPort(ipport); err == nil {
		return h
	}
	return ipport
}

// SummaryJSON is the denormalized list-view payload stored as the client hash's
// summary_json field, so listing N clients costs one HGET each (no HGETALL).
func SummaryJSON(res types.Response, visitCount, ipCount, lastSeen, firstSeen int64) string {
	ja4 := ""
	if res.TLS != nil {
		ja4 = res.TLS.JA4
	}
	m := map[string]interface{}{
		"last_seen":   lastSeen,
		"first_seen":  firstSeen,
		"visit_count": visitCount,
		"ip_count":    ipCount,
		"ja4":         ja4,
		"ja4t":        res.TCPIP.JA4T,
		"user_agent":  res.UserAgent,
		"sphbi":       res.SPHBI,
	}
	b, _ := json.Marshal(m)
	return string(b)
}
