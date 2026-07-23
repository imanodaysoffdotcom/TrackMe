package server

import (
	"crypto/subtle"
	"strings"
	"sync"

	"github.com/pagpeter/trackme/pkg/store"
	"github.com/pagpeter/trackme/pkg/types"
)

// State holds all the global state previously scattered across the application
type State struct {
	Config          *types.Config
	TCPFingerprints sync.Map
	SPHBI           sync.Map
	JA4T            sync.Map
	QOSFKernel      sync.Map
	Local           bool
	Store           *store.Store
}

// Server provides access to shared state and functionality
type Server struct {
	State *State
}

// NewServer creates a new server instance with initialized state
func NewServer() *Server {
	return &Server{
		State: &State{
			Config:          &types.Config{},
			TCPFingerprints: sync.Map{},
		},
	}
}

// GetConfig returns the loaded configuration
func (s *Server) GetConfig() *types.Config {
	return s.State.Config
}

// GetTCPFingerprints returns the TCP fingerprints map
func (s *Server) GetTCPFingerprints() *sync.Map {
	return &s.State.TCPFingerprints
}

// GetSPHBI returns the Single Packet Header Binary Image map (keyed by client IP:port)
func (s *Server) GetSPHBI() *sync.Map {
	return &s.State.SPHBI
}

// GetJA4T returns the JA4T TCP-client-fingerprint map. Keyed by client IP:port
// and (as a fallback for protocols without their own SYN, e.g. HTTP/3 over QUIC)
// by client IP alone, mirroring the SPHBI map.
func (s *Server) GetJA4T() *sync.Map {
	return &s.State.JA4T
}

// GetQOSFKernel returns the QOSF kernel/long-header observation map. Populated
// ONLY by the packet tap's QUIC branch from the client's first QUIC long-header
// datagram, and keyed by client IP:port and by IP alone, mirroring the SPHBI map.
// Carries the OS-bearing fields (TTL/ECN/DF/flow) + QUIC long-header fields
// (version, connection-ID lengths) that the UDP socket API cannot observe.
func (s *Server) GetQOSFKernel() *sync.Map {
	return &s.State.QOSFKernel
}

// GetAdmin returns the CORS key configuration
func (s *Server) GetAdmin() (string, bool) {
	return s.State.Config.CorsKey, s.State.Config.CorsKey != ""
}

// InitStore connects the Redis visit store if enabled. A connection failure is
// returned (and logged by the caller) but is non-fatal: the server runs without
// history storage rather than refusing to start.
func (s *Server) InitStore() error {
	cfg := s.State.Config
	if !cfg.IsRedisEnabled() {
		return nil
	}
	addr := cfg.RedisAddr
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	st, err := store.New(addr, cfg.RedisPassword)
	if err != nil {
		return err
	}
	s.State.Store = st
	return nil
}

// GetStore returns the Redis visit store, or nil if storage is disabled/down.
func (s *Server) GetStore() *store.Store {
	return s.State.Store
}

// collectHeaders gathers every request header line from whichever protocol
// section is populated on res (h1 lines, h3 lines, or h2 HEADERS-frame lines).
func collectHeaders(res types.Response) []string {
	var headers []string
	if res.Http1 != nil {
		headers = append(headers, res.Http1.Headers...)
	}
	if res.Http3 != nil {
		headers = append(headers, res.Http3.Headers...)
	}
	if res.Http2 != nil {
		for _, f := range res.Http2.SendFrames {
			headers = append(headers, f.Headers...)
		}
	}
	return headers
}

// computeAdmin decides whether a request is the owner: localhost, or any request
// header whose name exactly equals the configured CorsKey. Used to gate the
// historical endpoints when history_public is false. Covers h1/h2/h3.
func (s *Server) computeAdmin(res types.Response) bool {
	if s.IsLocal() {
		return true
	}
	key, ok := s.GetAdmin()
	if !ok {
		return false
	}
	for _, h := range collectHeaders(res) {
		name := h
		if i := strings.Index(h, ":"); i >= 0 {
			name = h[:i]
		}
		if strings.EqualFold(strings.TrimSpace(name), key) {
			return true
		}
	}
	return false
}

// collectAuthorized reports whether res carries the configured trusted-collection
// header (CollectKey) with the correct secret value, compared in constant time.
// Returns false when no CollectSecret is set, so request-parameter capture is
// strictly opt-in (fail closed). Localhost is NOT auto-trusted here: capture is
// a deliberate, secret-gated action, unlike the owner/admin read gate.
func (s *Server) collectAuthorized(res types.Response) bool {
	secret := s.GetConfig().CollectSecret
	if secret == "" {
		return false
	}
	key := s.GetConfig().CollectKey
	if key == "" {
		key = types.DefaultCollectKey
	}
	got := findHeader(collectHeaders(res), key)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(secret)) == 1
}

// DeleteHeader is the request header carrying the delete password.
const DeleteHeader = "X-Delete-Password"

// DeleteEnabled reports whether a delete password is configured.
func (s *Server) DeleteEnabled() bool { return s.GetConfig().DeletePassword != "" }

// deleteAuthorized reports whether res carries the correct delete password in the
// X-Delete-Password header (constant-time compare). False when no password is
// configured, so the destructive endpoints are off by default (fail closed).
func (s *Server) deleteAuthorized(res types.Response) bool {
	pw := s.GetConfig().DeletePassword
	if pw == "" {
		return false
	}
	got := findHeader(collectHeaders(res), DeleteHeader)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(pw)) == 1
}

// GetUserAgent extracts the user agent from a response
func GetUserAgent(res types.Response) string {
	var headers []string
	var ua string

	if res.HTTPVersion == "h2" {
		return res.UserAgent
	} else {
		if res.Http1 == nil {
			return ""
		}
		headers = res.Http1.Headers
	}

	for _, header := range headers {
		lower := strings.ToLower(header)
		if strings.HasPrefix(lower, "user-agent: ") {
			ua = strings.Split(header, ": ")[1]
		}
	}

	return ua
}

// SetLocal sets the local development flag
func (s *Server) SetLocal(local bool) {
	s.State.Local = local
}

// IsLocal returns whether we're running in local development mode
func (s *Server) IsLocal() bool {
	return s.State.Local
}
