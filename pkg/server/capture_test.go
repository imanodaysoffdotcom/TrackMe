package server

import (
	"encoding/base64"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pagpeter/trackme/pkg/types"
)

func TestFindHeader(t *testing.T) {
	hdrs := []string{":method: GET", "Host: a.b", "X-Collect: s3cr3t", "content-type: application/json"}
	cases := []struct{ key, want string }{
		{"x-collect", "s3cr3t"}, // case-insensitive name match
		{"X-COLLECT", "s3cr3t"}, // fully case-insensitive
		{"content-type", "application/json"},
		{"host", "a.b"},
		{"method", ""}, // pseudo-header (colon at index 0) must NOT match
		{"absent", ""}, // missing header
	}
	for _, c := range cases {
		if got := findHeader(hdrs, c.key); got != c.want {
			t.Errorf("findHeader(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}

func TestNewRequestDetails(t *testing.T) {
	rd := newRequestDetails("POST", "/api/x?a=1&a=2&b=z",
		[]string{"content-type: text/plain"}, []byte("hello"), false, "")
	if rd.Method != "POST" || rd.Target != "/api/x?a=1&a=2&b=z" {
		t.Fatalf("method/target wrong: %+v", rd)
	}
	if rd.ContentType != "text/plain" {
		t.Errorf("content_type = %q", rd.ContentType)
	}
	if rd.BodyBytes != 5 || rd.BodyB64 != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Errorf("body wrong: bytes=%d b64=%q", rd.BodyBytes, rd.BodyB64)
	}
	if got := rd.Query["a"]; len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Errorf("query a = %v, want [1 2]", got)
	}
	if got := rd.Query["b"]; len(got) != 1 || got[0] != "z" {
		t.Errorf("query b = %v, want [z]", got)
	}

	// No query => nil map (omitted from JSON).
	if rd2 := newRequestDetails("GET", "/x", nil, nil, false, ""); rd2.Query != nil {
		t.Errorf("expected nil query, got %v", rd2.Query)
	}
	// Empty body => no base64 field.
	if rd3 := newRequestDetails("GET", "/x", nil, nil, false, ""); rd3.BodyB64 != "" || rd3.BodyBytes != 0 {
		t.Errorf("expected empty body, got bytes=%d b64=%q", rd3.BodyBytes, rd3.BodyB64)
	}
}

// The collection control header must never land in the stored record (it carries
// the secret and isn't part of the client's natural request).
func TestNewRequestDetailsRedactsCollectHeader(t *testing.T) {
	hdrs := []string{"Host: a.b", "X-Collect: s3cr3t", "Accept: */*"}
	rd := newRequestDetails("GET", "/x", hdrs, nil, false, "X-Collect")
	for _, h := range rd.Headers {
		if strings.HasPrefix(strings.ToLower(h), "x-collect:") {
			t.Fatalf("collection header leaked into record: %q", h)
		}
	}
	if len(rd.Headers) != 2 {
		t.Errorf("expected 2 headers after redaction, got %v", rd.Headers)
	}
}

func TestNewRequestDetailsBinaryBodyRoundTrips(t *testing.T) {
	bin := []byte{0x00, 0xff, 0x10, 0x80, 0x00, 0x7f}
	rd := newRequestDetails("PUT", "/x", nil, bin, false, "")
	got, err := base64.StdEncoding.DecodeString(rd.BodyB64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != string(bin) {
		t.Errorf("binary body corrupted: %v -> %v", bin, got)
	}
}

func TestCaptureHTTP2Request(t *testing.T) {
	frames := []types.ParsedFrame{
		{Type: "SETTINGS"},
		{Type: "HEADERS", Headers: []string{":method: POST", ":path: /up"}},
		{Type: "DATA", Payload: []byte("foo")},
		{Type: "DATA", Payload: []byte("bar")},
	}
	rd := captureHTTP2Request("POST", "/up", frames[1].Headers, frames, "")
	if rd.BodyBytes != 6 {
		t.Fatalf("body bytes = %d, want 6", rd.BodyBytes)
	}
	body, _ := base64.StdEncoding.DecodeString(rd.BodyB64)
	if string(body) != "foobar" {
		t.Errorf("reassembled body = %q, want foobar", body)
	}
	if rd.Truncated {
		t.Errorf("unexpected truncation")
	}
}

func TestCaptureHTTP2RequestTruncates(t *testing.T) {
	big := make([]byte, maxCollectBody+100)
	frames := []types.ParsedFrame{{Type: "DATA", Payload: big}}
	rd := captureHTTP2Request("POST", "/up", nil, frames, "")
	if !rd.Truncated || rd.BodyBytes != maxCollectBody {
		t.Errorf("expected truncated to %d, got bytes=%d truncated=%v", maxCollectBody, rd.BodyBytes, rd.Truncated)
	}
}

func TestCaptureHTTP3Request(t *testing.T) {
	req := httptest.NewRequest("POST", "/x?q=1", strings.NewReader("payload"))
	rd := captureHTTP3Request(req, []string{":method: POST", "content-type: text/x"}, "")
	if rd.Target != "/x?q=1" || rd.Method != "POST" {
		t.Fatalf("target/method wrong: %+v", rd)
	}
	body, _ := base64.StdEncoding.DecodeString(rd.BodyB64)
	if string(body) != "payload" {
		t.Errorf("body = %q, want payload", body)
	}
	if got := rd.Query["q"]; len(got) != 1 || got[0] != "1" {
		t.Errorf("query q = %v", got)
	}
}

// captureHTTP1Request: body fully buffered (Content-Length == buffered), so the
// conn is never read.
func TestCaptureHTTP1RequestBuffered(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	raw := []byte("POST /x?a=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello")
	details := parseHTTP1(raw)
	rd := captureHTTP1Request(c1, details, raw, "")
	if rd.Method != "POST" || rd.Target != "/x?a=1" {
		t.Fatalf("method/target wrong: %+v", rd)
	}
	body, _ := base64.StdEncoding.DecodeString(rd.BodyB64)
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}
}

// captureHTTP1Request: part of the body is buffered, the rest must be read off
// the connection using Content-Length.
func TestCaptureHTTP1RequestReadsRemainder(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	// Buffer holds headers + "hel"; remaining "lo world" (8 bytes) arrives on conn.
	raw := []byte("POST /x HTTP/1.1\r\nContent-Length: 11\r\n\r\nhel")
	details := parseHTTP1(raw)
	go func() {
		_, _ = c2.Write([]byte("lo world"))
		c2.Close()
	}()
	rd := captureHTTP1Request(c1, details, raw, "")
	body, _ := base64.StdEncoding.DecodeString(rd.BodyB64)
	if string(body) != "hello world" {
		t.Errorf("body = %q, want %q", body, "hello world")
	}
	if rd.BodyBytes != 11 {
		t.Errorf("body bytes = %d, want 11", rd.BodyBytes)
	}
}

func TestCollectAuthorized(t *testing.T) {
	srv := NewServer()
	srv.GetConfig().CollectKey = "X-Collect"
	srv.GetConfig().CollectSecret = "s3cr3t"

	h1 := func(line string) types.Response {
		return types.Response{Http1: &types.Http1Details{Headers: []string{"Host: h", line}}}
	}
	if !srv.collectAuthorized(h1("X-Collect: s3cr3t")) {
		t.Error("expected authorized for correct secret")
	}
	if srv.collectAuthorized(h1("X-Collect: wrong")) {
		t.Error("expected NOT authorized for wrong secret")
	}
	if srv.collectAuthorized(h1("Host: h")) {
		t.Error("expected NOT authorized when header absent")
	}

	// h2 frames path.
	h2 := types.Response{Http2: &types.Http2Details{SendFrames: []types.ParsedFrame{
		{Type: "HEADERS", Headers: []string{":method: GET", "x-collect: s3cr3t"}},
	}}}
	if !srv.collectAuthorized(h2) {
		t.Error("expected authorized via h2 frame header")
	}

	// Fail closed when no secret is configured.
	srv.GetConfig().CollectSecret = ""
	if srv.collectAuthorized(h1("X-Collect: s3cr3t")) {
		t.Error("expected NOT authorized when CollectSecret unset (fail closed)")
	}
}
