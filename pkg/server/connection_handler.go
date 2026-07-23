package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pagpeter/quic-go/http3"
	trackmehttp "github.com/pagpeter/trackme/pkg/http"
	"github.com/pagpeter/trackme/pkg/tls"
	"github.com/pagpeter/trackme/pkg/types"
	"github.com/pagpeter/trackme/pkg/utils"
	utls "github.com/wwhtrbbtt/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const HTTP2_PREAMBLE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// parseHeaderValue safely extracts the value from a header string "key: value"
func parseHeaderValue(header, prefix string) string {
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	parts := strings.SplitN(header, ": ", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// maxCollectBody caps how many request-body bytes a trusted-collection request
// stores. Bodies beyond this are truncated and flagged.
const maxCollectBody = 256 * 1024

// findHeader returns the value of the first header named key (case-insensitive)
// in a list of "name: value" lines. h2/h3 pseudo-headers (colon at index 0) are
// skipped. Returns "" when absent.
func findHeader(headers []string, key string) string {
	for _, h := range headers {
		i := strings.Index(h, ":")
		if i <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(h[:i]), key) {
			return strings.TrimSpace(h[i+1:])
		}
	}
	return ""
}

// newRequestDetails assembles a RequestDetails from the request line, header
// lines and captured body. The body is stored base64-encoded so binary payloads
// survive JSON round-tripping intact. truncated marks a body that hit the cap.
// redact, when non-empty, names a header to drop from the stored record — used to
// keep our own collection control header (and its secret) out of the dataset.
func newRequestDetails(method, target string, headers []string, body []byte, truncated bool, redact string) *types.RequestDetails {
	var query map[string][]string
	if i := strings.IndexByte(target, '?'); i >= 0 {
		if vals, err := url.ParseQuery(target[i+1:]); err == nil && len(vals) > 0 {
			query = map[string][]string(vals)
		}
	}
	if redact != "" {
		kept := make([]string, 0, len(headers))
		for _, h := range headers {
			if i := strings.Index(h, ":"); i > 0 && strings.EqualFold(strings.TrimSpace(h[:i]), redact) {
				continue // drop our collection control header (carries the secret)
			}
			kept = append(kept, h)
		}
		headers = kept
	}
	rd := &types.RequestDetails{
		Method:      method,
		Target:      target,
		Query:       query,
		Headers:     headers,
		ContentType: findHeader(headers, "content-type"),
		BodyBytes:   len(body),
		Truncated:   truncated,
		CapturedTS:  time.Now().Unix(),
	}
	if len(body) > 0 {
		rd.BodyB64 = base64.StdEncoding.EncodeToString(body)
	}
	return rd
}

// captureHTTP1Request builds the trusted-collection record for an HTTP/1 request.
// raw is the exact bytes read so far (request line + headers + any buffered body);
// when Content-Length promises more body than is buffered, the remainder is read
// from conn (bounded by maxCollectBody and a short deadline) before the response
// is written.
func captureHTTP1Request(conn net.Conn, details types.Response, raw []byte, collectKey string) *types.RequestDetails {
	var headers []string
	if details.Http1 != nil {
		headers = details.Http1.Headers
	}
	var body []byte
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		body = append(body, raw[idx+4:]...)
	}
	truncated := false
	if cl, err := strconv.Atoi(findHeader(headers, "content-length")); err == nil && cl > len(body) {
		need := cl - len(body)
		if room := maxCollectBody - len(body); need > room {
			need = room
			truncated = true
		}
		if need > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			extra := make([]byte, need)
			n, _ := io.ReadFull(conn, extra)
			body = append(body, extra[:n]...)
			_ = conn.SetReadDeadline(time.Time{}) // clear before writing the response
		}
	}
	if len(body) > maxCollectBody {
		body = body[:maxCollectBody]
		truncated = true
	}
	return newRequestDetails(details.Method, details.Path, headers, body, truncated, collectKey)
}

// captureHTTP2Request builds the trusted-collection record for an HTTP/2 request.
// The body is reassembled from the DATA-frame payloads already collected by the
// frame loop (no extra read), so it never perturbs the h2 fingerprinting.
func captureHTTP2Request(method, path string, headers []string, frames []types.ParsedFrame, collectKey string) *types.RequestDetails {
	var body []byte
	truncated := false
	for _, f := range frames {
		if f.Type != "DATA" || len(f.Payload) == 0 {
			continue
		}
		body = append(body, f.Payload...)
		if len(body) >= maxCollectBody {
			body = body[:maxCollectBody]
			truncated = true
			break
		}
	}
	return newRequestDetails(method, path, headers, body, truncated, collectKey)
}

// captureHTTP3Request builds the trusted-collection record for an HTTP/3 request,
// reading the body from the standard request stream (bounded by maxCollectBody).
func captureHTTP3Request(r *http.Request, headers []string, collectKey string) *types.RequestDetails {
	var body []byte
	truncated := false
	if r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, maxCollectBody+1))
		if len(b) > maxCollectBody {
			b = b[:maxCollectBody]
			truncated = true
		}
		body = b
	}
	return newRequestDetails(r.Method, r.URL.RequestURI(), headers, body, truncated, collectKey)
}

func parseHTTP1(request []byte) types.Response {
	// Split the request into lines
	lines := strings.Split(string(request), "\r\n")
	if len(lines) == 0 {
		return types.Response{
			HTTPVersion: "--",
			Method:      "--",
			Path:        "--",
		}
	}

	// Split the first line into the method, path and http version
	firstLine := strings.Split(lines[0], " ")

	// Split the headers into an array
	var headers []string
	var userAgent string
	for _, line := range lines {
		if strings.Contains(line, ":") {
			headers = append(headers, line)
			if strings.HasPrefix(strings.ToLower(line), "user-agent") {
				if val := parseHeaderValue(line, ""); val != "" {
					userAgent = strings.TrimSpace(val)
				}
			}
		}
	}

	if len(firstLine) != 3 {
		return types.Response{
			HTTPVersion: "--",
			Method:      "--",
			Path:        "--",
		}
	}
	return types.Response{
		HTTPVersion: firstLine[2],
		Path:        firstLine[1],
		Method:      firstLine[0],
		UserAgent:   userAgent,
		Http1: &types.Http1Details{
			Headers: headers,
		},
	}
}

func parseHTTP2(f *http2.Framer, c chan types.ParsedFrame) {
	for {
		frame, err := f.ReadFrame()
		if err != nil {
			r := "ERROR_CLOSE"
			if strings.HasSuffix(err.Error(), "unknown certificate") {
				r = "ERROR"
			}
			c <- types.ParsedFrame{Type: r}
			return
		}

		p := types.ParsedFrame{}
		p.Type = frame.Header().Type.String()
		p.Stream = frame.Header().StreamID
		p.Length = frame.Header().Length
		p.Flags = utils.GetAllFlags(frame)

		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			p.Settings = []string{}
			frame.ForeachSetting(func(s http2.Setting) error {
				setting := fmt.Sprintf("%q", s)
				setting = strings.Replace(setting, "\"", "", -1)
				setting = strings.Replace(setting, "[", "", -1)
				setting = strings.Replace(setting, "]", "", -1)

				// SETTINGS_NO_RFC7540_PRIORITIES
				// https://www.rfc-editor.org/rfc/rfc9218.html#section-2.1
				// https://github.com/golang/go/issues/69917
				// TODO: when net/http2 is updated to support it, remove this as it won't be needed (this is ugly code too)
				if strings.HasPrefix(setting, "UNKNOWN_SETTING_9 = ") {
					setting = strings.ReplaceAll(setting, "UNKNOWN_SETTING_9", "NO_RFC7540_PRIORITIES")
				}

				p.Settings = append(p.Settings, setting)
				return nil
			})
		case *http2.HeadersFrame:
			d := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})
			d.SetEmitEnabled(true)
			h2Headers, err := d.DecodeFull(frame.HeaderBlockFragment())
			if err != nil {
				return
			}

			for _, h := range h2Headers {
				headerStr := fmt.Sprintf("%s: %s", h.Name, h.Value)
				p.Headers = append(p.Headers, headerStr)
			}
			if frame.HasPriority() {
				prio := types.Priority{}
				p.Priority = &prio
				// 6.2: Weight: An 8-bit weight for the stream; Add one to the value to obtain a weight between 1 and 256
				p.Priority.Weight = int(frame.Priority.Weight) + 1
				p.Priority.DependsOn = int(frame.Priority.StreamDep)
				if frame.Priority.Exclusive {
					p.Priority.Exclusive = 1
				}
			}
		case *http2.DataFrame:
			p.Payload = frame.Data()
		case *http2.WindowUpdateFrame:
			p.Increment = frame.Increment
		case *http2.PriorityFrame:
			prio := types.Priority{}
			p.Priority = &prio
			// 6.3: Weight: An 8-bit weight for the stream; Add one to the value to obtain a weight between 1 and 256
			p.Priority.Weight = int(frame.PriorityParam.Weight) + 1
			p.Priority.DependsOn = int(frame.PriorityParam.StreamDep)
			if frame.PriorityParam.Exclusive {
				p.Priority.Exclusive = 1
			}
		case *http2.GoAwayFrame:
			p.GoAway = &types.GoAway{}
			p.GoAway.LastStreamID = frame.LastStreamID
			p.GoAway.ErrCode = uint32(frame.ErrCode)
			p.GoAway.DebugData = frame.DebugData()
		}

		c <- p
	}
}

func (srv *Server) HandleTLSConnection(conn net.Conn) error {
	// Read the first line of the request
	// We only read the first line to determine if the connection is HTTP1 or HTTP2
	// If we know that it isnt HTTP2, we can read the rest of the request and then start processing it
	// If we know that it is HTTP2, we start the HTTP2 handler

	l := len([]byte(HTTP2_PREAMBLE))
	request := make([]byte, l)

	_, err := conn.Read(request)
	if err != nil {
		if strings.HasSuffix(err.Error(), "unknown certificate") && srv.IsLocal() {
			// Local development error - don't close connection
			return nil
		}
		return fmt.Errorf("failed to read request: %w", err)
	}

	hs := conn.(*utls.Conn).ClientHello

	parsedClientHello := tls.ParseClientHello(hs)
	JA3Data := tls.CalculateJA3(parsedClientHello)
	peetfp, peetprintHash := tls.CalculatePeetPrint(parsedClientHello, JA3Data)

	// Convert raw bytes to hex and base64
	rawBytes, err := hex.DecodeString(hs)
	if err != nil {
		return fmt.Errorf("failed to decode hex: %w", err)
	}
	rawB64 := base64.StdEncoding.EncodeToString(rawBytes)

	tlsDetails := types.TLSDetails{
		Ciphers:          JA3Data.ReadableCiphers,
		Extensions:       parsedClientHello.Extensions,
		RecordVersion:    JA3Data.Version,
		NegotiatedVesion: fmt.Sprintf("%v", conn.(*utls.Conn).ConnectionState().Version),
		JA3:              JA3Data.JA3,
		JA3Hash:          JA3Data.JA3Hash,
		PeetPrint:        peetfp,
		PeetPrintHash:    peetprintHash,

		QUICTransportParameters: parsedClientHello.QUICTransportParams,

		SessionID:    parsedClientHello.SessionID,
		ClientRandom: parsedClientHello.ClientRandom,
		RawBytes:     hs,
		RawB64:       rawB64,
	}

	// Check if the first line is HTTP/2
	if string(request) == HTTP2_PREAMBLE {
		srv.handleHTTP2(conn, &tlsDetails)
	} else {
		// Read the rest of the request
		r2 := make([]byte, 1024-l)
		n2, err := conn.Read(r2)
		if err != nil {
			return fmt.Errorf("failed to read HTTP/1 request: %w", err)
		}
		// Append it to the first line
		request = append(request, r2...)

		// Parse and handle the request
		details := parseHTTP1(request)
		details.IP = conn.RemoteAddr().String()
		details.TLS = &tlsDetails
		// Trusted-collection: capture the raw request (incl. body) when it carries
		// the configured collection header + secret. Done before responding so the
		// body's remaining bytes can still be read off the open connection.
		if srv.collectAuthorized(details) {
			raw := make([]byte, 0, l+n2)
			raw = append(raw, request[:l]...) // first read: request line + headers start
			raw = append(raw, r2[:n2]...)     // second read: rest of headers + buffered body
			details.Request = captureHTTP1Request(conn, details, raw, srv.GetConfig().CollectKey)
		}
		srv.respondToHTTP1(conn, details)
	}
	return nil
}

func (srv *Server) respondToHTTP1(conn net.Conn, resp types.Response) {
	var isAdmin bool
	var res []byte
	var ctype = "text/plain"
	if resp.Method != "OPTIONS" {
		var err error
		res, ctype, err = Router(resp.Path, resp, srv)
		if err != nil {
			log.Println("Router error:", err)
			res = []byte(fmt.Sprintf(`{"error": "%s"}`, err.Error()))
			ctype = "application/json"
		}
	} else {
		isAdmin = true
	}

	key, isKeySet := srv.GetAdmin()
	if isKeySet && resp.Http1 != nil {
		for _, a := range resp.Http1.Headers {
			if strings.HasPrefix(a, key) {
				isAdmin = true
			}
		}
	}

	res1 := "HTTP/1.1 200 OK\r\n"
	res1 += "Content-Length: " + fmt.Sprintf("%v\r\n", len(res))
	res1 += "Content-Type: " + ctype + "; charset=utf-8\r\n"
	if isAdmin {
		res1 += "Access-Control-Allow-Origin: *\r\n"
		res1 += "Access-Control-Allow-Methods: *\r\n"
		res1 += "Access-Control-Allow-Headers: *\r\n"
	}
	res1 += "Server: TrackMe\r\n"
	res1 += "Alt-Svc: h3=\":443\"; ma=86400\r\n"
	res1 += "\r\n"
	res1 += string(res)
	res1 += "\r\n\r\n"

	if _, err := conn.Write([]byte(res1)); err != nil {
		log.Println("Error writing HTTP/1 data:", err)
		return
	}
	if err := conn.Close(); err != nil {
		log.Println("Error closing HTTP/1 connection:", err)
	}
}

// https://stackoverflow.com/questions/52002623/golang-tcp-server-how-to-write-http2-data
func (srv *Server) handleHTTP2(conn net.Conn, tlsFingerprint *types.TLSDetails) {
	// make a new framer to encode/decode frames
	fr := http2.NewFramer(conn, conn)
	c := make(chan types.ParsedFrame)
	var frames []types.ParsedFrame

	// Same settings that google uses
	if err := fr.WriteSettings(
		http2.Setting{
			ID: http2.SettingInitialWindowSize, Val: 1048576,
		},
		http2.Setting{
			ID: http2.SettingMaxConcurrentStreams, Val: 100,
		},
		http2.Setting{
			ID: http2.SettingMaxHeaderListSize, Val: 65536,
		},
	); err != nil {
		log.Println("Error writing settings:", err)
		return
	}

	var frame types.ParsedFrame
	var headerFrame types.ParsedFrame
	var isAdmin bool

	go parseHTTP2(fr, c)

	for {
		frame = <-c
		if frame.Type == "ERROR_CLOSE" {
			if err := conn.Close(); err != nil {
				log.Println("Error closing connection:", err)
			}
			return
		} else if frame.Type == "ERROR" {
			return
		}
		frames = append(frames, frame)
		if frame.Type == "HEADERS" {
			headerFrame = frame
		}
		if len(frame.Flags) > 0 && frame.Flags[0] == "EndStream (0x1)" {
			break
		}
	}

	// get method, path and user-agent from the header frame
	var path string
	var method string
	var userAgent string
	key, isKeySet := srv.GetAdmin()

	for _, h := range headerFrame.Headers {
		if val := parseHeaderValue(h, ":method"); val != "" {
			method = val
		}
		if val := parseHeaderValue(h, ":path"); val != "" {
			path = val
		}
		if val := parseHeaderValue(h, "user-agent"); val != "" {
			userAgent = val
		}
		if isKeySet && strings.HasPrefix(h, key) {
			isAdmin = true
		}
	}

	resp := types.Response{
		IP:          conn.RemoteAddr().String(),
		HTTPVersion: "h2",
		Path:        path,
		Method:      method,
		UserAgent:   userAgent,
		Http2: &types.Http2Details{
			SendFrames:            frames,
			AkamaiFingerprint:     trackmehttp.GetAkamaiFingerprint(frames),
			AkamaiFingerprintHash: utils.GetMD5Hash(trackmehttp.GetAkamaiFingerprint(frames)),
		},
		TLS: tlsFingerprint,
	}

	// Trusted-collection: capture the raw request when it carries the configured
	// collection header + secret. The body is reassembled from the DATA frames the
	// loop already collected, so h2 fingerprinting is untouched.
	if srv.collectAuthorized(resp) {
		resp.Request = captureHTTP2Request(method, path, headerFrame.Headers, frames, srv.GetConfig().CollectKey)
	}

	var res []byte
	var ctype = "text/plain"
	if method != "OPTIONS" {
		var err error
		res, ctype, err = Router(path, resp, srv)
		if err != nil {
			log.Println("Router error:", err)
			res = []byte(fmt.Sprintf(`{"error": "%s"}`, err.Error()))
			ctype = "application/json"
		}
	} else {
		isAdmin = true
	}

	// Prepare HEADERS
	hbuf := bytes.NewBuffer([]byte{})
	encoder := hpack.NewEncoder(hbuf)
	encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	encoder.WriteField(hpack.HeaderField{Name: "server", Value: "TrackMe.peet.ws"})
	encoder.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(res))})
	encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: ctype})
	encoder.WriteField(hpack.HeaderField{Name: "alt-svc", Value: "h3=\":443\"; ma=86400"})
	if isAdmin {
		encoder.WriteField(hpack.HeaderField{Name: "access-control-allow-origin", Value: "*"})
		encoder.WriteField(hpack.HeaderField{Name: "access-control-allow-methods", Value: "*"})
		encoder.WriteField(hpack.HeaderField{Name: "access-control-allow-headers", Value: "*"})
	}

	// Write HEADERS frame
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: headerFrame.Stream, BlockFragment: hbuf.Bytes(), EndHeaders: true}); err != nil {
		log.Println("Error writing headers:", err)
		return
	}

	chunks := utils.SplitBytesIntoChunks(res, 1024)
	for _, chunk := range chunks {
		if err := fr.WriteData(headerFrame.Stream, false, chunk); err != nil {
			log.Println("Error writing data chunk:", err)
			return
		}
	}
	if err := fr.WriteData(headerFrame.Stream, true, []byte{}); err != nil {
		log.Println("Error writing final data frame:", err)
	}
	if err := fr.WriteGoAway(headerFrame.Stream, http2.ErrCodeNo, []byte{}); err != nil {
		log.Println("Error writing GoAway:", err)
	}

	time.Sleep(time.Millisecond * 500)
	if err := conn.Close(); err != nil {
		log.Println("Error closing HTTP/2 connection:", err)
	}
}

// HandleHTTP3 handles HTTP/3 requests
func (srv *Server) HandleHTTP3() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h3w, ok := w.(*http3.ResponseWriter)
		if !ok {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		h3c := h3w.Connection()
		if h3c == nil {
			http.Error(w, "No HTTP/3 connection", http.StatusInternalServerError)
			return
		}

		h3state := h3c.ConnectionState()

		// Extract TLS fingerprint from QUIC ClientHello
		var tlsDetails *types.TLSDetails
		if len(h3state.ClientHello) > 0 {
			clientHelloHex := hex.EncodeToString(h3state.ClientHello)
			parsedClientHello := tls.ParseClientHello(clientHelloHex)
			JA3Data := tls.CalculateJA3(parsedClientHello)
			peetfp, peetprintHash := tls.CalculatePeetPrint(parsedClientHello, JA3Data)

			rawB64 := base64.StdEncoding.EncodeToString(h3state.ClientHello)

			tlsDetails = &types.TLSDetails{
				Ciphers:          JA3Data.ReadableCiphers,
				Extensions:       parsedClientHello.Extensions,
				RecordVersion:    JA3Data.Version,
				NegotiatedVesion: fmt.Sprintf("%v", h3state.TLS.Version),
				JA3:              JA3Data.JA3,
				JA3Hash:          JA3Data.JA3Hash,
				PeetPrint:        peetfp,
				PeetPrintHash:    peetprintHash,
				SessionID:        parsedClientHello.SessionID,
				ClientRandom:     parsedClientHello.ClientRandom,
				RawBytes:         clientHelloHex,
				RawB64:           rawB64,

				// QUIC-only: feeds CalculateJa4QUIC and BuildQUICSPHBI in the router.
				QUICTransportParameters: parsedClientHello.QUICTransportParams,
			}
		}

		// Extract settings for fingerprinting
		var settings []types.Http3SettingPair
		if h3c.Settings() != nil {
			for _, pair := range h3c.Settings().RawSettings {
				settings = append(settings, types.Http3SettingPair{
					ID:    pair.ID,
					Name:  trackmehttp.GetHTTP3SettingName(pair.ID),
					Value: pair.Value,
				})
			}
		}

		// Extract headers in order (pseudo-headers first, then regular headers)
		var headers []string
		// Add pseudo-headers in the order they would appear
		headers = append(headers, fmt.Sprintf(":method: %s", r.Method))
		headers = append(headers, fmt.Sprintf(":authority: %s", r.Host))
		headers = append(headers, ":scheme: https")
		headers = append(headers, fmt.Sprintf(":path: %s", r.URL.RequestURI()))
		// Add regular headers
		for name, values := range r.Header {
			for _, value := range values {
				headers = append(headers, fmt.Sprintf("%s: %s", strings.ToLower(name), value))
			}
		}

		// Generate fingerprint
		headerOrder := trackmehttp.GetHTTP3HeaderOrder(headers)
		fingerprint := trackmehttp.GetHTTP3SettingsFingerprint(settings, headerOrder)
		fingerprintHash := trackmehttp.GetHTTP3FingerprintHash(fingerprint)

		resp := types.Response{
			IP:          r.RemoteAddr,
			HTTPVersion: "h3",
			// RequestURI() keeps the query string (r.URL.Path drops it), so the
			// stored path matches h1/h2 and a visit's ?query is retained.
			Path:      r.URL.RequestURI(),
			Method:    r.Method,
			UserAgent: r.Header.Get("User-Agent"),
			TLS:       tlsDetails,
			Http3: &types.Http3Details{
				Used0RTT:                           h3state.Used0RTT,
				SupportsDatagrams:                  h3state.SupportsDatagrams,
				SupportsStreamResetPartialDelivery: h3state.SupportsStreamResetPartialDelivery,
				Version:                            uint32(h3state.Version),
				GSO:                                h3state.GSO,
				Settings:                           settings,
				AkamaiFingerprint:                  fingerprint,
				AkamaiFingerprintHash:              fingerprintHash,
				Headers:                            headers,
			},
		}

		// Trusted-collection: capture the raw request (incl. body) when it carries
		// the configured collection header + secret.
		if srv.collectAuthorized(resp) {
			resp.Request = captureHTTP3Request(r, headers, srv.GetConfig().CollectKey)
		}

		// RequestURI() keeps the query string (r.URL.Path drops it), so endpoints
		// like /api/client?key=… work over HTTP/3, not just h1/h2.
		res, ctype, err := Router(r.URL.RequestURI(), resp, srv)
		if err != nil {
			log.Println("Router error:", err)
			res = []byte(fmt.Sprintf(`{"error": "%s"}`, err.Error()))
			ctype = "application/json"
		}

		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Server", "TrackMe")
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		if _, err := w.Write(res); err != nil {
			log.Println("Error writing HTTP/3 response:", err)
		}
	})

	return mux
}
