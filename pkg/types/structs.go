package types

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type TLSDetails struct {
	Ciphers          []string      `json:"ciphers"`
	Extensions       []interface{} `json:"extensions"`
	RecordVersion    string        `json:"tls_version_record"`
	NegotiatedVesion string        `json:"tls_version_negotiated"`

	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`

	JA4   string `json:"ja4"`
	JA4_r string `json:"ja4_r"`

	PeetPrint     string `json:"peetprint"`
	PeetPrintHash string `json:"peetprint_hash"`

	QUICTransportParameters []QUICTransportParam `json:"quic_transport_parameters,omitempty"`

	ClientRandom string `json:"client_random"`
	SessionID    string `json:"session_id"`
	RawBytes     string `json:"-"`
	RawB64       string `json:"-"`
}

type Http1Details struct {
	Headers []string `json:"headers"`
}

type Http2Details struct {
	AkamaiFingerprint     string        `json:"akamai_fingerprint"`
	AkamaiFingerprintHash string        `json:"akamai_fingerprint_hash"`
	SendFrames            []ParsedFrame `json:"sent_frames"`
}

type Http3Details struct {
	Used0RTT                           bool               `json:"used_0rtt"`
	SupportsDatagrams                  bool               `json:"supports_datagrams"`
	SupportsStreamResetPartialDelivery bool               `json:"supports_stream_reset_partial_delivery"`
	Version                            uint32             `json:"version"`
	GSO                                bool               `json:"gso"`
	Settings                           []Http3SettingPair `json:"settings"`
	AkamaiFingerprint                  string             `json:"akamai_fingerprint"`
	AkamaiFingerprintHash              string             `json:"akamai_fingerprint_hash"`
	Headers                            []string           `json:"headers,omitempty"`
}

// Http3SettingPair represents a single HTTP/3 setting for fingerprinting
type Http3SettingPair struct {
	ID    uint64 `json:"id"`
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

type Http3Settings struct {
	EnableDatagrams       bool               `json:"enable_datagrams"`
	EnableExtendedConnect bool               `json:"enable_extended_connect"`
	Other                 map[uint64]uint64  `json:"other,omitempty"`
	RawSettings           []Http3SettingPair `json:"settings,omitempty"`
}

type IPDetails struct {
	DF          int    `json:"df,omitempty"`
	HDRLength   int    `json:"hdr_length,omitempty"`
	ID          int    `json:"id,omitempty"`
	MF          int    `json:"mf,omitempty"`
	NXT         int    `json:"nxt,omitempty"`
	OFF         int    `json:"off,omitempty"`
	PLEN        int    `json:"plen,omitempty"`
	Protocol    int    `json:"protocol,omitempty"`
	RF          int    `json:"rf,omitempty"`
	TOS         int    `json:"tos,omitempty"`
	TotalLength int    `json:"total_length,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
	IPVersion   int    `json:"ip_version,omitempty"`
	DstIp       string `json:"dst_ip,omitempty"`
	SrcIP       string `json:"src_ip,omitempty"`
}
type TCPDetails struct {
	Ack                int    `json:"ack,omitempty"`
	Checksum           int    `json:"checksum,omitempty"`
	Flags              int    `json:"flags,omitempty"`
	HeaderLength       int    `json:"header_length,omitempty"`
	MSS                int    `json:"mss,omitempty"`
	OFF                int    `json:"off,omitempty"`
	Options            string `json:"options,omitempty"`
	OptionsOrder       string `json:"options_order,omitempty"`
	Seq                int    `json:"seq,omitempty"`
	Timestamp          int    `json:"timestamp,omitempty"`
	TimestampEchoReply int    `json:"timestamp_echo_reply,omitempty"`
	URP                int    `json:"urp,omitempty"`
	Window             int    `json:"window,omitempty"`
}
type TCPIPDetails struct {
	CapLen    int        `json:"cap_length,omitempty"`
	DstPort   int        `json:"dst_port,omitempty"`
	SrcPort   int        `json:"src_port,omitempty"`
	HeaderLen int        `json:"header_length,omitempty"`
	TS        []int      `json:"ts,omitempty"`
	IP        IPDetails  `json:"ip,omitempty"`
	TCP       TCPDetails `json:"tcp,omitempty"`
	// JA4T is FoxIO's passive TCP *client* fingerprint, computed from the client's
	// TCP SYN packet (distinct from the TLS-layer JA4). Format:
	// <window>_<option kinds, dash-separated>_<mss>_<window scale>.
	JA4T string `json:"ja4t,omitempty"`
}

// SPHBIField describes one of the selected TCP/IP header fields that make up
// the Single Packet Header Binary Image (El-Sherif et al. 2025, Table 2).
type SPHBIField struct {
	Name  string `json:"name"`
	Hex   string `json:"hex"`
	Bytes int    `json:"bytes"`
}

// QUICTransportParam is one QUIC transport parameter (RFC 9000 18.2) carried in
// the TLS ClientHello quic_transport_parameters extension (0x0039).
type QUICTransportParam struct {
	ID    uint64 `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"` // hex-encoded value bytes
}

// SPHBIDetails is the Single Packet Header Binary Image for a connection:
// 18 selected raw header bytes = 144 bits, arranged as a 12x12 binary image.
// Source/dest IP, both checksums and TCP seq/ack are intentionally excluded.
type SPHBIDetails struct {
	PacketType string       `json:"packet_type"`    // packet the image was built from, e.g. "SYN" / "Initial"
	Kind       string       `json:"kind,omitempty"` // image family: "ipv4", "ipv6" (TCP header) or "quic" (transport params)
	Hex        string       `json:"hex"`            // the selected bytes, hex-encoded
	Bits       string       `json:"bits"`           // size*size chars of '0'/'1', row-major, MSB first
	Size       int          `json:"size"`           // image edge length (12)
	Fields     []SPHBIField `json:"fields"`         // per-field breakdown
}

// --- QOSF (QUIC OS Fingerprint) --------------------------------------------
// QOSF is a readable, non-hashed passive fingerprint for QUIC connections,
// computed ALONGSIDE (never replacing) the QUIC JA4/SPHBI, and ONLY for QUIC.
// Format: q<ttl><ip><ecn><df><flow>_<stack><ver><order><grease><scid>_<tp-set>_<tp-values>
// Every field is emitted only from a source that can observe it; anything
// unobserved is "-" (never a fabricated or RFC-default value). It is meaningful
// only when this server is the first-hop QUIC terminator (which TrackMe is, via
// quic-go). See research/qosf-integration-plan.md.

// QOSFKernel holds the kernel / QUIC-long-header fields observed by the packet
// tap for one QUIC (UDP) flow: the OS-bearing signal (initial TTL/hop-limit,
// ECN, IPv4 DF, IPv6 flow label) plus the cleartext QUIC long header (version +
// connection-ID lengths, RFC 8999) that the UDP socket API cannot see. It is
// populated only by the pcap tap's QUIC branch on the client's first long-header
// packet; QOSF is computed with kern == nil (socket-only degradation) when no
// tap observed the flow, in which case those fields render "-".
type QOSFKernel struct {
	IPVersion   int    `json:"ip_version"`   // 4 or 6
	TTL         int    `json:"ttl"`          // observed IPv4 TTL / IPv6 hop limit
	ECN         int    `json:"ecn"`          // 2-bit ECN codepoint: 0=Not-ECT,1=ECT(1),2=ECT(0),3=CE
	DF          bool   `json:"df"`           // IPv4 Don't-Fragment (not meaningful for IPv6)
	FlowLabel   uint32 `json:"flow_label"`   // IPv6 flow label (0 for IPv4)
	QUICVersion   uint32 `json:"quic_version"`    // version from the QUIC long header (cross-check)
	DCIDLen       int    `json:"dcid_len"`        // client's Destination Connection ID length
	SCIDLen       int    `json:"scid_len"`        // client's Source Connection ID length
	UDPPayloadLen int    `json:"udp_payload_len"` // UDP payload size of the Initial datagram
}

// QOSFInitialStructure is the observable structure of the client's QUIC Initial
// packet (RFC 8999 long header + UDP datagram) — the userspace, library-chosen
// shape that a passive decryptor (e.g. 0x4D31/finch) reads through and a mimic
// (e.g. uQUIC's InitialPacketSpec) forges. Informational: it discriminates
// browser families (Chrome DCID=8, Firefox DCID=8/9/15; distinct padded sizes)
// but is user-space and therefore spoofable — it is NOT part of the canonical
// QOSF string. Present only when the packet tap observed the Initial.
type QOSFInitialStructure struct {
	QUICVersion     string `json:"quic_version"`      // "1" | "2" | "d" | hex
	DCIDLength      int    `json:"dcid_length"`       // client Destination Connection ID length
	SCIDLength      int    `json:"scid_length"`       // client Source Connection ID length
	UDPDatagramSize int    `json:"udp_datagram_size"` // UDP payload bytes of the Initial datagram
}

// QOSFField is one load-bearing QOSF field with its observability and the space
// that produces it, so an analyst can see exactly which fields were observed vs.
// unobserved ("-"), and which are written by the OS kernel vs. the userspace
// QUIC library.
type QOSFField struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Observed bool   `json:"observed"`
	Space    string `json:"space,omitempty"` // "kernel" (IP/UDP header) | "user" (QUIC library)
	Note     string `json:"note,omitempty"`
}

// QOSFSpace groups the QOSF by where each part is produced: the OS kernel (the
// IP/UDP header — segment A) vs. the userspace QUIC library (segments B/C/D).
// This is the load-bearing QUIC distinction — QUIC runs in user space, so the OS
// signal has to come from the kernel-written IP header (the TTL), not from
// anything QUIC puts on the wire.
type QOSFSpace struct {
	Label    string   `json:"label"`    // e.g. "OS kernel — IP/UDP header"
	Segments []string `json:"segments"` // ["A"] | ["B","C","D"]
	Value    string   `json:"value"`    // the concatenated substring of the QOSF
}

// QOSFOSGuess is a simple, honest OS-family inference derived from the QOSF —
// primarily the kernel initial TTL/hop-limit (segment A). It is never a hard
// label: it reports a family, candidate OSes, and a confidence, since the TTL is
// client-settable and TTL 64 is shared across Unix-likes. QUIC-only.
type QOSFOSGuess struct {
	Family     string   `json:"family"`               // "Windows" | "Unix-like" | … | "unknown"
	Candidates []string `json:"candidates,omitempty"` // e.g. ["Linux","Android","macOS","iOS","BSD"]
	Confidence string   `json:"confidence"`           // "none" | "low" | "moderate"
	Basis      string   `json:"basis"`                // human-readable rationale + caveat
}

// QOSFConsistency cross-checks the two layers of the fingerprint: the OS the
// kernel reveals (the initial TTL — segment A, which a userspace QUIC mimic like
// uQUIC cannot forge) vs. the OS the User-Agent claims. A mismatch means the OS
// writing the packets is not the OS being presented — the signature of a
// userspace QUIC mimic, a proxy, or a VPN. QUIC-only.
type QOSFConsistency struct {
	Verdict   string `json:"verdict"`              // "consistent" | "mismatch" | "unknown"
	ClaimedOS string `json:"claimed_os,omitempty"` // OS family parsed from the User-Agent
	KernelOS  string `json:"kernel_os,omitempty"`  // OS family implied by the kernel TTL (segment A)
	Detail    string `json:"detail"`               // human-readable rationale
}

// QOSFDetails is the QUIC OS Fingerprint for a connection: the canonical record
// plus a per-segment / per-field breakdown and an OS-family inference. QUIC-only;
// nil for TCP.
type QOSFDetails struct {
	QOSF        string       `json:"qosf"`          // canonical q..._..._..._... record
	SegKernel   string       `json:"seg_kernel"`    // segment A (kernel/OS)
	SegStack    string       `json:"seg_stack"`     // segment B (userspace stack)
	SegTPSet    string       `json:"seg_tp_set"`    // segment C (transport-param id-set)
	SegTPValues string       `json:"seg_tp_values"` // segment D (transport-param values)
	Source      string       `json:"source"`        // "pcap+quic" (segment A observed) | "socket-only"
	OS          *QOSFOSGuess `json:"os,omitempty"`  // OS-family inference (from the kernel TTL)
	// KernelSpace / UserSpace split the fingerprint by producer: the OS kernel
	// (IP/UDP header, segment A) vs. the userspace QUIC library (segments B/C/D).
	KernelSpace *QOSFSpace `json:"kernel_space,omitempty"`
	UserSpace   *QOSFSpace `json:"user_space,omitempty"`
	// Consistency cross-checks the kernel-revealed OS (TTL) against the OS the
	// User-Agent claims — catches userspace QUIC mimics (e.g. uQUIC) that forge the
	// whole QUIC layer but cannot forge the kernel TTL.
	Consistency *QOSFConsistency `json:"consistency,omitempty"`
	// InitialPacket is the observable QUIC Initial packet structure (version, CID
	// lengths, datagram size) — a userspace, spoofable discriminator, informational
	// only (not in the canonical string). Present when the tap saw the Initial.
	InitialPacket *QOSFInitialStructure `json:"initial_packet,omitempty"`
	Fields        []QOSFField           `json:"fields"`
}

// DefaultCollectKey is the request header that, carrying the configured secret
// value, marks a request as trusted for full request-parameter capture.
const DefaultCollectKey = "X-Collect"

// RequestDetails is the raw client request (method, target, query, headers and
// body) captured for a trusted-collection request — i.e. one that carried the
// configured collection header + secret. It is intended for model-training data
// pulls and is stored inside the connection record, so the request parameters
// join the very fingerprint they were observed with. nil (and unserialized) for
// ordinary traffic; capture is strictly opt-in.
type RequestDetails struct {
	Method      string              `json:"method"`
	Target      string              `json:"target"`            // request target: path + raw query
	Query       map[string][]string `json:"query,omitempty"`   // parsed query parameters
	Headers     []string            `json:"headers,omitempty"` // full ordered request header lines
	ContentType string              `json:"content_type,omitempty"`
	BodyB64     string              `json:"body_b64,omitempty"`  // request body, base64 (binary-safe)
	BodyBytes   int                 `json:"body_bytes"`          // captured body length in bytes
	Truncated   bool                `json:"truncated,omitempty"` // body hit the capture cap
	CapturedTS  int64               `json:"captured_ts,omitempty"`
}

type Response struct {
	Donate      string        `json:"donate"`
	IP          string        `json:"ip"`
	HTTPVersion string        `json:"http_version"`
	Path        string        `json:"-"`
	Method      string        `json:"method"`
	UserAgent   string        `json:"user_agent,omitempty"`
	TLS         *TLSDetails   `json:"tls"`
	Http1       *Http1Details `json:"http1,omitempty"`
	Http2       *Http2Details `json:"http2,omitempty"`
	Http3       *Http3Details `json:"http3,omitempty"`
	TCPIP       TCPIPDetails  `json:"tcpip,omitempty"`
	SPHBI       *SPHBIDetails `json:"sphbi,omitempty"`
	// QOSF is the QUIC OS Fingerprint (QUIC-only, computed alongside JA4); nil
	// and unserialized for TCP/HTTP1/HTTP2.
	QOSF *QOSFDetails `json:"qosf,omitempty"`
	// IsAdmin is set per-request by the connection handler; never serialized
	// (must not leak into /api/all or the homepage /*DATA*/ blob).
	IsAdmin bool `json:"-"`
	// Exp is the controlled-experiment token (?exp=) when present and HMAC-valid;
	// serialized so the store writer captures it alongside the fingerprint.
	Exp string `json:"exp,omitempty"`
	// Request is the captured raw request (trusted-collection only). Serialized so
	// the store writer persists it in the connection record alongside the
	// fingerprint; nil for ordinary traffic.
	Request *RequestDetails `json:"request,omitempty"`
}

func (res Response) ToJson() string {
	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Println("Error marshalling response", err)
		return ""
	}
	return string(j)
}

type SmallResponse struct {
	JA3           string `json:"ja3"`
	JA3Hash       string `json:"ja3_hash"`
	JA4           string `json:"ja4"`
	JA4_r         string `json:"ja4_r"`
	Akamai        string `json:"akamai"`
	AkamaiHash    string `json:"akamai_hash"`
	PeetPrint     string `json:"peetprint"`
	PeetPrintHash string `json:"peetprint_hash"`
	HTTPVersion   string `json:"http_version"`
}

func (res SmallResponse) ToJson() string {
	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Println("Error marshalling response", err)
		return ""
	}
	return string(j)
}

type Priority struct {
	Weight    int `json:"weight"`
	DependsOn int `json:"depends_on"`
	Exclusive int `json:"exclusive"`
}

type GoAway struct {
	LastStreamID uint32
	ErrCode      uint32
	DebugData    []byte
}

type ParsedFrame struct {
	Type      string    `json:"frame_type,omitempty"`
	Stream    uint32    `json:"stream_id,omitempty"`
	Length    uint32    `json:"length,omitempty"`
	Payload   []byte    `json:"payload,omitempty"`
	Headers   []string  `json:"headers,omitempty"`
	Settings  []string  `json:"settings,omitempty"`
	Increment uint32    `json:"increment,omitempty"`
	Flags     []string  `json:"flags,omitempty"`
	Priority  *Priority `json:"priority,omitempty"`
	GoAway    *GoAway   `json:"goaway,omitempty"`
}

type Config struct {
	TLSPort      string `json:"tls_port"`
	HTTPPort     string `json:"http_port"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	Host         string `json:"host"`
	HTTPRedirect string `json:"http_redirect"`
	Device       string `json:"device"`
	CorsKey      string `json:"cors_key"`
	EnableQUIC   bool   `json:"enable_quic"`

	// Redis client-history storage. RedisEnable/HistoryPublic are pointers so an
	// absent JSON field defaults to true (avoids silently disabling the feature).
	RedisAddr     string `json:"redis_addr,omitempty"`
	RedisPassword string `json:"redis_password,omitempty"`
	RedisEnable   *bool  `json:"redis_enable,omitempty"`
	HistoryPublic *bool  `json:"history_public,omitempty"`

	// ExpSecret HMAC-validates controlled-experiment ?exp= tokens (env EXP_SECRET).
	ExpSecret string `json:"exp_secret,omitempty"`

	// Trusted request-parameter capture. A request carrying header CollectKey with
	// value CollectSecret has its full parameters (incl. body) captured for the
	// training-data store. CollectSecret comes from the environment (COLLECT_SECRET)
	// and, when empty, disables capture entirely (fail closed). CollectKey defaults
	// to DefaultCollectKey ("X-Collect").
	CollectKey    string `json:"collect_key,omitempty"`
	CollectSecret string `json:"collect_secret,omitempty"`

	// DeletePassword gates the destructive history-deletion endpoints
	// (/api/client/delete, /api/clients/delete_all). Sent by the UI in the
	// X-Delete-Password header and compared constant-time. From the environment
	// (DELETE_PASSWORD); empty disables deletion entirely (fail closed).
	DeletePassword string `json:"delete_password,omitempty"`
}

// IsRedisEnabled reports whether visit storage is on (default true when unset).
func (c *Config) IsRedisEnabled() bool { return c.RedisEnable == nil || *c.RedisEnable }

// IsHistoryPublic reports whether the historical view is public (default true
// when unset). When false, the read endpoints require admin.
func (c *Config) IsHistoryPublic() bool { return c.HistoryPublic == nil || *c.HistoryPublic }

func (c *Config) LoadFromFile() error {
	data, err := os.ReadFile("config.json")
	if err != nil {
		fmt.Println("No config file found: generating one", err)
		c.MakeDefault()
		return c.WriteToFile("config.json")
	}

	var tmp Config
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("failed to parse config.json: %w", err)
	}

	c.Host = tmp.Host
	c.TLSPort = tmp.TLSPort
	c.HTTPPort = tmp.HTTPPort
	c.CertFile = tmp.CertFile
	c.KeyFile = tmp.KeyFile
	c.HTTPRedirect = tmp.HTTPRedirect
	c.Device = tmp.Device
	c.CorsKey = tmp.CorsKey
	c.EnableQUIC = tmp.EnableQUIC
	c.RedisAddr = tmp.RedisAddr
	c.RedisPassword = tmp.RedisPassword
	c.RedisEnable = tmp.RedisEnable
	c.HistoryPublic = tmp.HistoryPublic
	c.ExpSecret = tmp.ExpSecret
	c.CollectKey = tmp.CollectKey
	c.CollectSecret = tmp.CollectSecret
	c.DeletePassword = tmp.DeletePassword
	// Secrets/addresses come from the environment (systemd EnvironmentFile), not git.
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		c.RedisAddr = v
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		c.RedisPassword = v
	}
	if v := os.Getenv("EXP_SECRET"); v != "" {
		c.ExpSecret = v
	}
	if v := os.Getenv("COLLECT_SECRET"); v != "" {
		c.CollectSecret = v
	}
	if v := os.Getenv("DELETE_PASSWORD"); v != "" {
		c.DeletePassword = v
	}
	if c.CollectKey == "" {
		c.CollectKey = DefaultCollectKey
	}
	return nil
}

func (c *Config) WriteToFile(file string) error {
	j, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(file, j, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}

func (c *Config) MakeDefault() {
	c.Host = ""
	c.TLSPort = "443"
	c.HTTPPort = "80"
	c.CertFile = "certs/chain.pem"
	c.KeyFile = "certs/key.pem"
	c.HTTPRedirect = "https://tls.peet.ws"
	c.CorsKey = "X-CORS"
	c.CollectKey = DefaultCollectKey
	c.EnableQUIC = true
	c.RedisAddr = "127.0.0.1:6379"
	enable := true
	c.RedisEnable = &enable
	pub := true
	c.HistoryPublic = &pub
}
