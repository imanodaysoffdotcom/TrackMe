package tls

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pagpeter/trackme/pkg/types"
)

// quicTPNames maps known QUIC transport parameter IDs (RFC 9000 18.2, RFC 9221,
// RFC 9287) to readable names.
var quicTPNames = map[uint64]string{
	0x00:   "original_destination_connection_id",
	0x01:   "max_idle_timeout",
	0x02:   "stateless_reset_token",
	0x03:   "max_udp_payload_size",
	0x04:   "initial_max_data",
	0x05:   "initial_max_stream_data_bidi_local",
	0x06:   "initial_max_stream_data_bidi_remote",
	0x07:   "initial_max_stream_data_uni",
	0x08:   "initial_max_streams_bidi",
	0x09:   "initial_max_streams_uni",
	0x0a:   "ack_delay_exponent",
	0x0b:   "max_ack_delay",
	0x0c:   "disable_active_migration",
	0x0d:   "preferred_address",
	0x0e:   "active_connection_id_limit",
	0x0f:   "initial_source_connection_id",
	0x10:   "retry_source_connection_id",
	0x20:   "max_datagram_frame_size",
	0x2ab2: "grease_quic_bit",
}

func quicTPName(id uint64) string {
	if n, ok := quicTPNames[id]; ok {
		return n
	}
	if id >= 0x21 && (id-0x21)%0x1f == 0 { // GREASE reserved values (RFC 9000 18.1)
		return "GREASE"
	}
	return fmt.Sprintf("unknown_0x%x", id)
}

// readQUICVarint decodes one RFC 9000 16 variable-length integer; returns the
// value and the number of bytes consumed (0 on failure).
func readQUICVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	length := 1 << (b[0] >> 6) // 1, 2, 4 or 8
	if len(b) < length {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v, length
}

// ParseQUICTransportParameters decodes the (id, length, value) TLV list from the
// raw quic_transport_parameters extension (hex), in client order.
func ParseQUICTransportParameters(dataHex string) []types.QUICTransportParam {
	raw, err := hex.DecodeString(dataHex)
	if err != nil {
		return nil
	}
	var params []types.QUICTransportParam
	i := 0
	for i < len(raw) {
		id, n := readQUICVarint(raw[i:])
		if n == 0 {
			break
		}
		i += n
		length, n2 := readQUICVarint(raw[i:])
		if n2 == 0 {
			break
		}
		i += n2
		if i+int(length) > len(raw) {
			break
		}
		val := raw[i : i+int(length)]
		i += int(length)
		params = append(params, types.QUICTransportParam{
			ID:    id,
			Name:  quicTPName(id),
			Value: hex.EncodeToString(val),
		})
	}
	return params
}

// quicSPHBISlots is the canonical, fixed parameter order used for the image, so
// the same client maps to the same pixels regardless of the order it sends them.
var quicSPHBISlots = []uint64{
	0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0e, 0x0f, 0x20, 0x2ab2,
}

// randomValuedTP holds params whose VALUE is per-connection random, so we image
// presence only (not the value) - the same reason IP addresses are excluded.
var randomValuedTP = map[uint64]bool{0x00: true, 0x02: true, 0x0f: true, 0x10: true}

// BuildQUICSPHBI renders the QUIC transport parameters as a 12x12 binary image.
// Layout: 15 canonical parameter slots + 1 GREASE/unknown slot, each 9 bits =
// [present:1][value fold:8] = 144 bits. The value fold is the XOR of the value
// bytes (0 for absent or random-valued params). This is a stable per-client
// transport-parameter fingerprint image, not a raw packet-header image.
func BuildQUICSPHBI(params []types.QUICTransportParam) *types.SPHBIDetails {
	if len(params) == 0 {
		return nil
	}
	byID := map[uint64]types.QUICTransportParam{}
	hasGrease := false
	for _, p := range params {
		byID[p.ID] = p
		if _, known := quicTPNames[p.ID]; !known {
			hasGrease = true
		}
	}

	var bits strings.Builder
	bits.Grow(144)
	emit := func(present bool, fold byte) {
		if present {
			bits.WriteByte('1')
		} else {
			bits.WriteByte('0')
		}
		for i := 7; i >= 0; i-- {
			if (fold>>uint(i))&1 == 1 {
				bits.WriteByte('1')
			} else {
				bits.WriteByte('0')
			}
		}
	}
	fold := func(valHex string) byte {
		b, _ := hex.DecodeString(valHex)
		var f byte
		for _, x := range b {
			f ^= x
		}
		return f
	}

	for _, id := range quicSPHBISlots {
		p, ok := byID[id]
		switch {
		case !ok:
			emit(false, 0)
		case randomValuedTP[id]:
			emit(true, 0)
		default:
			emit(true, fold(p.Value))
		}
	}
	emit(hasGrease, 0) // 16th slot: any GREASE/unknown parameter present

	bitStr := bits.String()
	raw := make([]byte, 18)
	for i := 0; i < 144 && i < len(bitStr); i++ {
		if bitStr[i] == '1' {
			raw[i/8] |= 1 << uint(7-i%8)
		}
	}

	fields := make([]types.SPHBIField, 0, len(params))
	for _, p := range params {
		v := p.Value
		if v == "" {
			v = "(flag)"
		}
		fields = append(fields, types.SPHBIField{
			Name:  fmt.Sprintf("0x%x %s", p.ID, p.Name),
			Hex:   v,
			Bytes: len(p.Value) / 2,
		})
	}

	return &types.SPHBIDetails{
		PacketType: "QUIC Initial",
		Kind:       "quic",
		Hex:        hex.EncodeToString(raw),
		Bits:       bitStr,
		Size:       12,
		Fields:     fields,
	}
}
