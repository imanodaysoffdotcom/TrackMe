package tcp

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pagpeter/trackme/pkg/server"
	"github.com/pagpeter/trackme/pkg/types"
)

// TCP packet capture variables
var (
	snapshot_len int32         = 1024
	promiscuous  bool          = false
	timeout      time.Duration = 1 * time.Millisecond
	handle       *pcap.Handle
)

func parseIP(packet gopacket.Packet) *types.IPDetails {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer == nil {
		if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer == nil {
			return nil
		} else {
			// IPv6
			ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			return &types.IPDetails{
				DstIp:     ip.DstIP.String(),
				SrcIP:     ip.SrcIP.String(),
				TTL:       int(ip.HopLimit),
				IPVersion: 6,
			}
		}
	} else {
		// IPv4
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		return &types.IPDetails{
			DstIp:     ip.DstIP.String(),
			SrcIP:     ip.SrcIP.String(),
			ID:        int(ip.Id),
			TOS:       int(ip.TOS),
			TTL:       int(ip.TTL),
			IPVersion: 4,
		}
	}
}

func SniffTCP(device string, tlsPort int, srv *server.Server) {
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			// QOSF (QUIC-only): a QUIC long-header datagram (HTTP/3 over UDP) carries
			// the OS-bearing kernel fields (initial TTL/hop-limit, ECN, IPv4 DF, IPv6
			// flow label) + the cleartext QUIC version/connection-ID lengths that the
			// UDP socket API cannot see. This branch is purely additive: it only runs
			// for non-TCP packets and never touches the TCP/JA4/SPHBI path below.
			captureQOSFKernel(packet, tlsPort, srv)
			continue
		}
		tcp := tcpLayer.(*layers.TCP)
		if int(tcp.DstPort) != tlsPort {
			continue
		}

		// Single Packet Header Binary Image: built from the client's SYN packet,
		// which carries the cleanest per-client TCP/IP stack signature (IPv4 only).
		if tcp.SYN && !tcp.ACK {
			var img *types.SPHBIDetails
			var srcIP string
			if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
				ip4 := ip4Layer.(*layers.IPv4)
				img = buildSPHBI(ip4, tcp)
				srcIP = ip4.SrcIP.String()
			} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
				ip6 := ip6Layer.(*layers.IPv6)
				img = buildSPHBIv6(ip6, tcp)
				srcIP = ip6.SrcIP.String()
			}
			if img != nil && srcIP != "" {
				srv.GetSPHBI().Store(net.JoinHostPort(srcIP, strconv.Itoa(int(tcp.SrcPort))), img)
				// Also key by IP alone, so a returning user still sees their image on a
				// connection that has no TCP SYN of its own (e.g. HTTP/3 over QUIC).
				srv.GetSPHBI().Store(srcIP, img)
			}
			// JA4T (FoxIO TCP client fingerprint) is a TCP-layer fingerprint computed
			// straight from the SYN, independent of IP version. Store it on the same
			// keys as the SPHBI so the router can correlate it the same way.
			if srcIP != "" {
				ja4t := JA4TFromSYN(tcp)
				srv.GetJA4T().Store(net.JoinHostPort(srcIP, strconv.Itoa(int(tcp.SrcPort))), ja4t)
				srv.GetJA4T().Store(srcIP, ja4t)
			}
			continue
		}

		// Existing TCP/IP fingerprint (from the client's ACK packets).
		ip := parseIP(packet)
		if !tcp.ACK || ip == nil || ip.IPVersion == 0 {
			continue
		}
		pack := types.TCPIPDetails{
			CapLen:  packet.Metadata().CaptureLength,
			DstPort: int(tcp.DstPort),
			SrcPort: int(tcp.SrcPort),
			IP:      *ip,
			TCP: types.TCPDetails{
				Ack:          int(tcp.Ack),
				Checksum:     int(tcp.Checksum),
				Options:      parseTCPOptions(tcp.Options),
				OptionsOrder: parseTCPOptionsOrder(tcp.Options),
				Seq:          int(tcp.Seq),
				Window:       int(tcp.Window),
			},
		}
		src := net.JoinHostPort(pack.IP.SrcIP, strconv.Itoa(pack.SrcPort))
		srv.GetTCPFingerprints().Store(src, pack)
	}
}

// captureQOSFKernel records the QOSF kernel/long-header observation for a client
// QUIC datagram (UDP -> tlsPort). It reads the outer IP header (TTL/hop-limit,
// ECN, IPv4 DF, IPv6 flow label) and the cleartext QUIC long header (version +
// connection-ID lengths, RFC 8999), then stores it keyed by IP:port and by IP
// alone — exactly like the SPHBI/JA4T maps — so the router correlates it with
// the QUIC connection the same way. It ignores non-QUIC and short-header UDP.
func captureQOSFKernel(packet gopacket.Packet, tlsPort int, srv *server.Server) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp := udpLayer.(*layers.UDP)
	if int(udp.DstPort) != tlsPort {
		return
	}
	ver, dcidLen, scidLen, ok := parseQUICLongHeader(udp.Payload)
	if !ok {
		return
	}
	kern := &types.QOSFKernel{QUICVersion: ver, DCIDLen: dcidLen, SCIDLen: scidLen, UDPPayloadLen: len(udp.Payload)}
	var srcIP string
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		kern.IPVersion = 4
		kern.TTL = int(ip4.TTL)
		kern.ECN = int(ip4.TOS & 0x03)
		kern.DF = ip4.Flags&layers.IPv4DontFragment != 0
		srcIP = ip4.SrcIP.String()
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		kern.IPVersion = 6
		kern.TTL = int(ip6.HopLimit)
		kern.ECN = int(ip6.TrafficClass & 0x03)
		kern.FlowLabel = ip6.FlowLabel
		srcIP = ip6.SrcIP.String()
	} else {
		return
	}
	srv.GetQOSFKernel().Store(net.JoinHostPort(srcIP, strconv.Itoa(int(udp.SrcPort))), kern)
	srv.GetQOSFKernel().Store(srcIP, kern)
}

// parseQUICLongHeader decodes the version and Destination/Source Connection ID
// lengths from a QUIC long-header packet (RFC 8999 5.1, version-independent).
// ok is false for a short header (1-RTT, no version/CIDs) or a truncated header.
func parseQUICLongHeader(p []byte) (version uint32, dcidLen, scidLen int, ok bool) {
	if len(p) < 6 {
		return 0, 0, 0, false
	}
	if p[0]&0x80 == 0 {
		return 0, 0, 0, false // short header: no version or connection IDs
	}
	version = uint32(p[1])<<24 | uint32(p[2])<<16 | uint32(p[3])<<8 | uint32(p[4])
	dl := int(p[5])
	if len(p) < 6+dl+1 { // room for the DCID and the SCID-length byte
		return 0, 0, 0, false
	}
	sl := int(p[6+dl])
	if len(p) < 6+dl+1+sl {
		return 0, 0, 0, false
	}
	return version, dl, sl, true
}

func hx1(b byte) string    { return fmt.Sprintf("%02x", b) }
func hx2(a, b byte) string { return fmt.Sprintf("%02x%02x", a, b) }

// renderSPHBI turns the selected raw header bytes into a square binary image
// (1 bit = 1 pixel, MSB first, row-major) plus the per-field breakdown.
func renderSPHBI(raw []byte, kind string, fields []types.SPHBIField) *types.SPHBIDetails {
	var bits strings.Builder
	bits.Grow(len(raw) * 8)
	for _, b := range raw {
		for i := 7; i >= 0; i-- {
			if (b>>uint(i))&1 == 1 {
				bits.WriteByte('1')
			} else {
				bits.WriteByte('0')
			}
		}
	}
	return &types.SPHBIDetails{
		PacketType: "SYN",
		Kind:       kind,
		Hex:        hex.EncodeToString(raw),
		Bits:       bits.String(),
		Size:       12,
		Fields:     fields,
	}
}

// mssBytes returns the 2-byte TCP MSS option value (0,0 if absent).
func mssBytes(tcp *layers.TCP) (byte, byte) {
	for _, opt := range tcp.Options {
		if opt.OptionType == layers.TCPOptionKindMSS && len(opt.OptionData) >= 2 {
			return opt.OptionData[0], opt.OptionData[1]
		}
	}
	return 0, 0
}

// buildSPHBI extracts the 18 TCP/IP header bytes selected by El-Sherif et al.
// (2025), Table 2, and arranges their 144 bits as a 12x12 binary image.
// Source/dest IP, both checksums and the TCP sequence/ack numbers are excluded.
func buildSPHBI(ip4 *layers.IPv4, tcp *layers.TCP) *types.SPHBIDetails {
	ipc := ip4.Contents
	tcpc := tcp.Contents
	if len(ipc) < 10 || len(tcpc) < 16 {
		return nil
	}
	raw := make([]byte, 0, 18)
	raw = append(raw, ipc[0:10]...)   // IP: hdr-len, diffserv, total-len(2), id(2), flags+frag(2), ttl, proto
	raw = append(raw, tcpc[0:4]...)   // TCP: source port(2), dest port(2)
	raw = append(raw, tcpc[12:16]...) // TCP: data-offset+flags(2), window(2)
	fields := []types.SPHBIField{
		{Name: "IP: Header length", Hex: hx1(ipc[0]), Bytes: 1},
		{Name: "IP: Differentiated services", Hex: hx1(ipc[1]), Bytes: 1},
		{Name: "IP: Total length", Hex: hx2(ipc[2], ipc[3]), Bytes: 2},
		{Name: "IP: Identification", Hex: hx2(ipc[4], ipc[5]), Bytes: 2},
		{Name: "IP: Flags + fragment offset", Hex: hx2(ipc[6], ipc[7]), Bytes: 2},
		{Name: "IP: Time to live", Hex: hx1(ipc[8]), Bytes: 1},
		{Name: "IP: Protocol", Hex: hx1(ipc[9]), Bytes: 1},
		{Name: "TCP: Source port", Hex: hx2(tcpc[0], tcpc[1]), Bytes: 2},
		{Name: "TCP: Destination port", Hex: hx2(tcpc[2], tcpc[3]), Bytes: 2},
		{Name: "TCP: Data offset + flags", Hex: hx2(tcpc[12], tcpc[13]), Bytes: 2},
		{Name: "TCP: Window size", Hex: hx2(tcpc[14], tcpc[15]), Bytes: 2},
	}
	return renderSPHBI(raw, "ipv4", fields)
}

// buildSPHBIv6 is the IPv6 SPHBI. The IPv6 base header has only 8 non-address
// bytes (vs IPv4's 10), so 8 IPv6 + 8 TCP = 128 bits; we add the 2-byte TCP MSS
// option to reach 18 bytes / 144 bits / 12x12 (parity with the IPv4 image).
// Bytes 1-3 carry the 20-bit IPv6 flow label (new per-stack signal).
func buildSPHBIv6(ip6 *layers.IPv6, tcp *layers.TCP) *types.SPHBIDetails {
	ipc := ip6.Contents
	tcpc := tcp.Contents
	if len(ipc) < 8 || len(tcpc) < 16 {
		return nil
	}
	mssHi, mssLo := mssBytes(tcp)
	raw := make([]byte, 0, 18)
	raw = append(raw, ipc[0:8]...)    // IPv6: ver+TC(1), TC+flow(1), flow(2), payload-len(2), next-hdr(1), hop-limit(1)
	raw = append(raw, tcpc[0:4]...)   // TCP: source port(2), dest port(2)
	raw = append(raw, tcpc[12:16]...) // TCP: data-offset+flags(2), window(2)
	raw = append(raw, mssHi, mssLo)   // TCP MSS option value (2) -> 18 bytes / 144 bits
	fields := []types.SPHBIField{
		{Name: "IPv6: Version + traffic class", Hex: hx1(ipc[0]), Bytes: 1},
		{Name: "IPv6: Traffic class + flow label", Hex: hx1(ipc[1]), Bytes: 1},
		{Name: "IPv6: Flow label", Hex: hx2(ipc[2], ipc[3]), Bytes: 2},
		{Name: "IPv6: Payload length", Hex: hx2(ipc[4], ipc[5]), Bytes: 2},
		{Name: "IPv6: Next header", Hex: hx1(ipc[6]), Bytes: 1},
		{Name: "IPv6: Hop limit", Hex: hx1(ipc[7]), Bytes: 1},
		{Name: "TCP: Source port", Hex: hx2(tcpc[0], tcpc[1]), Bytes: 2},
		{Name: "TCP: Destination port", Hex: hx2(tcpc[2], tcpc[3]), Bytes: 2},
		{Name: "TCP: Data offset + flags", Hex: hx2(tcpc[12], tcpc[13]), Bytes: 2},
		{Name: "TCP: Window size", Hex: hx2(tcpc[14], tcpc[15]), Bytes: 2},
		{Name: "TCP: MSS option", Hex: hx2(mssHi, mssLo), Bytes: 2},
	}
	return renderSPHBI(raw, "ipv6", fields)
}

func parseTCPOptions(_ []layers.TCPOption) string {
	return ""
}

func parseTCPOptionsOrder(_ []layers.TCPOption) string {
	return ""
}
