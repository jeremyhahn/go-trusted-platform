// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build linux

package ipxe

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	ipHeaderLen    = 20
	udpHeaderLen   = 8
	dhcpServerPort = 67
	dhcpClientPort = 68
)

// ServerRawConn implements a raw socket connection for DHCP on bridged networks.
//
// The socket is an AF_PACKET datagram socket: the kernel strips the
// link-layer header on receive, so every offset here and in the BPF filter
// is relative to the IP header, and it builds the header on send from the
// destination hardware address WriteTo supplies. (As a SOCK_RAW socket the
// frames carried their Ethernet header, which the filter and the parser
// read as the IP header: a client's DISCOVER was rejected by the filter on
// a byte of its own MAC, and the server's own broadcast reply, looped back,
// passed it and crashed the parser.)
type ServerRawConn struct {
	conn     *packet.Conn
	iface    string
	serverIP net.IP
	port     int

	// peers remembers the hardware address each client IP last spoke
	// from, so a unicast reply can be framed without ARP.
	peers sync.Map // string (IPv4) -> net.HardwareAddr
}

// NewServerRawConn creates a new raw socket connection for DHCP server.
func NewServerRawConn(iface string, serverIP net.IP, port int) (*ServerRawConn, error) {
	if iface == "" {
		return nil, ErrInvalidInterface
	}

	if serverIP == nil {
		return nil, ErrNoServerIP
	}

	if port <= 0 || port > 65535 {
		return nil, ErrInvalidPort
	}

	// Get interface by name
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidInterface, Cause: err}
	}

	// Create BPF filter to only receive DHCP packets on port 67
	filter, err := bpf.Assemble([]bpf.Instruction{
		// Load protocol field from IP header (offset 9)
		bpf.LoadAbsolute{Off: 9, Size: 1},
		// Jump if not UDP (17)
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.IPPROTO_UDP, SkipTrue: 6},
		// Load destination port from UDP header (offset 20 + 2)
		bpf.LoadAbsolute{Off: ipHeaderLen + 2, Size: 2},
		// Jump if not port 67
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dhcpServerPort, SkipTrue: 4},
		// Load destination IP (offset 16)
		bpf.LoadAbsolute{Off: 16, Size: 4},
		// Jump if broadcast (0xffffffff)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xffffffff, SkipTrue: 0, SkipFalse: 1},
		// Accept
		bpf.RetConstant{Val: 65535},
		// Check if matches our server IP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip4ToUint32(serverIP), SkipTrue: 0, SkipFalse: 1},
		// Accept packet
		bpf.RetConstant{Val: 65535},
		// Reject packet
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to assemble BPF filter", Err: err}
	}

	// Create raw packet socket
	conn, err := packet.Listen(ifi, packet.Datagram, unix.ETH_P_IP, &packet.Config{
		Filter: filter,
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create raw packet socket", Err: err}
	}

	return &ServerRawConn{
		conn:     conn,
		iface:    iface,
		serverIP: serverIP.To4(),
		port:     port,
	}, nil
}

// ReadFrom implements net.PacketConn. It returns the next UDP datagram
// addressed to the server port and skips anything else the filter let
// through, rather than trusting the lengths a frame claims.
func (c *ServerRawConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, 1500)
	for {
		n, from, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		payload, src, ok := parseUDP4(buf[:n], c.port)
		if !ok {
			continue
		}
		if hw, isPacket := from.(*packet.Addr); isPacket && !src.IP.IsUnspecified() {
			c.peers.Store(src.IP.String(), hw.HardwareAddr)
		}
		return copy(p, payload), src, nil
	}
}

// parseUDP4 extracts the UDP payload and source of an IPv4 packet that
// starts at the IP header, accepting only UDP to port. Every length is
// checked against the bytes actually received.
func parseUDP4(b []byte, port int) (payload []byte, src *net.UDPAddr, ok bool) {
	if len(b) < ipHeaderLen {
		return nil, nil, false
	}
	if b[0]>>4 != 4 || b[9] != unix.IPPROTO_UDP {
		return nil, nil, false
	}
	ihl := int(b[0]&0x0F) * 4
	if ihl < ipHeaderLen || len(b) < ihl+udpHeaderLen {
		return nil, nil, false
	}
	udp := b[ihl : ihl+udpHeaderLen]
	if int(binary.BigEndian.Uint16(udp[2:4])) != port {
		return nil, nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < udpHeaderLen || ihl+udpLen > len(b) {
		return nil, nil, false
	}
	src = &net.UDPAddr{
		IP:   net.IPv4(b[12], b[13], b[14], b[15]),
		Port: int(binary.BigEndian.Uint16(udp[0:2])),
	}
	return b[ihl+udpHeaderLen : ihl+udpLen], src, true
}

// destinationHardwareAddr chooses the frame's destination: the broadcast
// address for a broadcast reply, else the address the client last spoke
// from. A destination this socket has never heard from cannot be framed
// (there is no ARP on a packet socket).
func (c *ServerRawConn) destinationHardwareAddr(dstIP net.IP) (net.HardwareAddr, error) {
	if dstIP.Equal(net.IPv4bcast) {
		return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, nil
	}
	if hw, ok := c.peers.Load(dstIP.String()); ok {
		return hw.(net.HardwareAddr), nil
	}
	return nil, &UnknownPeerError{IP: dstIP}
}

// WriteTo implements net.PacketConn.
func (c *ServerRawConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, &MessageError{Msg: "address must be *net.UDPAddr"}
	}

	dstIP := udpAddr.IP.To4()
	if dstIP == nil {
		return 0, &MessageError{Msg: "destination must be IPv4"}
	}
	dstHW, err := c.destinationHardwareAddr(dstIP)
	if err != nil {
		return 0, err
	}

	// Build IP + UDP packet
	pkt := buildUDP4Packet(
		c.serverIP,
		dstIP,
		uint16(c.port),
		uint16(udpAddr.Port),
		p,
	)

	// Send the datagram; the kernel frames it to dstHW.
	_, err = c.conn.WriteTo(pkt, &packet.Addr{HardwareAddr: dstHW})
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close implements net.PacketConn.
func (c *ServerRawConn) Close() error {
	return c.conn.Close()
}

// LocalAddr implements net.PacketConn.
func (c *ServerRawConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   c.serverIP,
		Port: c.port,
	}
}

// SetDeadline implements net.PacketConn.
func (c *ServerRawConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements net.PacketConn.
func (c *ServerRawConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn.
func (c *ServerRawConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// buildUDP4Packet constructs a complete IP + UDP packet with payload.
func buildUDP4Packet(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	// Calculate lengths
	udpLen := udpHeaderLen + len(payload)
	ipLen := ipHeaderLen + udpLen

	// Build packet buffer
	pkt := make([]byte, ipLen)

	// IP header
	ipHeader := pkt[:ipHeaderLen]
	ipHeader[0] = 0x45                                       // Version 4, header length 20
	ipHeader[1] = 0x00                                       // DSCP/ECN
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(ipLen)) // Total length
	binary.BigEndian.PutUint16(ipHeader[4:6], 0)             // Identification
	binary.BigEndian.PutUint16(ipHeader[6:8], 0)             // Flags/Fragment offset
	ipHeader[8] = 64                                         // TTL
	ipHeader[9] = unix.IPPROTO_UDP                           // Protocol
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)           // Checksum (filled later)
	copy(ipHeader[12:16], srcIP.To4())                       // Source IP
	copy(ipHeader[16:20], dstIP.To4())                       // Destination IP

	// Calculate IP checksum
	ipChecksum := calculateIPChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum)

	// UDP header
	udpHeader := pkt[ipHeaderLen : ipHeaderLen+udpHeaderLen]
	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort)        // Source port
	binary.BigEndian.PutUint16(udpHeader[2:4], dstPort)        // Destination port
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(udpLen)) // Length
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)              // Checksum (optional for IPv4)

	// Copy payload
	copy(pkt[ipHeaderLen+udpHeaderLen:], payload)

	// Calculate UDP checksum (optional but recommended)
	udpChecksum := calculateUDPChecksum(srcIP, dstIP, udpHeader, payload)
	binary.BigEndian.PutUint16(udpHeader[6:8], udpChecksum)

	return pkt
}

// calculateIPChecksum calculates the IP header checksum.
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	// Add carry bits
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Return one's complement
	return ^uint16(sum)
}

// calculateUDPChecksum calculates the UDP checksum including pseudo-header.
func calculateUDPChecksum(srcIP, dstIP net.IP, udpHeader, payload []byte) uint16 {
	var sum uint32

	// Pseudo-header
	srcIP = srcIP.To4()
	dstIP = dstIP.To4()

	// Source IP
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))

	// Destination IP
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))

	// Protocol (UDP = 17)
	sum += uint32(unix.IPPROTO_UDP)

	// UDP length
	udpLen := len(udpHeader) + len(payload)
	sum += uint32(udpLen)

	// UDP header (excluding checksum field)
	sum += uint32(binary.BigEndian.Uint16(udpHeader[0:2])) // Source port
	sum += uint32(binary.BigEndian.Uint16(udpHeader[2:4])) // Destination port
	sum += uint32(binary.BigEndian.Uint16(udpHeader[4:6])) // Length

	// Payload
	for i := 0; i < len(payload); i += 2 {
		if i+1 < len(payload) {
			sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
		} else {
			// Odd length, pad with zero
			sum += uint32(payload[i]) << 8
		}
	}

	// Add carry bits
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// Return one's complement
	checksum := ^uint16(sum)

	// UDP checksum of 0 means no checksum
	if checksum == 0 {
		checksum = 0xffff
	}

	return checksum
}

// ip4ToUint32 converts an IPv4 address to uint32 for BPF filter.
func ip4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}
