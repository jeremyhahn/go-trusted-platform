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

package arp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// ARP-over-Ethernet wire constants (RFC 826).
const (
	// hardwareTypeEthernet is the ARP htype for 10Mb Ethernet.
	hardwareTypeEthernet uint16 = 1

	// protocolTypeIPv4 is the ARP ptype for IPv4.
	protocolTypeIPv4 uint16 = 0x0800

	// etherTypeARP is the Ethernet II EtherType carrying ARP.
	etherTypeARP uint16 = 0x0806

	// hardwareAddrLen is the length of an Ethernet MAC address.
	hardwareAddrLen = 6

	// protocolAddrLen is the length of an IPv4 address.
	protocolAddrLen = 4

	// OperationRequest is the ARP request opcode.
	OperationRequest uint16 = 1

	// OperationReply is the ARP reply opcode.
	OperationReply uint16 = 2

	// payloadLen is the size of an ARP payload for IPv4 over Ethernet.
	payloadLen = 28

	// etherHeaderLen is the size of an Ethernet II header.
	etherHeaderLen = 14

	// frameLen is the size of a complete ARP probe frame.
	frameLen = etherHeaderLen + payloadLen
)

// broadcastHardwareAddr is the Ethernet broadcast destination an ARP probe
// is sent to.
var broadcastHardwareAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// RFC 5227 duplicate-address detection timing. The RFC randomises the
// inter-probe delay between PROBE_MIN and PROBE_MAX so a room full of hosts
// booting together does not synchronise its probe bursts. platformd probes a
// handful of statically configured bridge addresses once per boot, not a
// fleet of DHCP clients, so the interval is fixed at PROBE_MIN: the timing is
// deterministic, which makes the guard testable, and the storm the
// randomisation defends against cannot arise here.
const (
	// DefaultProbeCount is RFC 5227 PROBE_NUM.
	DefaultProbeCount = 3

	// DefaultProbeInterval is RFC 5227 PROBE_MIN: the window the detector
	// listens for a defence after each probe.
	DefaultProbeInterval = 1 * time.Second
)

// Packet is a decoded ARP payload for IPv4 over Ethernet.
type Packet struct {
	// Operation is the ARP opcode (OperationRequest or OperationReply).
	Operation uint16

	// SenderHardwareAddr is the sender's MAC address.
	SenderHardwareAddr net.HardwareAddr

	// SenderProtocolAddr is the sender's IPv4 address.
	SenderProtocolAddr net.IP

	// TargetHardwareAddr is the target's MAC address.
	TargetHardwareAddr net.HardwareAddr

	// TargetProtocolAddr is the target's IPv4 address.
	TargetProtocolAddr net.IP
}

// MarshalFrame encodes the packet as a complete Ethernet II frame addressed
// to dst.
func (p *Packet) MarshalFrame(src, dst net.HardwareAddr) ([]byte, error) {
	if len(src) != hardwareAddrLen || len(dst) != hardwareAddrLen {
		return nil, ErrInvalidMAC
	}
	sha := p.SenderHardwareAddr
	if sha == nil {
		sha = make(net.HardwareAddr, hardwareAddrLen)
	}
	tha := p.TargetHardwareAddr
	if tha == nil {
		tha = make(net.HardwareAddr, hardwareAddrLen)
	}
	if len(sha) != hardwareAddrLen || len(tha) != hardwareAddrLen {
		return nil, ErrInvalidMAC
	}
	spa := ipv4Bytes(p.SenderProtocolAddr)
	tpa := ipv4Bytes(p.TargetProtocolAddr)
	if spa == nil || tpa == nil {
		return nil, ErrNotIPv4
	}

	frame := make([]byte, frameLen)
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP)

	payload := frame[etherHeaderLen:]
	binary.BigEndian.PutUint16(payload[0:2], hardwareTypeEthernet)
	binary.BigEndian.PutUint16(payload[2:4], protocolTypeIPv4)
	payload[4] = hardwareAddrLen
	payload[5] = protocolAddrLen
	binary.BigEndian.PutUint16(payload[6:8], p.Operation)
	copy(payload[8:14], sha)
	copy(payload[14:18], spa)
	copy(payload[18:24], tha)
	copy(payload[24:28], tpa)

	return frame, nil
}

// UnmarshalFrame decodes an Ethernet II frame carrying an ARP payload for
// IPv4 over Ethernet. Frames that are not ARP, or that carry a hardware or
// protocol type this detector does not speak, are rejected with a typed
// error rather than silently misread.
func UnmarshalFrame(frame []byte) (*Packet, error) {
	if len(frame) < frameLen {
		return nil, ErrShortFrame
	}
	if binary.BigEndian.Uint16(frame[12:14]) != etherTypeARP {
		return nil, ErrNotARP
	}

	payload := frame[etherHeaderLen:]
	if binary.BigEndian.Uint16(payload[0:2]) != hardwareTypeEthernet {
		return nil, ErrUnsupportedHardwareType
	}
	if binary.BigEndian.Uint16(payload[2:4]) != protocolTypeIPv4 {
		return nil, ErrUnsupportedProtocolType
	}
	if payload[4] != hardwareAddrLen || payload[5] != protocolAddrLen {
		return nil, ErrUnsupportedAddressLength
	}

	return &Packet{
		Operation:          binary.BigEndian.Uint16(payload[6:8]),
		SenderHardwareAddr: net.HardwareAddr(append([]byte(nil), payload[8:14]...)),
		SenderProtocolAddr: net.IP(append([]byte(nil), payload[14:18]...)),
		TargetHardwareAddr: net.HardwareAddr(append([]byte(nil), payload[18:24]...)),
		TargetProtocolAddr: net.IP(append([]byte(nil), payload[24:28]...)),
	}, nil
}

// ipv4Bytes returns the 4-byte form of ip, or nil when ip is not IPv4. A nil
// IP is treated as the unspecified address 0.0.0.0, which is what an RFC 5227
// probe carries as its sender protocol address.
func ipv4Bytes(ip net.IP) []byte {
	if ip == nil {
		return make([]byte, protocolAddrLen)
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	return v4
}

// PacketConn is the subset of a raw packet socket the probe session uses. It
// is an interface so the session logic is exercised in memory: the Linux
// implementation supplies a *packet.Conn, tests supply a fake.
type PacketConn interface {
	// ReadFrom reads one link-layer frame into b.
	ReadFrom(b []byte) (int, net.Addr, error)

	// WriteTo writes one link-layer frame to addr.
	WriteTo(b []byte, addr net.Addr) (int, error)

	// SetReadDeadline bounds a subsequent ReadFrom.
	SetReadDeadline(t time.Time) error

	// Close releases the socket.
	Close() error
}

// ProbeSession is one bound duplicate-address probing session on a single
// interface.
type ProbeSession interface {
	// LocalHardwareAddr returns the MAC address of the bound interface, so
	// the detector can tell a foreign defence from an echo of its own probe.
	LocalHardwareAddr() net.HardwareAddr

	// SendProbe broadcasts one ARP probe for target.
	SendProbe(target net.IP) error

	// Receive returns the next ARP packet seen on the interface, or
	// ErrProbeTimeout when the deadline passes with nothing to report.
	Receive(deadline time.Time) (*Packet, error)

	// Close releases the session.
	Close() error
}

// ProbeTransport opens probe sessions. Production wiring uses the raw
// AF_PACKET transport; tests substitute a fake so no test ever touches a
// real network.
type ProbeTransport interface {
	// Open binds a probe session to the named interface.
	Open(iface string) (ProbeSession, error)
}

// connSession is the PacketConn-backed ProbeSession shared by every
// transport. Only the socket construction is platform-specific.
type connSession struct {
	conn  PacketConn
	local net.HardwareAddr
	addr  net.Addr
}

// NewProbeSession builds a probe session over an already-opened packet
// socket bound to an interface whose MAC is local. addr is the link-layer
// destination writes are addressed to; a nil addr writes to the raw socket's
// default destination.
func NewProbeSession(conn PacketConn, local net.HardwareAddr, addr net.Addr) (ProbeSession, error) {
	if conn == nil {
		return nil, ErrNilPacketConn
	}
	if len(local) != hardwareAddrLen {
		return nil, ErrInvalidMAC
	}
	return &connSession{conn: conn, local: local, addr: addr}, nil
}

// LocalHardwareAddr returns the MAC address of the bound interface.
func (s *connSession) LocalHardwareAddr() net.HardwareAddr { return s.local }

// SendProbe broadcasts an RFC 5227 ARP probe: an ARP request whose sender
// protocol address is 0.0.0.0, so no receiver caches the probe itself as a
// mapping for the address being tested.
func (s *connSession) SendProbe(target net.IP) error {
	probe := &Packet{
		Operation:          OperationRequest,
		SenderHardwareAddr: s.local,
		SenderProtocolAddr: net.IPv4zero,
		TargetHardwareAddr: net.HardwareAddr(make([]byte, hardwareAddrLen)),
		TargetProtocolAddr: target,
	}
	frame, err := probe.MarshalFrame(s.local, broadcastHardwareAddr)
	if err != nil {
		return err
	}
	if _, err := s.conn.WriteTo(frame, s.addr); err != nil {
		return &SentinelCauseError{Sentinel: ErrProbeSend, Cause: err}
	}
	return nil
}

// Receive returns the next well-formed ARP packet, discarding frames this
// detector does not speak, until the deadline passes.
func (s *connSession) Receive(deadline time.Time) (*Packet, error) {
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrProbeReceive, Cause: err}
	}
	buf := make([]byte, frameLen*2)
	for {
		n, _, err := s.conn.ReadFrom(buf)
		if err != nil {
			if isTimeout(err) {
				return nil, ErrProbeTimeout
			}
			return nil, &SentinelCauseError{Sentinel: ErrProbeReceive, Cause: err}
		}
		packet, decodeErr := UnmarshalFrame(buf[:n])
		if decodeErr != nil {
			// Not an ARP frame this detector speaks. Keep listening
			// until the caller's deadline rather than reporting a
			// clean segment on the first stray frame.
			continue
		}
		return packet, nil
	}
}

// Close releases the underlying socket.
func (s *connSession) Close() error { return s.conn.Close() }

// isTimeout reports whether err is a read deadline expiry.
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// DuplicateAddressDetector probes a segment for an address before the
// platform assigns it, in the style of RFC 5227.
type DuplicateAddressDetector struct {
	transport ProbeTransport
	probes    int
	interval  time.Duration
	// shared maps an address this node deliberately shares with a peer —
	// a VRRP virtual address (pkg/sdn/fhrp) — to the group's virtual MAC.
	// A defence of that address from that MAC is the redundancy group
	// answering, not a conflict; any other MAC still is one.
	shared map[string]net.HardwareAddr
}

// DetectorOption configures a DuplicateAddressDetector.
type DetectorOption func(*DuplicateAddressDetector)

// WithProbeCount sets how many probes are sent before the address is
// declared free. Values below one are ignored.
func WithProbeCount(count int) DetectorOption {
	return func(d *DuplicateAddressDetector) {
		if count > 0 {
			d.probes = count
		}
	}
}

// WithProbeInterval sets how long the detector listens for a defence after
// each probe. Values at or below zero are ignored.
func WithProbeInterval(interval time.Duration) DetectorOption {
	return func(d *DuplicateAddressDetector) {
		if interval > 0 {
			d.interval = interval
		}
	}
}

// WithSharedAddress declares that ip is a first-hop redundancy address the
// node shares on purpose (RFC 5798 virtual router, epic #553 ruling R7) and
// that mac is the group's virtual MAC. A defence from that MAC is accepted;
// a defence from any other MAC is still a conflict, so a misconfigured
// second speaker or a router still holding the address is caught.
func WithSharedAddress(ip net.IP, mac net.HardwareAddr) DetectorOption {
	return func(d *DuplicateAddressDetector) {
		if ip == nil || len(mac) == 0 {
			return
		}
		if d.shared == nil {
			d.shared = make(map[string]net.HardwareAddr)
		}
		d.shared[ip.String()] = mac
	}
}

// NewDuplicateAddressDetector builds a detector over transport.
func NewDuplicateAddressDetector(transport ProbeTransport, opts ...DetectorOption) *DuplicateAddressDetector {
	d := &DuplicateAddressDetector{
		transport: transport,
		probes:    DefaultProbeCount,
		interval:  DefaultProbeInterval,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Window returns the worst-case duration a Check occupies: the whole probe
// budget elapses only when nothing answers.
func (d *DuplicateAddressDetector) Window() time.Duration {
	return time.Duration(d.probes) * d.interval
}

// Check probes iface for ip and reports whether another station already
// answers for it.
//
// It returns nil when the address is free. A *ConflictError — carrying both
// the local and the responding MAC — means another station defended the
// address and the caller must not assign it. Every other error means the
// probe could not be carried out (no such interface, no raw-socket
// privilege, unsupported platform); those say nothing about the address, and
// the caller decides what an unusable probe implies.
func (d *DuplicateAddressDetector) Check(ctx context.Context, iface string, ip net.IP) error {
	if d.transport == nil {
		return ErrNoProbeTransport
	}
	if iface == "" {
		return ErrInvalidInterface
	}
	if ip == nil || ipv4Bytes(ip) == nil || ip.IsUnspecified() {
		return ErrNotIPv4
	}

	session, err := d.transport.Open(iface)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrInterfaceUnavailable, Cause: err}
	}
	defer func() { _ = session.Close() }()

	local := session.LocalHardwareAddr()

	for probe := 0; probe < d.probes; probe++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err := session.SendProbe(ip); err != nil {
			return err
		}
		deadline := time.Now().Add(d.interval)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := d.listen(ctx, session, iface, ip, local, deadline); err != nil {
			return err
		}
	}
	return nil
}

// listen drains ARP traffic until the deadline, returning a *ConflictError
// as soon as a foreign station answers for ip.
func (d *DuplicateAddressDetector) listen(
	ctx context.Context,
	session ProbeSession,
	iface string,
	ip net.IP,
	local net.HardwareAddr,
	deadline time.Time,
) error {
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		packet, err := session.Receive(deadline)
		if err != nil {
			if errors.Is(err, ErrProbeTimeout) {
				return nil
			}
			return err
		}
		if !defends(packet, ip, local) {
			continue
		}
		if d.isSharedResponder(ip, packet.SenderHardwareAddr) {
			continue
		}
		return &ConflictError{
			Interface:             iface,
			Address:               ip,
			LocalHardwareAddr:     local,
			ResponderHardwareAddr: packet.SenderHardwareAddr,
		}
	}
}

// isSharedResponder reports whether a defence of ip from mac is the
// redundancy group this node belongs to.
func (d *DuplicateAddressDetector) isSharedResponder(ip net.IP, mac net.HardwareAddr) bool {
	if d.shared == nil {
		return false
	}
	want, ok := d.shared[ip.String()]
	return ok && bytes.Equal(want, mac)
}

// defends reports whether packet is another station claiming ip.
//
// RFC 5227 §2.1.1 counts two answers as a conflict: an ARP reply whose
// sender protocol address is the probed address, and an ARP request from a
// host probing the same address. Both are recognised here. A packet whose
// sender MAC is our own is our own probe looped back on the socket, not a
// defence.
func defends(packet *Packet, ip net.IP, local net.HardwareAddr) bool {
	if packet == nil {
		return false
	}
	if !packet.SenderProtocolAddr.Equal(ip) {
		return false
	}
	if len(packet.SenderHardwareAddr) == 0 {
		return false
	}
	if bytes.Equal(packet.SenderHardwareAddr, local) {
		return false
	}
	return packet.Operation == OperationReply || packet.Operation == OperationRequest
}
