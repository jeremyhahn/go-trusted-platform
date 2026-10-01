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

package rpinetboot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/pin/tftp/v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// DHCP ports, as the bootloader uses them.
const (
	dhcpServerPort = 67
	dhcpClientPort = 68
	tftpPort       = 69
)

// Options configures a Probe: which Pi to be, on which interface, with
// which bootloader settings.
type Options struct {
	// Interface is the network interface the DISCOVER is broadcast from,
	// which needs CAP_NET_RAW to bind. Ignored when DialDHCP is set.
	Interface string
	// Identity is the Pi's serial, MAC and revision.
	Identity Identity
	// Model is the board family (LookupModel).
	Model Model
	// Prefix and PrefixString are the bootloader's TFTP_PREFIX and
	// TFTP_PREFIX_STR.
	Prefix       PrefixMode
	PrefixString string
	// Option43 is the PXE_OPTION43 match string (Option43Match when
	// empty).
	Option43 string

	// Timing; zero means the bootloader's default.
	DHCPTimeout        time.Duration
	DHCPRequestTimeout time.Duration
	TFTPFileTimeout    time.Duration
	TFTPRetries        int
	TFTPRetryInterval  time.Duration

	// TFTPPort is the server port to fetch from (69 when zero).
	TFTPPort int

	// Logger receives the exchange as it happens; nil means the default.
	Logger *logging.Logger

	// DialDHCP supplies the DHCP client socket. The default is a UDP
	// socket on port 68 bound to Interface with SO_BROADCAST; a test
	// supplies a loopback pair.
	DialDHCP func(iface string) (net.PacketConn, error)
	// DHCPServerAddr is where DISCOVER and REQUEST are sent; the limited
	// broadcast to port 67 when nil.
	DHCPServerAddr net.Addr
}

func (o *Options) withDefaults() Options {
	out := *o
	if out.Option43 == "" {
		out.Option43 = Option43Match
	}
	if out.DHCPTimeout == 0 {
		out.DHCPTimeout = DHCPTimeout
	}
	if out.DHCPRequestTimeout == 0 {
		out.DHCPRequestTimeout = DHCPRequestTimeout
	}
	if out.TFTPFileTimeout == 0 {
		out.TFTPFileTimeout = TFTPFileTimeout
	}
	if out.TFTPRetries == 0 {
		out.TFTPRetries = TFTPRetries
	}
	if out.TFTPRetryInterval == 0 {
		out.TFTPRetryInterval = TFTPRetryInterval
	}
	if out.TFTPPort == 0 {
		out.TFTPPort = tftpPort
	}
	if out.Logger == nil {
		out.Logger = logging.DefaultLogger()
	}
	if out.DialDHCP == nil {
		out.DialDHCP = dialDHCPClient
	}
	if out.DHCPServerAddr == nil {
		out.DHCPServerAddr = &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpServerPort}
	}
	return out
}

// Report is what the probe saw: the offer it accepted, the lease it took
// (when the offer carried one), the per-device prefix it used and every
// file it fetched.
type Report struct {
	Offer  OfferReport
	Lease  *LeaseReport
	Prefix string
	Files  []FileReport
}

// OfferReport is the DHCP offer the bootloader would have accepted.
type OfferReport struct {
	// Server is the offer's server identifier.
	Server net.IP
	// TFTPServer is where the files were fetched from: siaddr, else
	// option 66, else the server identifier.
	TFTPServer net.IP
	// Proxy is true for a proxy DHCP offer (no address).
	Proxy bool
	// Option43 is the vendor option that matched.
	Option43 []byte
	// BootFile is the offered bootfile, which the bootloader ignores.
	BootFile string
}

// LeaseReport is the address the network's DHCP server gave.
type LeaseReport struct {
	IP     net.IP
	Mask   net.IPMask
	Router net.IP
}

// FileReport is one file of the boot sequence.
type FileReport struct {
	// Name is what the bootloader asked for, before the prefix.
	Name string
	// Path is the request that succeeded (with or without the prefix), or
	// the last one tried.
	Path string
	// Bytes and SHA256 describe what was received.
	Bytes  int64
	SHA256 string
	// Optional files may be absent; Missing says this one was.
	Optional bool
	Missing  bool
}

// Probe boots from the network the way the Raspberry Pi bootloader does,
// as far as the bootloader goes: the DHCP exchange, then every file the
// bootloader and the firmware fetch, in order, with the per-device
// prefix tried before the root. It fails at the first thing a real Pi
// would have failed at, with the report so far in the error.
func Probe(ctx context.Context, opts Options) (*Report, error) {
	o := opts.withDefaults()
	prefix, err := o.Identity.Prefix(o.Prefix, o.PrefixString)
	if err != nil {
		return nil, err
	}
	report := &Report{Prefix: prefix}

	if err := probeDHCP(ctx, &o, report); err != nil {
		return report, err
	}
	if err := probeTFTP(ctx, &o, report); err != nil {
		return report, err
	}
	return report, nil
}

// probeDHCP runs the DHCP exchange: DISCOVER until an offer carries the
// match string, then REQUEST/ACK when the offer carried an address.
func probeDHCP(ctx context.Context, o *Options, report *Report) error {
	conn, err := o.DialDHCP(o.Interface)
	if err != nil {
		return &DHCPError{Stage: "socket", Err: err}
	}
	defer conn.Close()

	discover, err := o.discover()
	if err != nil {
		return &DHCPError{Stage: "discover", Err: err}
	}
	deadline := time.Now().Add(o.DHCPTimeout)
	offer, err := exchange(ctx, conn, o, discover, deadline, func(p *dhcpv4.DHCPv4) bool {
		if p.MessageType() != dhcpv4.MessageTypeOffer {
			return false
		}
		opt43 := p.Options.Get(dhcpv4.OptionVendorSpecificInformation)
		if !Option43Matches(opt43, o.Option43) {
			o.Logger.Info("Offer without the match string ignored", "server", p.ServerIdentifier().String(), "option43", hex.EncodeToString(opt43))
			return false
		}
		return true
	})
	if err != nil {
		return &DHCPError{Stage: "offer", Err: err}
	}
	report.Offer = OfferReport{
		Server:   offer.ServerIdentifier(),
		Proxy:    offer.YourIPAddr.IsUnspecified(),
		Option43: offer.Options.Get(dhcpv4.OptionVendorSpecificInformation),
		BootFile: offer.BootFileName,
	}
	report.Offer.TFTPServer = tftpServerOf(offer)
	if report.Offer.TFTPServer == nil {
		return &DHCPError{Stage: "offer", Err: errNoTFTPServer}
	}
	o.Logger.Info("Offer accepted", "server", report.Offer.Server.String(), "tftp", report.Offer.TFTPServer.String(), "proxy", report.Offer.Proxy)

	if report.Offer.Proxy {
		return nil
	}
	request, err := o.request(offer)
	if err != nil {
		return &DHCPError{Stage: "request", Err: err}
	}
	ack, err := exchange(ctx, conn, o, request, deadline, func(p *dhcpv4.DHCPv4) bool {
		return p.MessageType() == dhcpv4.MessageTypeAck && p.YourIPAddr.Equal(offer.YourIPAddr)
	})
	if err != nil {
		return &DHCPError{Stage: "ack", Err: err}
	}
	report.Lease = &LeaseReport{IP: ack.YourIPAddr, Mask: ack.SubnetMask(), Router: firstIP(ack.Router())}
	o.Logger.Info("Lease acknowledged", "ip", ack.YourIPAddr.String())
	return nil
}

// discover builds the bootloader's DISCOVER.
func (o *Options) discover() (*dhcpv4.DHCPv4, error) {
	return dhcpv4.New(
		dhcpv4.WithHwAddr(o.Identity.MAC),
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithOption(dhcpv4.OptClassIdentifier(VendorClass)),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{byte(ClientArch >> 8), byte(ClientArch)})),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientMachineIdentifier, o.Identity.Option97(o.Model))),
		dhcpv4.WithOption(dhcpv4.OptParameterRequestList(
			dhcpv4.OptionSubnetMask, dhcpv4.OptionRouter, dhcpv4.OptionDomainNameServer,
			dhcpv4.OptionTFTPServerName, dhcpv4.OptionBootfileName,
			dhcpv4.OptionVendorSpecificInformation, dhcpv4.OptionClassIdentifier)),
	)
}

// request builds the REQUEST for an offer's address.
func (o *Options) request(offer *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	req, err := dhcpv4.NewRequestFromOffer(offer)
	if err != nil {
		return nil, err
	}
	req.UpdateOption(dhcpv4.OptClassIdentifier(VendorClass))
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{byte(ClientArch >> 8), byte(ClientArch)}))
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientMachineIdentifier, o.Identity.Option97(o.Model)))
	req.SetBroadcast()
	return req, nil
}

// exchange sends msg and waits for a reply accept approves, re-sending
// every DHCPRequestTimeout until deadline or the context ends.
func exchange(ctx context.Context, conn net.PacketConn, o *Options, msg *dhcpv4.DHCPv4, deadline time.Time, accept func(*dhcpv4.DHCPv4) bool) (*dhcpv4.DHCPv4, error) {
	buf := make([]byte, 1500)
	for attempt := 1; ; attempt++ {
		if time.Now().After(deadline) {
			return nil, &TimeoutError{What: msg.MessageType().String(), After: o.DHCPTimeout}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		o.Logger.Debug("Sending", "type", msg.MessageType().String(), "attempt", attempt, "xid", msg.TransactionID.String())
		if _, err := conn.WriteTo(msg.ToBytes(), o.DHCPServerAddr); err != nil {
			return nil, err
		}
		retryAt := time.Now().Add(o.DHCPRequestTimeout)
		if retryAt.After(deadline) {
			retryAt = deadline
		}
		if d, ok := ctx.Deadline(); ok && d.Before(retryAt) {
			retryAt = d
		}
		for time.Now().Before(retryAt) {
			if err := conn.SetReadDeadline(retryAt); err != nil {
				return nil, err
			}
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) || isTimeout(err) {
					break
				}
				return nil, err
			}
			reply, err := dhcpv4.FromBytes(buf[:n])
			if err != nil || reply.OpCode != dhcpv4.OpcodeBootReply || reply.TransactionID != msg.TransactionID {
				continue
			}
			o.Logger.Debug("Received", "type", reply.MessageType().String(), "from", from.String())
			if accept(reply) {
				return reply, nil
			}
		}
	}
}

// isTimeout reports a read-deadline error from a net.PacketConn.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// tftpServerOf is the server the bootloader fetches from: siaddr, else
// option 66 as an address, else the server identifier.
func tftpServerOf(offer *dhcpv4.DHCPv4) net.IP {
	if !offer.ServerIPAddr.IsUnspecified() {
		return offer.ServerIPAddr
	}
	if name := offer.TFTPServerName(); name != "" {
		if ip := net.ParseIP(name); ip != nil {
			return ip
		}
	}
	if id := offer.ServerIdentifier(); id != nil && !id.IsUnspecified() {
		return id
	}
	return nil
}

func firstIP(ips []net.IP) net.IP {
	if len(ips) == 0 {
		return nil
	}
	return ips[0]
}

// probeTFTP fetches the boot sequence: the model's first-stage files,
// config.txt, then what the firmware reads from it.
func probeTFTP(ctx context.Context, o *Options, report *Report) error {
	client, err := tftp.NewClient(net.JoinHostPort(report.Offer.TFTPServer.String(), strconv.Itoa(o.TFTPPort)))
	if err != nil {
		return &TFTPError{File: "", Err: err}
	}
	client.SetTimeout(o.TFTPRetryInterval)
	client.SetRetries(o.TFTPRetries)

	fetch := func(spec FileSpec) ([]byte, error) {
		fr, data, err := fetchWithPrefix(ctx, o, client, report.Prefix, spec)
		report.Files = append(report.Files, fr)
		return data, err
	}
	for _, name := range o.Model.FirstStage {
		if _, err := fetch(FileSpec{Name: name}); err != nil {
			return err
		}
	}
	configTxt, err := fetch(FileSpec{Name: "config.txt"})
	if err != nil {
		return err
	}
	for _, spec := range o.Model.FirmwareFiles(ParseBootConfig(configTxt)) {
		if _, err := fetch(spec); err != nil {
			return err
		}
	}
	return nil
}

// fetchWithPrefix fetches one file the way the bootloader does: under the
// per-device prefix first, then from the root when the server says the
// prefixed file does not exist. A missing optional file is reported, not
// an error.
func fetchWithPrefix(ctx context.Context, o *Options, client *tftp.Client, prefix string, spec FileSpec) (FileReport, []byte, error) {
	fr := FileReport{Name: spec.Name, Optional: spec.Optional}
	for _, path := range []string{prefix + spec.Name, spec.Name} {
		fr.Path = path
		if err := ctx.Err(); err != nil {
			return fr, nil, &TFTPError{File: path, Err: err}
		}
		data, err := fetchOne(o, client, path)
		if err == nil {
			fr.Bytes = int64(len(data))
			sum := sha256.Sum256(data)
			fr.SHA256 = hex.EncodeToString(sum[:])
			o.Logger.Info("Fetched", "path", path, "bytes", fr.Bytes)
			return fr, data, nil
		}
		if !isTFTPNotFound(err) {
			return fr, nil, &TFTPError{File: path, Err: err}
		}
		o.Logger.Debug("Not found", "path", path)
	}
	if spec.Optional {
		fr.Missing = true
		return fr, nil, nil
	}
	return fr, nil, &TFTPError{File: spec.Name, Err: errFileNotFound}
}

// fetchOne downloads one path within TFTPFileTimeout.
func fetchOne(o *Options, client *tftp.Client, path string) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		wt, err := client.Receive(path, "octet")
		if err != nil {
			done <- result{err: err}
			return
		}
		var sink countingBuffer
		if _, err := wt.WriteTo(&sink); err != nil {
			done <- result{err: err}
			return
		}
		done <- result{data: sink.data}
	}()
	timer := time.NewTimer(o.TFTPFileTimeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.data, r.err
	case <-timer.C:
		return nil, &TimeoutError{What: "tftp " + path, After: o.TFTPFileTimeout}
	}
}

// countingBuffer collects a transfer.
type countingBuffer struct{ data []byte }

func (b *countingBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

// isTFTPNotFound recognises the server's "file not found" (error code 1)
// as the tftp client reports it — as text, which is all it offers.
func isTFTPNotFound(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "code: 1,")
}

var _ io.Writer = (*countingBuffer)(nil)
