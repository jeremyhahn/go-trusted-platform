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
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/pin/tftp/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDHCPServer answers on a loopback UDP socket the way the platform's
// boot server (or a proxy, or a stranger) would.
type fakeDHCPServer struct {
	conn     net.PacketConn
	option43 []byte
	proxy    bool
	siaddr   net.IP
	yiaddr   net.IP
	// silent servers never answer; strangers answer without option 43.
	silent bool
	// noServerID leaves the server identifier out of every reply.
	noServerID bool
	// noise precedes each reply with a datagram that is not DHCP and a
	// reply to another transaction.
	noise bool
	seen  chan dhcpv4.MessageType
}

// newFakeDHCPServer starts a server after applying configure, so the serving
// goroutine never races a test that sets the server's behaviour.
func newFakeDHCPServer(t *testing.T, configure ...func(*fakeDHCPServer)) *fakeDHCPServer {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	s := &fakeDHCPServer{conn: conn, option43: Option43(Option43Match), siaddr: net.ParseIP("127.0.0.1").To4(), yiaddr: net.ParseIP("10.99.99.100").To4(), seen: make(chan dhcpv4.MessageType, 16)}
	for _, c := range configure {
		c(s)
	}
	go s.serve()
	return s
}

func (s *fakeDHCPServer) addr() net.Addr { return s.conn.LocalAddr() }

func (s *fakeDHCPServer) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue
		}
		s.seen <- req.MessageType()
		if s.silent {
			continue
		}
		reply, err := dhcpv4.NewReplyFromRequest(req)
		if err != nil {
			continue
		}
		switch req.MessageType() {
		case dhcpv4.MessageTypeDiscover:
			reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
		case dhcpv4.MessageTypeRequest:
			if s.proxy {
				continue
			}
			reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
		default:
			continue
		}
		reply.ServerIPAddr = s.siaddr
		if !s.noServerID {
			reply.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("127.0.0.1").To4()))
		}
		if !s.proxy {
			reply.YourIPAddr = s.yiaddr
			reply.UpdateOption(dhcpv4.OptSubnetMask(net.CIDRMask(24, 32)))
			reply.UpdateOption(dhcpv4.OptRouter(net.ParseIP("10.99.99.1").To4()))
		}
		if s.option43 != nil {
			reply.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, s.option43))
		}
		reply.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))
		if s.noise {
			_, _ = s.conn.WriteTo([]byte("not dhcp"), from)
			stranger := *reply
			stranger.TransactionID = dhcpv4.TransactionID{0xde, 0xad, 0xbe, 0xef}
			stranger.YourIPAddr = net.ParseIP("10.99.99.200").To4()
			_, _ = s.conn.WriteTo(stranger.ToBytes(), from)
		}
		_, _ = s.conn.WriteTo(reply.ToBytes(), from)
	}
}

// plainPacketConn hides the *net.UDPConn from the TFTP server. Given a
// UDPConn, pin/tftp reads each request's control message and calls
// net.InterfaceByIndex, a netlink dump of every link that waits on the
// kernel's RTNL lock; on a CI host busy creating and removing containers
// that wait outlasts the client's retry budget (#1174). Without it the
// server answers from the address the kernel routes to the client.
type plainPacketConn struct {
	net.PacketConn
}

// tftpTree serves dir on a loopback TFTP server and returns its port.
func tftpTree(t *testing.T, dir string) int {
	t.Helper()
	srv := tftp.NewServer(func(filename string, rf io.ReaderFrom) error {
		f, err := os.Open(filepath.Join(dir, filepath.FromSlash(filename)))
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = rf.ReadFrom(f)
		return err
	}, nil)
	// The socket is bound before Serve starts, so a request sent before
	// Serve reads it waits in the socket buffer: the server is ready now.
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(plainPacketConn{conn}) }()
	t.Cleanup(func() {
		srv.Shutdown()
		require.NoError(t, <-served)
	})
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// stageTree writes a minimal Pi 4 boot tree: start4.elf in the device
// directory only, everything else at the root, no cmdline.txt.
func stageTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"9ffefdef/start4.elf":        "ELF from the device directory",
		"start4.elf":                 "ELF from the root",
		"config.txt":                 "arm_64bit=1\ndtoverlay=disable-bt\ndtoverlay=tpm-soft-spi\nkernel=kernel8.img\n",
		"fixup4.dat":                 "fixup",
		"bcm2711-rpi-4-b.dtb":        "dtb",
		"overlays/disable-bt.dtbo":   "bt",
		"overlays/tpm-soft-spi.dtbo": "tpm",
		"kernel8.img":                "U-Boot",
	}
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	return dir
}

func loopbackOptions(t *testing.T, server *fakeDHCPServer, tftpPort int) Options {
	t.Helper()
	model, err := LookupModel("rpi4")
	require.NoError(t, err)
	return Options{
		Identity:           pi4(),
		Model:              model,
		TFTPPort:           tftpPort,
		DHCPTimeout:        3 * time.Second,
		DHCPRequestTimeout: 300 * time.Millisecond,
		// The bootloader's TFTP budget, not a tighter one: these bound a
		// failure, never a pass, so a late reply on a loaded runner is
		// retransmitted instead of failing the file (#1174). A test that
		// wants a TFTP failure sets its own timeout.
		TFTPFileTimeout:   TFTPFileTimeout,
		TFTPRetries:       TFTPRetries,
		TFTPRetryInterval: TFTPRetryInterval,
		DHCPServerAddr:    server.addr(),
		DialDHCP: func(string) (net.PacketConn, error) {
			return net.ListenPacket("udp4", "127.0.0.1:0")
		},
	}
}

func TestProbe_FullDHCPServer(t *testing.T) {
	server := newFakeDHCPServer(t)
	tree := stageTree(t)
	opts := loopbackOptions(t, server, tftpTree(t, tree))

	report, err := Probe(context.Background(), opts)
	require.NoError(t, err)

	assert.False(t, report.Offer.Proxy)
	assert.Equal(t, "127.0.0.1", report.Offer.TFTPServer.String())
	assert.Equal(t, Option43(Option43Match), report.Offer.Option43)
	require.NotNil(t, report.Lease, "the offer carried an address, so the bootloader took the lease")
	assert.Equal(t, "10.99.99.100", report.Lease.IP.String())
	assert.Equal(t, "10.99.99.1", report.Lease.Router.String())
	assert.Equal(t, "9ffefdef/", report.Prefix)

	names := make([]string, 0, len(report.Files))
	paths := make([]string, 0, len(report.Files))
	for _, f := range report.Files {
		names = append(names, f.Name)
		paths = append(paths, f.Path)
	}
	assert.Equal(t, []string{"start4.elf", "config.txt", "fixup4.dat", "bcm2711-rpi-4-b.dtb", "overlays/disable-bt.dtbo", "overlays/tpm-soft-spi.dtbo", "cmdline.txt", "kernel8.img"}, names, "the bootloader's order")
	assert.Equal(t, "9ffefdef/start4.elf", paths[0], "the device directory is tried first")
	assert.Equal(t, "config.txt", paths[1], "and the root when the device directory lacks the file")
	sum := sha256.Sum256([]byte("ELF from the device directory"))
	assert.Equal(t, hex.EncodeToString(sum[:]), report.Files[0].SHA256)
	assert.Equal(t, int64(len("ELF from the device directory")), report.Files[0].Bytes)
	cmdline := report.Files[6]
	assert.True(t, cmdline.Optional)
	assert.True(t, cmdline.Missing, "cmdline.txt may be absent")
	assert.Equal(t, "U-Boot", string(mustRead(t, filepath.Join(tree, "kernel8.img"))))
	assert.Equal(t, int64(6), report.Files[7].Bytes)

	// The exchange was DISCOVER then REQUEST.
	assert.Equal(t, dhcpv4.MessageTypeDiscover, <-server.seen)
	assert.Equal(t, dhcpv4.MessageTypeRequest, <-server.seen)
}

func TestProbe_ProxyDHCP(t *testing.T) {
	server := newFakeDHCPServer(t, func(s *fakeDHCPServer) { s.proxy = true })
	opts := loopbackOptions(t, server, tftpTree(t, stageTree(t)))

	report, err := Probe(context.Background(), opts)
	require.NoError(t, err)
	assert.True(t, report.Offer.Proxy)
	assert.Nil(t, report.Lease, "a proxy offer carries no address; the network's server would")
	assert.Equal(t, "127.0.0.1", report.Offer.TFTPServer.String(), "siaddr from the proxy offer")
	assert.Len(t, report.Files, 8)
	assert.Equal(t, dhcpv4.MessageTypeDiscover, <-server.seen)
	select {
	case mt := <-server.seen:
		t.Fatalf("a proxy offer must not be followed by a %s", mt)
	default:
	}
}

func TestProbe_IgnoresOffersWithoutTheMatchString(t *testing.T) {
	server := newFakeDHCPServer(t, func(s *fakeDHCPServer) { s.option43 = []byte{0x06, 0x01, 0x08, 0xff} }) // an x86 PXE reply
	opts := loopbackOptions(t, server, 0)
	opts.DHCPTimeout = 700 * time.Millisecond

	report, err := Probe(context.Background(), opts)
	var dhcpErr *DHCPError
	require.ErrorAs(t, err, &dhcpErr)
	assert.Equal(t, "offer", dhcpErr.Stage)
	var timeout *TimeoutError
	assert.ErrorAs(t, err, &timeout, "the bootloader keeps DISCOVERing until DHCP_TIMEOUT")
	assert.NotNil(t, report, "the report so far comes back with the error")
	assert.GreaterOrEqual(t, len(server.seen), 2, "DISCOVER was retried every DHCP_REQ_TIMEOUT")
}

func TestProbe_SilentNetworkTimesOut(t *testing.T) {
	server := newFakeDHCPServer(t, func(s *fakeDHCPServer) { s.silent = true })
	opts := loopbackOptions(t, server, 0)
	opts.DHCPTimeout = 500 * time.Millisecond

	_, err := Probe(context.Background(), opts)
	var timeout *TimeoutError
	require.ErrorAs(t, err, &timeout)
	assert.Equal(t, "DISCOVER", timeout.What)
}

func TestProbe_ContextCancellation(t *testing.T) {
	server := newFakeDHCPServer(t, func(s *fakeDHCPServer) { s.silent = true })
	opts := loopbackOptions(t, server, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Probe(ctx, opts)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestProbe_MissingRequiredFile(t *testing.T) {
	server := newFakeDHCPServer(t)
	tree := stageTree(t)
	require.NoError(t, os.Remove(filepath.Join(tree, "fixup4.dat")))
	opts := loopbackOptions(t, server, tftpTree(t, tree))

	report, err := Probe(context.Background(), opts)
	var tftpErr *TFTPError
	require.ErrorAs(t, err, &tftpErr)
	assert.Equal(t, "fixup4.dat", tftpErr.File)
	assert.True(t, errors.Is(err, errFileNotFound))
	require.Len(t, report.Files, 3, "start4.elf and config.txt succeeded; fixup4.dat is the failure")
	assert.Equal(t, "fixup4.dat", report.Files[2].Path, "the root was the last place tried")
}

func TestProbe_Pi5FetchesNoFirstStage(t *testing.T) {
	server := newFakeDHCPServer(t)
	tree := stageTree(t)
	require.NoError(t, os.WriteFile(filepath.Join(tree, "bcm2712-rpi-5-b.dtb"), []byte("dtb5"), 0o644))
	opts := loopbackOptions(t, server, tftpTree(t, tree))
	opts.Model, _ = LookupModel("rpi5")

	report, err := Probe(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "config.txt", report.Files[0].Name, "the Pi 5 EEPROM reads config.txt itself")
	for _, f := range report.Files {
		assert.NotEqual(t, "fixup4.dat", f.Name)
		assert.NotEqual(t, "start4.elf", f.Name)
	}
}

func TestProbe_TFTPServerFromOption66WhenNoSiaddr(t *testing.T) {
	server := newFakeDHCPServer(t, func(s *fakeDHCPServer) { s.siaddr = net.IPv4zero.To4() })
	opts := loopbackOptions(t, server, tftpTree(t, stageTree(t)))
	// The fake sets no option 66, so the server identifier is what remains.
	report, err := Probe(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", report.Offer.TFTPServer.String())
}

func TestProbe_InvalidPrefixIsRefusedBeforeTheNetwork(t *testing.T) {
	opts := loopbackOptions(t, newFakeDHCPServer(t), 0)
	opts.Prefix = PrefixString
	_, err := Probe(context.Background(), opts)
	var invalid *InvalidIdentityError
	require.ErrorAs(t, err, &invalid)
}

func TestIsTFTPNotFound(t *testing.T) {
	assert.True(t, isTFTPNotFound(errors.New("code: 1, message: File not found")))
	assert.False(t, isTFTPNotFound(errors.New("code: 2, message: Access violation")))
	assert.False(t, isTFTPNotFound(nil))
}

// A busy segment carries datagrams that are not DHCP and replies to other
// clients; the bootloader takes only a reply to its own transaction.
func TestProbe_IgnoresRepliesToOtherTransactions(t *testing.T) {
	server := newFakeDHCPServer(t, func(s *fakeDHCPServer) { s.noise = true })
	opts := loopbackOptions(t, server, tftpTree(t, stageTree(t)))

	report, err := Probe(context.Background(), opts)
	require.NoError(t, err)
	require.NotNil(t, report.Lease)
	assert.Equal(t, "10.99.99.100", report.Lease.IP.String(), "not the address offered to another transaction")
}

func TestProbe_OfferNamingNoTFTPServer(t *testing.T) {
	server := newFakeDHCPServer(t, func(s *fakeDHCPServer) {
		s.siaddr = net.IPv4zero.To4()
		s.noServerID = true
	})
	opts := loopbackOptions(t, server, 0)

	report, err := Probe(context.Background(), opts)
	var dhcpErr *DHCPError
	require.ErrorAs(t, err, &dhcpErr)
	assert.Equal(t, "offer", dhcpErr.Stage)
	assert.ErrorIs(t, err, errNoTFTPServer)
	assert.Nil(t, report.Offer.TFTPServer)
}

// Without DialDHCP the probe opens the bootloader's own socket on the named
// interface; an interface that cannot be bound fails at the socket stage and
// names the interface.
func TestProbe_UnbindableInterface(t *testing.T) {
	model, err := LookupModel("rpi4")
	require.NoError(t, err)

	_, err = Probe(context.Background(), Options{Interface: "no-such-if0", Identity: pi4(), Model: model})
	var dhcpErr *DHCPError
	require.ErrorAs(t, err, &dhcpErr)
	assert.Equal(t, "socket", dhcpErr.Stage)
	var sockErr *SocketError
	require.ErrorAs(t, err, &sockErr)
	assert.Equal(t, "SO_BINDTODEVICE(no-such-if0)", sockErr.Option)
	assert.Contains(t, err.Error(), "no-such-if0")
}

// A TFTP server that stops answering is a failure at the file the
// bootloader asked for; it is not "not found", so the root is not tried.
func TestProbe_StalledTFTPServer(t *testing.T) {
	stalled, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { stalled.Close() })
	opts := loopbackOptions(t, newFakeDHCPServer(t), stalled.LocalAddr().(*net.UDPAddr).Port)
	opts.TFTPFileTimeout = 200 * time.Millisecond

	report, err := Probe(context.Background(), opts)
	var tftpErr *TFTPError
	require.ErrorAs(t, err, &tftpErr)
	assert.Equal(t, "9ffefdef/start4.elf", tftpErr.File)
	var timeout *TimeoutError
	require.ErrorAs(t, err, &timeout)
	assert.Equal(t, "tftp 9ffefdef/start4.elf", timeout.What)
	require.Len(t, report.Files, 1)
	assert.Equal(t, "9ffefdef/start4.elf", report.Files[0].Path)
}

func TestOptions_DefaultsAreTheBootloaders(t *testing.T) {
	o := (&Options{}).withDefaults()

	assert.Equal(t, Option43Match, o.Option43)
	assert.Equal(t, DHCPTimeout, o.DHCPTimeout)
	assert.Equal(t, DHCPRequestTimeout, o.DHCPRequestTimeout)
	assert.Equal(t, TFTPFileTimeout, o.TFTPFileTimeout)
	assert.Equal(t, TFTPRetries, o.TFTPRetries)
	assert.Equal(t, TFTPRetryInterval, o.TFTPRetryInterval)
	assert.Equal(t, tftpPort, o.TFTPPort)
	assert.NotNil(t, o.Logger)
	assert.NotNil(t, o.DialDHCP)
	assert.Equal(t, "255.255.255.255:67", o.DHCPServerAddr.String(), "the limited broadcast to the server port")

	set := Options{Option43: "custom", TFTPPort: 6969, DHCPTimeout: time.Second}
	o = set.withDefaults()
	assert.Equal(t, "custom", o.Option43, "a set field is kept")
	assert.Equal(t, 6969, o.TFTPPort)
	assert.Equal(t, time.Second, o.DHCPTimeout)
}

func TestTFTPServerOf(t *testing.T) {
	offer := func(siaddr net.IP, opts ...dhcpv4.Option) *dhcpv4.DHCPv4 {
		t.Helper()
		p, err := dhcpv4.New()
		require.NoError(t, err)
		p.ServerIPAddr = siaddr
		for _, o := range opts {
			p.UpdateOption(o)
		}
		return p
	}
	zero := net.IPv4zero.To4()
	serverID := dhcpv4.OptServerIdentifier(net.ParseIP("10.0.0.1").To4())

	cases := []struct {
		name  string
		offer *dhcpv4.DHCPv4
		want  string
	}{
		{"siaddr first", offer(net.ParseIP("10.0.0.9").To4(), dhcpv4.OptTFTPServerName("10.0.0.5"), serverID), "10.0.0.9"},
		{"then option 66 as an address", offer(zero, dhcpv4.OptTFTPServerName("10.0.0.5"), serverID), "10.0.0.5"},
		{"option 66 as a name is not resolved", offer(zero, dhcpv4.OptTFTPServerName("tftp.example"), serverID), "10.0.0.1"},
		{"then the server identifier", offer(zero, serverID), "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tftpServerOf(tc.offer).String())
		})
	}
	assert.Nil(t, tftpServerOf(offer(zero)), "an offer naming no server")
}

func TestFirstIP(t *testing.T) {
	assert.Nil(t, firstIP(nil), "an ACK without a router")
	assert.Equal(t, "10.0.0.1", firstIP([]net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}).String())
}

// A read deadline surfaces as a net.Error timeout that need not wrap
// os.ErrDeadlineExceeded; both end the wait, other errors do not.
func TestIsTimeout(t *testing.T) {
	assert.True(t, isTimeout(&net.OpError{Op: "read", Err: timeoutError{}}))
	assert.False(t, isTimeout(&net.OpError{Op: "read", Err: errors.New("connection refused")}))
	assert.False(t, isTimeout(errors.New("closed")))
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
