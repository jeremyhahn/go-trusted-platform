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
	seen   chan dhcpv4.MessageType
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
		reply.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("127.0.0.1").To4()))
		if !s.proxy {
			reply.YourIPAddr = s.yiaddr
			reply.UpdateOption(dhcpv4.OptSubnetMask(net.CIDRMask(24, 32)))
			reply.UpdateOption(dhcpv4.OptRouter(net.ParseIP("10.99.99.1").To4()))
		}
		if s.option43 != nil {
			reply.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, s.option43))
		}
		reply.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient"))
		_, _ = s.conn.WriteTo(reply.ToBytes(), from)
	}
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
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(conn) }()
	t.Cleanup(srv.Shutdown)
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
		TFTPFileTimeout:    5 * time.Second,
		TFTPRetries:        1,
		TFTPRetryInterval:  time.Second,
		DHCPServerAddr:     server.addr(),
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

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
