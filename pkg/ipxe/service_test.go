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

package ipxe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/pin/tftp/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run the whole PXE service (the TFTP and HTTP listeners on
// loopback, and the DHCP server on a loopback socket) in process. They
// replace the test/integration/ipxe service tests (#964 step b).

const (
	// serviceFirmwareSize spans many 512-byte TFTP blocks and ends
	// mid-block, so a transfer that drops, repeats or truncates a block
	// changes the bytes the tests compare.
	serviceFirmwareSize = 256*1024 + 77

	// serviceProxyPath and serviceProxyBody are what the HTTPS origin
	// behind the /proxy/ route serves.
	serviceProxyPath = "/get"
	serviceProxyBody = `{"origin":"ipxe-service-proxy-upstream"}`
)

// serviceFirmwarePaths maps each path the TFTP server requests from its
// firmware upstream (boot.ipxe.org's layout, tftp_server.go) to the TFTP
// name it serves the binary under.
var serviceFirmwarePaths = map[string]string{
	"/x86_64-efi/ipxe.efi":   "ipxe.efi",
	"/i386-efi/ipxe.efi":     "ipxe32.efi",
	"/undionly.kpxe":         "undionly.kpxe",
	"/arm64-efi/snponly.efi": FirmwareSNPOnlyAArch64,
}

// serviceFirmware returns the bytes the firmware upstream serves for the
// TFTP name: a PE "MZ" header and a body unique to the name.
func serviceFirmware(name string) []byte {
	seed := sha256.Sum256([]byte(name))
	data := make([]byte, serviceFirmwareSize)
	copy(data, "MZ")
	for i := 2; i < len(data); i++ {
		data[i] = seed[i%len(seed)] ^ byte(i)
	}
	return data
}

// runningService is a started PXE service and the addresses its tests
// reach it on.
type runningService struct {
	baseURL  string
	tftpAddr string
	proxyURL string
}

// startService starts the PXE service with the firmware upstream and the
// HTTPS proxy origin as httptest servers, and stops all of it at cleanup.
func startService(t *testing.T) runningService {
	t.Helper()

	firmwareUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := serviceFirmwarePaths[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(serviceFirmware(name)))
	}))
	t.Cleanup(firmwareUpstream.Close)

	proxyUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != serviceProxyPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		http.ServeContent(w, r, "get.json", time.Time{}, strings.NewReader(serviceProxyBody))
	}))
	t.Cleanup(proxyUpstream.Close)

	proxyCAs := x509.NewCertPool()
	proxyCAs.AddCert(proxyUpstream.Certificate())

	httpPort := freeTCPPort(t)
	tftpPort := freeUDPPort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", httpPort)

	server, err := NewServer(&ServerConfig{
		BindHost:         "127.0.0.1",
		HTTPPort:         httpPort,
		TFTPPort:         tftpPort,
		ExternalURL:      baseURL,
		FirmwareDir:      t.TempDir(),
		FirmwareUpstream: firmwareUpstream.URL,
		ProxyCACertPool:  proxyCAs,
		BootEntries: []BootEntry{
			{
				Name:        "alpine-test",
				Description: "Alpine Linux Test Entry",
				ISOURL:      "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-standard-3.20.0-x86_64.iso",
			},
			{
				Name:        "test-kernel",
				Description: "Test Kernel Boot",
				Kernel:      "http://example.com/vmlinuz",
				Initrd:      "http://example.com/initrd.img",
				Args:        "console=ttyS0",
			},
		},
	}, logging.DefaultLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, server.Stop())
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(ipxeDeadline):
			t.Errorf("PXE server did not stop within %s", ipxeDeadline)
		}
	})

	select {
	case <-server.Ready():
	case err := <-done:
		t.Fatalf("PXE server stopped before it was ready: %v", err)
	case <-time.After(ipxeDeadline):
		t.Fatalf("PXE server did not become ready within %s", ipxeDeadline)
	}

	return runningService{
		baseURL:  baseURL,
		tftpAddr: fmt.Sprintf("127.0.0.1:%d", tftpPort),
		proxyURL: fmt.Sprintf("%s/proxy/https/%s%s", baseURL, proxyUpstream.Listener.Addr(), serviceProxyPath),
	}
}

// tftpReceive downloads name from the service in octet mode and returns
// the bytes and the size the server announced (RFC 2349 tsize, -1 when it
// sent none).
func tftpReceive(addr, name string) ([]byte, int64, error) {
	client, err := tftp.NewClient(addr)
	if err != nil {
		return nil, 0, err
	}
	client.SetTimeout(2 * time.Second)
	client.SetRetries(1)
	client.RequestTSize(true)

	wt, err := client.Receive(name, "octet")
	if err != nil {
		return nil, 0, err
	}

	size := int64(-1)
	if transfer, ok := wt.(tftp.IncomingTransfer); ok {
		if announced, sent := transfer.Size(); sent {
			size = announced
		}
	}

	var buf bytes.Buffer
	if _, err := wt.WriteTo(&buf); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), size, nil
}

// serviceGet issues a GET and returns the response and its body.
func serviceGet(t *testing.T, url string) (*http.Response, string) {
	t.Helper()

	resp, err := http.Get(url)
	require.NoError(t, err, "GET %s", url)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read the body of GET %s", url)
	return resp, string(body)
}

func TestService_TFTPServesUpstreamFirmware(t *testing.T) {
	svc := startService(t)

	for _, name := range []string{"ipxe.efi", "ipxe32.efi", "undionly.kpxe"} {
		t.Run(name, func(t *testing.T) {
			want := serviceFirmware(name)

			first, size, err := tftpReceive(svc.tftpAddr, name)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(want, first),
				"%s should be the bytes the firmware upstream served", name)
			assert.Equal(t, int64(len(want)), size,
				"the announced tsize should be the firmware size")

			second, _, err := tftpReceive(svc.tftpAddr, name)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(first, second),
				"a repeated download should return the same bytes")
		})
	}

	t.Run("ConcurrentDownloads", func(t *testing.T) {
		const clients = 3
		want := serviceFirmware("ipxe.efi")

		var wg sync.WaitGroup
		errs := make([]error, clients)
		data := make([][]byte, clients)
		for i := range clients {
			wg.Go(func() {
				data[i], _, errs[i] = tftpReceive(svc.tftpAddr, "ipxe.efi")
			})
		}
		wg.Wait()

		for i := range clients {
			require.NoError(t, errs[i], "client %d", i)
			assert.True(t, bytes.Equal(want, data[i]),
				"client %d should get the firmware byte for byte", i)
		}
	})
}

func TestService_TFTPRefusesWhatItDoesNotServe(t *testing.T) {
	svc := startService(t)

	refused := map[string]string{
		"NonExistentFile":      "nonexistent-file.bin",
		"PathTraversalBlocked": "../../../etc/passwd",
		"EmptyFilename":        "",
		// The longest name one 516-byte RRQ with the tsize option carries;
		// pin/tftp drops a longer datagram unread.
		"LongFilename": strings.Repeat("a", 480) + ".efi",
	}
	for name, file := range refused {
		t.Run(name, func(t *testing.T) {
			_, _, err := tftpReceive(svc.tftpAddr, file)
			assert.Error(t, err, "the TFTP server should refuse %q", file)
		})
	}
}

func TestService_HTTPMenuOffersEveryEntryAndTheUtilities(t *testing.T) {
	svc := startService(t)

	t.Run("BootScriptChainsToTheMenu", func(t *testing.T) {
		resp, body := serviceGet(t, svc.baseURL+"/boot.ipxe")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, strings.HasPrefix(body, "#!ipxe"), "the script should start with #!ipxe")
		assert.Contains(t, body, "chain")
		assert.Contains(t, body, "menu.ipxe")
		assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
	})

	t.Run("MenuListsEntriesAndUtilities", func(t *testing.T) {
		resp, body := serviceGet(t, svc.baseURL+"/menu.ipxe")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, strings.HasPrefix(body, "#!ipxe"), "the menu should start with #!ipxe")
		for _, want := range []string{"menu", "item", "choose", ":shell", ":reboot", "alpine-test", "test-kernel"} {
			assert.Contains(t, body, want)
		}
	})

	for _, entry := range []string{"alpine-test", "test-kernel"} {
		t.Run("Entry_"+entry, func(t *testing.T) {
			resp, body := serviceGet(t, svc.baseURL+"/boot/"+entry+".ipxe")
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.True(t, strings.HasPrefix(body, "#!ipxe"), "the entry should start with #!ipxe")
			assert.True(t, strings.Contains(body, "kernel") || strings.Contains(body, "chain"),
				"the entry should have a kernel or chain command")
			assert.True(t, strings.Contains(body, "boot") || strings.Contains(body, "chain"),
				"the entry should have a boot or chain command")
		})
	}

	t.Run("Health", func(t *testing.T) {
		resp, body := serviceGet(t, svc.baseURL+"/health")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

		var health struct {
			Status string `json:"status"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &health))
		assert.Equal(t, "healthy", health.Status)
	})
}

func TestService_HTTPProxyRelaysUpstreamHeaders(t *testing.T) {
	svc := startService(t)

	resp, body := serviceGet(t, svc.proxyURL)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, serviceProxyBody, body, "the proxy should relay the upstream body")
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"),
		"the proxy should relay the upstream headers")
}

func TestService_HTTPRoutesRefuseWhatTheyDoNotServe(t *testing.T) {
	svc := startService(t)

	tests := []struct {
		path string
		want []int
	}{
		{"/boot/nonexistent-entry.ipxe", []int{http.StatusNotFound}},
		{"/proxy/http/example.com/", []int{http.StatusBadRequest}},
		{"/proxy/", []int{http.StatusBadRequest}},
		{"/static/../../../etc/passwd", []int{http.StatusBadRequest, http.StatusNotFound}},
		{"/static/", []int{http.StatusForbidden, http.StatusNotFound}},
		{"/files/../../../etc/passwd", []int{http.StatusBadRequest, http.StatusNotFound}},
		{"/files/", []int{http.StatusBadRequest, http.StatusNotFound, http.StatusForbidden}},
		{"/nonexistent", []int{http.StatusNotFound, http.StatusBadRequest}},
		{"/boot/", []int{http.StatusNotFound, http.StatusBadRequest}},
		{"/../../../", []int{http.StatusNotFound, http.StatusBadRequest}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			resp, _ := serviceGet(t, svc.baseURL+tt.path)
			assert.Contains(t, tt.want, resp.StatusCode, "GET %s", tt.path)
		})
	}

	t.Run("POST /boot.ipxe", func(t *testing.T) {
		resp, err := http.Post(svc.baseURL+"/boot.ipxe", "text/plain", strings.NewReader(""))
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Contains(t, []int{http.StatusMethodNotAllowed, http.StatusOK}, resp.StatusCode,
			"POST should be rejected or handled")
	})
}

func TestService_HTTPConcurrentBootScriptRequests(t *testing.T) {
	svc := startService(t)

	const clients = 10
	var wg sync.WaitGroup
	codes := make([]int, clients)
	errs := make([]error, clients)
	for i := range clients {
		wg.Go(func() {
			resp, err := http.Get(svc.baseURL + "/boot.ipxe")
			if err != nil {
				errs[i] = err
				return
			}
			codes[i] = resp.StatusCode
			errs[i] = resp.Body.Close()
		})
	}
	wg.Wait()

	for i := range clients {
		require.NoError(t, errs[i], "client %d", i)
		assert.Equal(t, http.StatusOK, codes[i], "client %d", i)
	}
}

// loopbackReplyConn is the DHCP server's socket for these tests: a real
// UDP socket on 127.0.0.1 whose replies go to the test client. The server
// addresses replies to 255.255.255.255:68 or giaddr:67, both privileged;
// sendDHCPReply's choice between them is covered by its own unit test.
type loopbackReplyConn struct {
	net.PacketConn
	client net.Addr
}

func (c *loopbackReplyConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, c.client)
}

// loopbackConnFactory hands the DHCP server its loopbackReplyConn.
type loopbackConnFactory struct {
	conn net.PacketConn
}

func (f *loopbackConnFactory) CreateConn(string, net.IP, bool) (net.PacketConn, error) {
	return f.conn, nil
}

// dhcpExchange is a DHCP server on a loopback socket and the client socket
// its replies go to.
type dhcpExchange struct {
	server *DHCPServer
	client net.PacketConn
	addr   net.Addr
}

// startDHCPExchange starts a DHCP server for 192.168.1.100-200 on a
// loopback socket and stops it at cleanup.
func startDHCPExchange(t *testing.T) dhcpExchange {
	t.Helper()

	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	server, err := NewDHCPServer(&DHCPConfig{
		ServerIP:       net.ParseIP("192.168.1.1"),
		SubnetMask:     net.ParseIP("255.255.255.0"),
		RangeStart:     net.ParseIP("192.168.1.100"),
		RangeEnd:       net.ParseIP("192.168.1.200"),
		LeaseTime:      time.Hour,
		TFTPServerIP:   net.ParseIP("192.168.1.1"),
		BootFilename:   "ipxe.efi",
		IPXEScript:     "http://192.168.1.1:8080/boot.ipxe",
		TFTPServerName: "pxeserver",
	}, logging.DefaultLogger(), WithPacketConnFactory(&loopbackConnFactory{
		conn: &loopbackReplyConn{PacketConn: serverConn, client: client.LocalAddr()},
	}))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	bound := newBoundSignal()
	done := make(chan error, 1)
	go func() { done <- server.Start(ctx, bound) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(ipxeDeadline):
			t.Errorf("DHCP server did not stop within %s", ipxeDeadline)
		}
	})
	awaitBound(t, bound, "DHCP listener")

	return dhcpExchange{server: server, client: client, addr: serverConn.LocalAddr()}
}

// pxePacket builds a DHCP message of the given type from a PXE (or, with
// userClass, an iPXE) client of EFI x64 architecture.
func pxePacket(t *testing.T, msgType dhcpv4.MessageType, mac net.HardwareAddr, userClass string, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()

	mods = append([]dhcpv4.Modifier{
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(msgType),
		dhcpv4.WithOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00007:UNDI:003001")),
		dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, []byte{0x00, 0x07})),
	}, mods...)
	if userClass != "" {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptUserClass(userClass)))
	}
	pkt, err := dhcpv4.New(mods...)
	require.NoError(t, err)
	return pkt
}

// send writes pkt to the DHCP server.
func (x dhcpExchange) send(t *testing.T, pkt *dhcpv4.DHCPv4) {
	t.Helper()
	_, err := x.client.WriteTo(pkt.ToBytes(), x.addr)
	require.NoError(t, err)
}

// receive reads the next reply the DHCP server sent.
func (x dhcpExchange) receive(t *testing.T) *dhcpv4.DHCPv4 {
	t.Helper()

	require.NoError(t, x.client.SetReadDeadline(time.Now().Add(ipxeDeadline)))
	buf := make([]byte, 1500)
	n, _, err := x.client.ReadFrom(buf)
	require.NoError(t, err, "the DHCP server should reply")
	reply, err := dhcpv4.FromBytes(buf[:n])
	require.NoError(t, err)
	return reply
}

func TestDHCPServer_DiscoverRequestExchange(t *testing.T) {
	x := startDHCPExchange(t)
	rangeStart := net.ParseIP("192.168.1.100").To4()
	rangeEnd := net.ParseIP("192.168.1.200").To4()

	t.Run("NonPXEAndZeroMACAreIgnored", func(t *testing.T) {
		plain, err := dhcpv4.New(
			dhcpv4.WithHwAddr(net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}),
			dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		)
		require.NoError(t, err)
		zeroMAC := pxePacket(t, dhcpv4.MessageTypeDiscover, net.HardwareAddr{0, 0, 0, 0, 0, 0}, "")
		pxe := pxePacket(t, dhcpv4.MessageTypeDiscover, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}, "")

		// The server answers only the last one, so the first reply is its.
		x.send(t, plain)
		x.send(t, zeroMAC)
		x.send(t, pxe)
		reply := x.receive(t)
		assert.Equal(t, pxe.TransactionID, reply.TransactionID,
			"the only reply should answer the PXE client")
	})

	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x10}
	discover := pxePacket(t, dhcpv4.MessageTypeDiscover, mac, "")
	x.send(t, discover)
	offer := x.receive(t)

	t.Run("PXEOffer", func(t *testing.T) {
		assert.Equal(t, dhcpv4.MessageTypeOffer, offer.MessageType())
		assert.Equal(t, discover.TransactionID, offer.TransactionID)
		ip := offer.YourIPAddr.To4()
		require.NotNil(t, ip, "the offer should carry an IPv4 address")
		assert.True(t, compareIPs(ip, rangeStart) >= 0 && compareIPs(ip, rangeEnd) <= 0,
			"offered %s should be in the range", ip)
		assert.Equal(t, "192.168.1.1", offer.ServerIPAddr.String(),
			"the TFTP server IP should be set")
		assert.Contains(t, offer.BootFileName, "ipxe.efi",
			"an EFI x64 PXE client should get ipxe.efi")
	})

	t.Run("SameMACGetsSameIP", func(t *testing.T) {
		x.send(t, pxePacket(t, dhcpv4.MessageTypeDiscover, mac, ""))
		again := x.receive(t)
		assert.Equal(t, offer.YourIPAddr.String(), again.YourIPAddr.String())
	})

	t.Run("RequestAndRenewalAreAcked", func(t *testing.T) {
		for _, step := range []string{"request", "renewal"} {
			x.send(t, pxePacket(t, dhcpv4.MessageTypeRequest, mac, "",
				dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
				dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.1.1")))))
			ack := x.receive(t)
			assert.Equal(t, dhcpv4.MessageTypeAck, ack.MessageType(), step)
			assert.Equal(t, offer.YourIPAddr.String(), ack.YourIPAddr.String(), step)
			assert.NotEmpty(t, ack.BootFileName, step)
		}
	})

	t.Run("IPXEClientGetsTheScriptURL", func(t *testing.T) {
		x.send(t, pxePacket(t, dhcpv4.MessageTypeDiscover, net.HardwareAddr{0x02, 0, 0, 0, 0, 0x20}, "iPXE"))
		reply := x.receive(t)
		require.NotNil(t, reply.YourIPAddr.To4())
		assert.Contains(t, reply.BootFileName, "http://")
		assert.Contains(t, reply.BootFileName, "/boot.ipxe")
	})
}

func TestDHCPServer_ConcurrentDiscoversGetUniqueIPs(t *testing.T) {
	x := startDHCPExchange(t)

	const clients = 5
	sent := make(map[dhcpv4.TransactionID]string, clients)
	var wg sync.WaitGroup
	for i := range clients {
		pkt := pxePacket(t, dhcpv4.MessageTypeDiscover, net.HardwareAddr{0x02, 0, 0, 0, 1, byte(i)}, "")
		sent[pkt.TransactionID] = pkt.ClientHWAddr.String()
		wg.Go(func() {
			_, err := x.client.WriteTo(pkt.ToBytes(), x.addr)
			assert.NoError(t, err)
		})
	}
	wg.Wait()

	offered := make(map[string]string, clients)
	for range clients {
		reply := x.receive(t)
		mac, ok := sent[reply.TransactionID]
		require.True(t, ok, "reply %s answers no DISCOVER sent", reply.TransactionID)
		assert.Equal(t, mac, reply.ClientHWAddr.String())
		ip := reply.YourIPAddr.String()
		assert.NotContains(t, offered, ip, "%s offered twice", ip)
		offered[ip] = mac
	}
	assert.Len(t, offered, clients, "every client should get its own IP")
}
