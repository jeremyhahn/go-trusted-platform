package dhcp

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingConn is the server's socket as the handler sees it: it keeps
// every reply written to it and nothing else.
type recordingConn struct {
	net.PacketConn
	sent []*dhcpv4.DHCPv4
}

func (c *recordingConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	reply, err := dhcpv4.FromBytes(b)
	if err != nil {
		return 0, err
	}
	c.sent = append(c.sent, reply)
	return len(b), nil
}

var replyTestPeer = &net.UDPAddr{IP: net.IPv4bcast, Port: 68}

// newReplyTestHandler wires the IPAM plugin into the server's packet
// handler the way startInterfaceServer does, minus the socket.
func newReplyTestHandler(t *testing.T) (*CoreDHCPServer, server4.Handler) {
	t.Helper()
	ctx := context.Background()
	allocator := backends.NewMemoryBackend()
	t.Cleanup(func() { require.NoError(t, allocator.Close()) })
	createTestPool(ctx, t, allocator, "test-pool")

	srv, err := NewCoreDHCPServer(testServerConfig(), allocator)
	require.NoError(t, err)
	plugin, err := NewIPAMPlugin(allocator, "test-pool", testServerConfig().Interfaces[0].Options,
		WithLeaseStore(srv.leases))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, plugin.Close()) })

	handler := srv.createHandlerFunc(plugin)
	return srv, handler
}

// exchange hands req to the handler and returns what it wrote back.
func exchange(handle server4.Handler, req *dhcpv4.DHCPv4) *recordingConn {
	conn := &recordingConn{}
	handle(conn, replyTestPeer, req)
	return conn
}

func newReplyTestRequest(t *testing.T, msgType dhcpv4.MessageType, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	mac, err := net.ParseMAC("00:11:22:33:44:55")
	require.NoError(t, err)
	req, err := dhcpv4.New(append([]dhcpv4.Modifier{
		dhcpv4.WithHwAddr(mac),
		dhcpv4.WithMessageType(msgType),
	}, mods...)...)
	require.NoError(t, err)
	return req
}

// The IPAM plugin ends the handler chain (stop=true) with every reply it
// builds; the server used to send a reply only when stop was false, so no
// OFFER, ACK or NAK ever left it.
func TestCoreDHCPServer_HandlerSendsPluginReply(t *testing.T) {
	srv, handle := newReplyTestHandler(t)

	offer := exchange(handle, newReplyTestRequest(t, dhcpv4.MessageTypeDiscover))
	require.Len(t, offer.sent, 1, "DISCOVER must be answered")
	assert.Equal(t, dhcpv4.MessageTypeOffer, offer.sent[0].MessageType())
	offered, ok := netip.AddrFromSlice(offer.sent[0].YourIPAddr.To4())
	require.True(t, ok)
	assert.True(t, netip.MustParsePrefix("192.168.1.0/24").Contains(offered))

	ack := exchange(handle, newReplyTestRequest(t, dhcpv4.MessageTypeRequest,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offered.AsSlice()))))
	require.Len(t, ack.sent, 1, "REQUEST for the offered address must be answered")
	assert.Equal(t, dhcpv4.MessageTypeAck, ack.sent[0].MessageType())
	assert.Equal(t, offered.String(), ack.sent[0].YourIPAddr.String())

	nak := exchange(handle, newReplyTestRequest(t, dhcpv4.MessageTypeRequest))
	require.Len(t, nak.sent, 1, "REQUEST without an address must be refused")
	assert.Equal(t, dhcpv4.MessageTypeNak, nak.sent[0].MessageType())

	stats := srv.Stats()
	assert.Equal(t, uint64(3), stats.PacketsSent)
	assert.Equal(t, uint64(1), stats.OfferCount)
	assert.Equal(t, uint64(1), stats.AckCount)
	assert.Equal(t, uint64(1), stats.NakCount)
}

// A message the plugin answers with no reply, such as DHCPRELEASE, must
// still send nothing.
func TestCoreDHCPServer_HandlerSendsNothingWithoutReply(t *testing.T) {
	srv, handle := newReplyTestHandler(t)

	release := exchange(handle, newReplyTestRequest(t, dhcpv4.MessageTypeRelease,
		dhcpv4.WithClientIP(net.ParseIP("192.168.1.100"))))

	assert.Empty(t, release.sent)
	stats := srv.Stats()
	assert.Equal(t, uint64(1), stats.PacketsReceived)
	assert.Zero(t, stats.PacketsSent)
}

// A reply the socket refuses is counted as an error.
func TestCoreDHCPServer_HandlerCountsSendFailure(t *testing.T) {
	srv, handle := newReplyTestHandler(t)

	handle(&failingConn{}, replyTestPeer, newReplyTestRequest(t, dhcpv4.MessageTypeDiscover))

	assert.Equal(t, uint64(1), srv.Stats().ErrorCount)
}

// failingConn refuses every write.
type failingConn struct {
	net.PacketConn
}

func (c *failingConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, net.ErrClosed
}
