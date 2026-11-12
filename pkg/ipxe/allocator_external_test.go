package ipxe_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

// externalAllocator is an IPAllocator written outside package ipxe, the way
// an external IPAM integration would write one.
type externalAllocator struct {
	ip net.IP
}

var _ ipxe.IPAllocator = (*externalAllocator)(nil)

func (a *externalAllocator) Allocate(_ context.Context, _ net.HardwareAddr, _ string) (net.IP, error) {
	return a.ip, nil
}

func (a *externalAllocator) Release(_ context.Context, _ net.HardwareAddr) error {
	return nil
}

func (a *externalAllocator) GetLease(_ context.Context, mac net.HardwareAddr) (*ipxe.Lease, error) {
	return &ipxe.Lease{IP: a.ip, MAC: mac, ExpiresAt: time.Unix(0, 0).Add(time.Hour)}, nil
}

func (a *externalAllocator) Renew(_ context.Context, _ net.HardwareAddr) error {
	return nil
}

// TestIPAllocator_ExternalImplementation proves IPAllocator can be implemented
// outside the package and is accepted by WithIPAllocator (#1693).
func TestIPAllocator_ExternalImplementation(t *testing.T) {
	alloc := &externalAllocator{ip: net.ParseIP("10.0.0.100")}

	cfg := &ipxe.DHCPConfig{
		ServerIP:   net.ParseIP("192.168.1.1"),
		RangeStart: net.ParseIP("192.168.1.100"),
		RangeEnd:   net.ParseIP("192.168.1.200"),
	}
	server, err := ipxe.NewDHCPServer(cfg, nil, ipxe.WithIPAllocator(alloc))
	require.NoError(t, err)
	assert.Same(t, alloc, server.GetAllocator())

	mac, err := net.ParseMAC("00:11:22:33:44:55")
	require.NoError(t, err)
	l, err := server.GetAllocator().GetLease(context.Background(), mac)
	require.NoError(t, err)
	assert.True(t, l.IP.Equal(alloc.ip))
	assert.Equal(t, mac, l.MAC)
}
