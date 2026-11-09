package fabric

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSingleDriverManager builds a manager over the two-switch test fabric
// with a driver for sw-01 only, so sw-02 is a configured peer without one.
func newSingleDriverManager(t *testing.T) (Manager, *mockDriver) {
	t.Helper()
	a := newMock()
	mgr, err := NewManagerWithDrivers(validFabricConfig(), testPlan(t), quietLogger(),
		map[string]Driver{"sw-01": a})
	require.NoError(t, err)
	return mgr, a
}

// TestPortOps_SkipPeerWithoutDriver applies each port operation on sw-01 and
// expects it to succeed on sw-01 alone: a LAG peer with no driver is skipped,
// not reported as an unknown switch.
func TestPortOps_SkipPeerWithoutDriver(t *testing.T) {
	ref := PortRef{SwitchID: "sw-01", Port: "Ethernet1/7"}
	tests := []struct {
		name string
		op   func(ctx context.Context, mgr Manager) error
	}{
		{"disable", func(ctx context.Context, mgr Manager) error { return mgr.DisablePort(ctx, ref) }},
		{"quarantine", func(ctx context.Context, mgr Manager) error { return mgr.QuarantinePort(ctx, ref) }},
		{"provision", func(ctx context.Context, mgr Manager) error { return mgr.ProvisionPort(ctx, ref) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, a := newSingleDriverManager(t)
			require.NoError(t, tt.op(context.Background(), mgr))
			require.Len(t, a.ports, 1)
			assert.Equal(t, ref, a.ports[0].port)
		})
	}
}

// TestApplyFabric_PeerLinkUnknownSwitch refuses a peer link on a switch with
// no driver, after configuring the peer link on the switch that has one.
func TestApplyFabric_PeerLinkUnknownSwitch(t *testing.T) {
	mgr, a := newSingleDriverManager(t)

	err := mgr.ApplyFabric(context.Background())

	var unknown ErrUnknownSwitch
	require.True(t, errors.As(err, &unknown), "got %v", err)
	assert.Equal(t, "sw-02", unknown.ID)
	require.Len(t, a.ports, 1)
	assert.Equal(t, PortRef{SwitchID: "sw-01", Port: "Ethernet1/49"}, a.ports[0].port)
}

// TestQuarantinePort_InvalidRef refuses a port reference without a switch
// before any driver is touched.
func TestQuarantinePort_InvalidRef(t *testing.T) {
	mgr, a, b := newTestManager(t)

	err := mgr.QuarantinePort(context.Background(), PortRef{Port: "Ethernet1/7"})

	var badRef ErrInvalidPortRef
	require.True(t, errors.As(err, &badRef), "got %v", err)
	assert.Empty(t, a.ports)
	assert.Empty(t, b.ports)
}
