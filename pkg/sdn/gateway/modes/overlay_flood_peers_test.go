package modes

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// floodPeerRecorder is a FloodPeers handler that records each change it is
// told as "add|withdraw vni@vtep" and answers with err.
type floodPeerRecorder struct {
	mu   sync.Mutex
	told []string
	err  error
}

func (r *floodPeerRecorder) handle(_ context.Context, route *bgp.EVPNRouteData) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	change := "add"
	if route.IsWithdraw {
		change = "withdraw"
	}
	r.told = append(r.told, fmt.Sprintf("%s %d@%s", change, route.IMET.VNI, route.IMET.VTEPIP))
	return r.err
}

func (r *floodPeerRecorder) changes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.told...)
}

func newFloodPeersFixture(t *testing.T, peers *floodPeerRecorder, edit func(*OverlayModeConfig)) *overlayFixture {
	t.Helper()
	return newOverlayFixture(t, func(c *OverlayModeConfig) {
		c.FloodPeers = peers.handle
		if edit != nil {
			edit(c)
		}
	}).withVNI(t)
}

func TestOverlayFloodPeers(t *testing.T) {
	t.Run("is told each change to a flood list and the VTEPs of a VNI left", func(t *testing.T) {
		peers := &floodPeerRecorder{}
		f := newFloodPeersFixture(t, peers, nil)

		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPC)))
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)), "a repeat changes nothing")
		require.NoError(t, f.route(t, withdraw(imet(ovlL2VNI, ovlVTEPB))))
		require.NoError(t, f.handler.RemoveVNI(context.Background(), ovlL2VNI))

		assert.Equal(t, []string{
			"add 10100@10.0.0.2",
			"add 10100@10.0.0.3",
			"withdraw 10100@10.0.0.2",
			"withdraw 10100@10.0.0.3",
		}, peers.changes())
	})

	t.Run("a revocation withdraws the VTEP", func(t *testing.T) {
		peers := &floodPeerRecorder{}
		f := newFloodPeersFixture(t, peers, nil)
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))

		require.NoError(t, f.handler.RevokeVTEP(context.Background(), ovlVTEPB))

		assert.Equal(t, []string{"add 10100@10.0.0.2", "withdraw 10100@10.0.0.2"}, peers.changes())
	})

	t.Run("a change the admitter or the switch refuses is not told", func(t *testing.T) {
		peers := &floodPeerRecorder{}
		admitter := &recordingAdmitter{refused: map[netip.Addr]bool{ovlVTEPB: true}}
		f := newFloodPeersFixture(t, peers, func(c *OverlayModeConfig) { c.Admitter = admitter })

		assertVTEPFailed(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)), "admit")
		f.sw.fail(errSwitchDown)
		assertVTEPFailed(t, f.route(t, imet(ovlL2VNI, ovlVTEPC)), "flood list")
		f.sw.fail(nil)

		assert.Empty(t, peers.changes())
	})

	t.Run("a failure is returned and the flows keep the change", func(t *testing.T) {
		peers := &floodPeerRecorder{err: errSwitchDown}
		f := newFloodPeersFixture(t, peers, nil)

		err := f.route(t, imet(ovlL2VNI, ovlVTEPB))

		assertVTEPFailed(t, err, "flood peers")
		assert.ErrorIs(t, err, errSwitchDown)
		assert.Equal(t, "goto:20", f.sw.lookup(t, TableVXLANDecap, fromVTEP(ovlL2VNI, ovlVTEPB)...))
	})

	t.Run("a failed withdrawal on leaving a VNI is returned once the VNI is gone", func(t *testing.T) {
		peers := &floodPeerRecorder{}
		f := newFloodPeersFixture(t, peers, nil)
		require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
		peers.mu.Lock()
		peers.err = errSwitchDown
		peers.mu.Unlock()

		err := f.handler.RemoveVNI(context.Background(), ovlL2VNI)

		assertVTEPFailed(t, err, "flood peers")
		assert.ErrorIs(t, f.handler.RemoveVNI(context.Background(), ovlL2VNI), ErrVNINotFound,
			"the VNI is gone despite the failure")
	})
}
