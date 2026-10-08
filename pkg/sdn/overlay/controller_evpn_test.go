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

package overlay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

var errSpeakerDown = errors.New("speaker down")

// pathRecorder is an EVPN speaker that records the paths it is given.
type pathRecorder struct {
	mu      sync.Mutex
	added   []*bgp.Path
	deleted []*bgp.Path
	addErr  error
}

func (r *pathRecorder) AddPath(_ context.Context, path *bgp.Path) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.addErr != nil {
		return r.addErr
	}
	r.added = append(r.added, path)
	return nil
}

func (r *pathRecorder) DeletePath(_ context.Context, path *bgp.Path) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleted = append(r.deleted, path)
	return nil
}

func (r *pathRecorder) WatchEvent(context.Context, ...bgp.WatchOption) (<-chan *bgp.Event, error) {
	return make(chan *bgp.Event), nil
}

// imetVNIs returns the VNIs of the Type-3 routes among paths.
func imetVNIs(r *pathRecorder, deleted bool) []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	paths := r.added
	if deleted {
		paths = r.deleted
	}
	var vnis []uint32
	for _, path := range paths {
		if path.EVPN != nil && path.EVPN.IMET != nil {
			vnis = append(vnis, path.EVPN.IMET.VNI)
		}
	}
	return vnis
}

// newEVPNController starts a controller whose EVPN manager originates into
// speaker.
func newEVPNController(t *testing.T, speaker *pathRecorder) (*Controller, *bgp.EVPNManager) {
	t.Helper()
	vtep := netip.MustParseAddr("10.0.0.1")
	manager, err := bgp.NewEVPNManager(&bgp.EVPNManagerConfig{
		Speaker:    speaker,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		LocalVTEP:  vtep,
		OverlayASN: 65000,
	})
	if err != nil {
		t.Fatalf("NewEVPNManager() error = %v", err)
	}
	ctrl, err := New(&Config{
		NodeID:              "test-node",
		VTEPIP:              vtep,
		UnderlayInterface:   "eth0",
		BridgeName:          "br-test",
		HealthCheckInterval: time.Hour,
		MACExpiration:       time.Hour,
		EnableEVPN:          true,
	}, WithEVPNManager(manager))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := context.Background()
	if err := ctrl.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		if err := ctrl.Stop(ctx); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	return ctrl, manager
}

func TestController_EVPNJoinsAndLeavesVNI(t *testing.T) {
	t.Parallel()

	speaker := &pathRecorder{}
	ctrl, manager := newEVPNController(t, speaker)
	ctx := context.Background()

	if err := ctrl.AddVNI(ctx, &VNIConfig{VNI: 100000, VLAN: 100, AdvertiseIMET: true}); err != nil {
		t.Fatalf("AddVNI() error = %v", err)
	}
	if got := imetVNIs(speaker, false); len(got) != 1 || got[0] != 100000 {
		t.Fatalf("advertised IMET VNIs = %v, want [100000]", got)
	}
	info, err := ctrl.GetVNI(ctx, 100000)
	if err != nil {
		t.Fatalf("GetVNI() error = %v", err)
	}
	if !info.IMETAdvertised {
		t.Error("IMETAdvertised = false, want true")
	}
	if rd, ok := manager.RouteDistinguisher(100000); !ok || rd.String() != "10.0.0.1:1" {
		t.Errorf("RouteDistinguisher() = %v, %v; want 10.0.0.1:1, true", rd, ok)
	}

	if err := ctrl.RemoveVNI(ctx, 100000); err != nil {
		t.Fatalf("RemoveVNI() error = %v", err)
	}
	if got := imetVNIs(speaker, true); len(got) != 1 || got[0] != 100000 {
		t.Errorf("withdrawn IMET VNIs = %v, want [100000]", got)
	}
	if _, ok := manager.RouteDistinguisher(100000); ok {
		t.Error("the EVI kept its RD after the VNI was removed")
	}
}

func TestController_EVPNJoinFailure(t *testing.T) {
	t.Parallel()

	speaker := &pathRecorder{addErr: errSpeakerDown}
	ctrl, _ := newEVPNController(t, speaker)
	ctx := context.Background()

	var advErr bgp.ErrRouteAdvertisementFailed
	if err := ctrl.advertiseIMET(ctx, 100000); !errors.As(err, &advErr) || !errors.Is(err, errSpeakerDown) {
		t.Errorf("advertiseIMET() error = %v, want ErrRouteAdvertisementFailed wrapping the speaker error", err)
	}

	// The VNI is still added; only its IMET route is missing.
	if err := ctrl.AddVNI(ctx, &VNIConfig{VNI: 100000, AdvertiseIMET: true}); err != nil {
		t.Fatalf("AddVNI() error = %v", err)
	}
	info, err := ctrl.GetVNI(ctx, 100000)
	if err != nil {
		t.Fatalf("GetVNI() error = %v", err)
	}
	if info.IMETAdvertised {
		t.Error("IMETAdvertised = true after a failed advertisement")
	}

	var notJoined bgp.ErrVNINotJoined
	if err := ctrl.withdrawIMET(ctx, 100000); !errors.As(err, &notJoined) {
		t.Errorf("withdrawIMET() error = %v, want ErrVNINotJoined", err)
	}
}
