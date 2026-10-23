// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package commands

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// recordingRefresher records the devices it was asked to re-attest.
type recordingRefresher struct {
	ids []string
}

func (r *recordingRefresher) Refresh(deviceID string) error {
	r.ids = append(r.ids, deviceID)
	return nil
}

func onFabricDevices() *stubSaveGetSvc {
	return &stubSaveGetSvc{devices: map[uint64]*entities.Device{
		55: {ID: 55, State: entities.DeviceStateAttested, NetworkPortID: "tap55"},
	}}
}

// TestWireDeviceLifecycle_EnforcesThroughTheManager proves the wired flow
// reaches the quarantine manager: disable suspends the device, enable re-admits
// it to quarantine and asks the collector to re-attest it.
func TestWireDeviceLifecycle_EnforcesThroughTheManager(t *testing.T) {
	svc := onFabricDevices()
	refresher := &recordingRefresher{}
	cfg := &daemon.Config{DeviceService: svc}

	wireDeviceLifecycle(cfg, buildTestQuarantineManager(t, &deviceStateStoreAdapter{svc: svc}), refresher, nil)
	if cfg.DeviceLifecycle == nil {
		t.Fatal("DeviceLifecycle was not configured")
	}

	ctx := context.Background()
	if _, err := cfg.DeviceLifecycle.Disable(ctx, 55, "rma pending"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if got := svc.devices[55].State; got != entities.DeviceStateSuspended {
		t.Fatalf("state after disable = %s, want suspended", got)
	}

	res, err := cfg.DeviceLifecycle.Enable(ctx, 55)
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if got := svc.devices[55].State; got != entities.DeviceStateQuarantined {
		t.Errorf("state after enable = %s, want quarantined", got)
	}
	if !res.ReattestationRequested || len(refresher.ids) != 1 || refresher.ids[0] != "55" {
		t.Errorf("re-attestation requested=%v refreshed=%v, want device 55 refreshed", res.ReattestationRequested, refresher.ids)
	}
}

func TestWireDeviceLifecycle_LeavesTheConfigUnenforced(t *testing.T) {
	svc := onFabricDevices()
	manager := buildTestQuarantineManager(t, &deviceStateStoreAdapter{svc: svc})

	t.Run("nil config", func(t *testing.T) {
		wireDeviceLifecycle(nil, manager, nil, nil)
	})
	t.Run("no quarantine manager", func(t *testing.T) {
		cfg := &daemon.Config{DeviceService: svc}
		wireDeviceLifecycle(cfg, nil, &recordingRefresher{}, nil)
		if cfg.DeviceLifecycle != nil {
			t.Errorf("DeviceLifecycle = %v, want none without an enforcer", cfg.DeviceLifecycle)
		}
	})
	t.Run("no device service", func(t *testing.T) {
		cfg := &daemon.Config{}
		wireDeviceLifecycle(cfg, manager, nil, nil)
		if cfg.DeviceLifecycle != nil {
			t.Errorf("DeviceLifecycle = %v, want none without a device registry", cfg.DeviceLifecycle)
		}
	})
}

func TestReportingRefresher(t *testing.T) {
	collector := &recordingRefresher{}
	withCollector := &daemon.Config{AttestationReporting: &daemon.ReportingHandles{Refresher: collector}}
	if got := reportingRefresher(withCollector); got != collector {
		t.Errorf("reportingRefresher = %v, want the collector", got)
	}

	for name, cfg := range map[string]*daemon.Config{
		"nil config":   nil,
		"no reporting": {},
		"no collector": {AttestationReporting: &daemon.ReportingHandles{}},
	} {
		if got := reportingRefresher(cfg); got != nil {
			t.Errorf("%s: reportingRefresher = %v, want nil", name, got)
		}
	}
}
