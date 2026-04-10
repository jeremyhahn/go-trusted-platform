//go:build integration

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

package stress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

// underlayInterfaceEnvVar is the environment variable that specifies
// the underlay network interface name for overlay tests.
const underlayInterfaceEnvVar = "OVERLAY_UNDERLAY_INTERFACE"

// skipIfNoUnderlayInterface checks whether a suitable underlay network
// interface is available for overlay controller tests. It first checks the
// OVERLAY_UNDERLAY_INTERFACE environment variable, then falls back to
// probing for common interface names (eth0, ens0, enp0s0). If no usable
// interface is found, the test is skipped.
func skipIfNoUnderlayInterface(t *testing.T) string {
	t.Helper()

	// Check environment variable first
	if iface := os.Getenv(underlayInterfaceEnvVar); iface != "" {
		if _, err := net.InterfaceByName(iface); err == nil {
			return iface
		}
		t.Skipf("Skipping: underlay interface %q from %s not available: interface not found",
			iface, underlayInterfaceEnvVar)
	}

	// Probe for common underlay interface names
	candidates := []string{"eth0", "ens0", "enp0s0"}
	for _, name := range candidates {
		if _, err := net.InterfaceByName(name); err == nil {
			return name
		}
	}

	t.Skipf("Skipping: no underlay network interface available (set %s or ensure eth0/ens0/enp0s0 exists)",
		underlayInterfaceEnvVar)
	return "" // unreachable, t.Skipf calls runtime.Goexit
}

// createTestOverlayController creates an overlay controller for testing.
func createTestOverlayController(t *testing.T, nodeID string, underlayIface string) *overlay.Controller {
	t.Helper()

	config := &overlay.Config{
		NodeID:              nodeID,
		VTEPIP:              netip.MustParseAddr("10.0.0.1"),
		UnderlayInterface:   underlayIface,
		HealthCheckInterval: 30 * time.Second,
		MACExpiration:       5 * time.Minute,
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	controller, err := overlay.New(config, overlay.WithLogger(logger))
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	return controller
}

// generateTestMAC generates a unique MAC address for testing.
func generateTestMAC(counter uint64) net.HardwareAddr {
	return net.HardwareAddr{
		0x02, // Locally administered
		0x00,
		byte((counter >> 24) & 0xFF),
		byte((counter >> 16) & 0xFF),
		byte((counter >> 8) & 0xFF),
		byte(counter & 0xFF),
	}
}

// isVTEPAlreadyExistsErr returns true if the error chain contains a VTEP
// "already exists" condition. Under concurrent churn, duplicate adds are
// expected and should not count as failures.
func isVTEPAlreadyExistsErr(err error) bool {
	var vtepOpErr *overlay.ErrVTEPOperationFailed
	if errors.As(err, &vtepOpErr) {
		return errors.Is(vtepOpErr.Cause, overlay.ErrVTEPAlreadyExists)
	}
	return errors.Is(err, overlay.ErrVTEPAlreadyExists)
}

// isVTEPNotFoundErr returns true if the error chain contains a VTEP
// "not found" condition. Under concurrent churn, double-removes are
// expected and should not count as failures.
func isVTEPNotFoundErr(err error) bool {
	var vtepOpErr *overlay.ErrVTEPOperationFailed
	if errors.As(err, &vtepOpErr) {
		return errors.Is(vtepOpErr.Cause, overlay.ErrVTEPNotFound)
	}
	return errors.Is(err, overlay.ErrVTEPNotFound)
}

// TestOverlayMACLearningStress tests high MAC learning rate.
func TestOverlayMACLearningStress(t *testing.T) {
	underlayIface := skipIfNoUnderlayInterface(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	controller := createTestOverlayController(t, "stress-node-1", underlayIface)

	if err := controller.Start(ctx); err != nil {
		t.Fatalf("Failed to start controller: %v", err)
	}
	defer func() {
		if err := controller.Stop(ctx); err != nil {
			t.Logf("Error stopping controller: %v", err)
		}
	}()

	// Create a VNI for testing
	vniConfig := &overlay.VNIConfig{
		VNI:  100,
		VLAN: 10,
	}
	if err := controller.AddVNI(ctx, vniConfig); err != nil {
		t.Fatalf("Failed to add VNI: %v", err)
	}

	config := StressConfig{
		Name:           "Overlay MAC Learning Stress",
		Duration:       8 * time.Second,
		Concurrency:    20,
		RateLimit:      2000,
		ReportInterval: 3 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	macCounter := atomic.Uint64{}
	learnedCount := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		counter := macCounter.Add(1)
		mac := generateTestMAC(counter)

		// Simulate MAC learning from different remote VTEPs
		vtepOctet := byte((counter % 254) + 1)
		remoteVTEP := netip.MustParseAddr(fmt.Sprintf("10.0.1.%d", vtepOctet))

		err := controller.LearnMAC(ctx, mac, 100, remoteVTEP)
		if err == nil {
			learnedCount.Add(1)
		}
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("MACs learned: %d, Total operations: %d", learnedCount.Load(), result.TotalOperations)

	if result.SuccessRate() < 95 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 95%%)", result.SuccessRate())
	}

	if result.Latencies.P99 > 10*time.Millisecond {
		t.Errorf("P99 latency too high: %s (expected <= 10ms)", result.Latencies.P99)
	}
}

// TestOverlayMACChurnStress tests rapid MAC learning and forgetting.
func TestOverlayMACChurnStress(t *testing.T) {
	underlayIface := skipIfNoUnderlayInterface(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	controller := createTestOverlayController(t, "stress-node-2", underlayIface)

	if err := controller.Start(ctx); err != nil {
		t.Fatalf("Failed to start controller: %v", err)
	}
	defer func() {
		if err := controller.Stop(ctx); err != nil {
			t.Logf("Error stopping controller: %v", err)
		}
	}()

	// Create multiple VNIs
	for vni := uint32(100); vni <= 105; vni++ {
		vniConfig := &overlay.VNIConfig{
			VNI:  vni,
			VLAN: uint16(vni - 90),
		}
		if err := controller.AddVNI(ctx, vniConfig); err != nil {
			t.Fatalf("Failed to add VNI %d: %v", vni, err)
		}
	}

	config := StressConfig{
		Name:           "Overlay MAC Churn Stress",
		Duration:       8 * time.Second,
		Concurrency:    15,
		RateLimit:      1000,
		ReportInterval: 3 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	macCounter := atomic.Uint64{}
	learnCount := atomic.Int64{}
	forgetCount := atomic.Int64{}

	// Track learned MACs for forgetting
	learnedMACs := make(chan struct {
		mac net.HardwareAddr
		vni uint32
	}, 500)

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		counter := macCounter.Add(1)
		vni := uint32(100 + (counter % 6))

		if counter%4 == 0 {
			// Try to forget a MAC
			select {
			case entry := <-learnedMACs:
				err := controller.ForgetMAC(ctx, entry.mac, entry.vni)
				if err == nil {
					forgetCount.Add(1)
				}
				return err
			default:
				// No MACs to forget
			}
		}

		// Learn a new MAC
		mac := generateTestMAC(counter)
		vtepOctet := byte((counter % 254) + 1)
		remoteVTEP := netip.MustParseAddr(fmt.Sprintf("10.0.1.%d", vtepOctet))

		err := controller.LearnMAC(ctx, mac, vni, remoteVTEP)
		if err == nil {
			learnCount.Add(1)
			select {
			case learnedMACs <- struct {
				mac net.HardwareAddr
				vni uint32
			}{mac, vni}:
			default:
			}
		}
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("MACs learned: %d, MACs forgotten: %d", learnCount.Load(), forgetCount.Load())

	if result.SuccessRate() < 90 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 90%%)", result.SuccessRate())
	}
}

// TestOverlayVTEPChurnStress tests VTEP creation/deletion churn.
func TestOverlayVTEPChurnStress(t *testing.T) {
	underlayIface := skipIfNoUnderlayInterface(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	controller := createTestOverlayController(t, "stress-node-3", underlayIface)

	if err := controller.Start(ctx); err != nil {
		t.Fatalf("Failed to start controller: %v", err)
	}
	defer func() {
		if err := controller.Stop(ctx); err != nil {
			t.Logf("Error stopping controller: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "Overlay VTEP Churn Stress",
		Duration:       8 * time.Second,
		Concurrency:    10,
		RateLimit:      200,
		ReportInterval: 3 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	vtepCounter := atomic.Uint64{}
	addCount := atomic.Int64{}
	removeCount := atomic.Int64{}

	// Track active VTEPs
	activeVTEPs := make(chan netip.Addr, 100)

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		counter := vtepCounter.Add(1)

		if counter%3 == 0 {
			// Try to remove a VTEP
			select {
			case vtepIP := <-activeVTEPs:
				err := controller.RemoveVTEP(ctx, vtepIP)
				if err == nil {
					removeCount.Add(1)
					return nil
				}
				// Under concurrent churn, the VTEP may have already been
				// removed by another worker. Treat "not found" as success.
				if isVTEPNotFoundErr(err) {
					return nil
				}
				return err
			default:
				// No VTEPs to remove
			}
		}

		// Add a VTEP
		octet := byte((counter % 250) + 1)
		vtepIP := netip.MustParseAddr(fmt.Sprintf("10.0.2.%d", octet))

		vtep := &overlay.VTEPInfo{
			NodeID:      fmt.Sprintf("remote-node-%d", counter),
			IP:          vtepIP,
			Healthy:     true,
			LastSeen:    time.Now(),
			EVPNEnabled: true,
		}

		err := controller.AddVTEP(ctx, vtep)
		if err == nil {
			addCount.Add(1)
			select {
			case activeVTEPs <- vtepIP:
			default:
			}
			return nil
		}

		// Under concurrent churn with a limited IP space (250 addresses),
		// duplicate adds are expected. Treat "already exists" as success.
		if isVTEPAlreadyExistsErr(err) {
			return nil
		}
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("VTEPs added: %d, VTEPs removed: %d", addCount.Load(), removeCount.Load())

	if result.SuccessRate() < 85 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 85%%)", result.SuccessRate())
	}
}

// TestOverlayVNIOperationsStress tests VNI creation and management under load.
func TestOverlayVNIOperationsStress(t *testing.T) {
	underlayIface := skipIfNoUnderlayInterface(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	controller := createTestOverlayController(t, "stress-node-4", underlayIface)

	if err := controller.Start(ctx); err != nil {
		t.Fatalf("Failed to start controller: %v", err)
	}
	defer func() {
		if err := controller.Stop(ctx); err != nil {
			t.Logf("Error stopping controller: %v", err)
		}
	}()

	config := StressConfig{
		Name:           "Overlay VNI Operations Stress",
		Duration:       8 * time.Second,
		Concurrency:    10,
		RateLimit:      100,
		ReportInterval: 3 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	vniCounter := atomic.Uint64{}
	addCount := atomic.Int64{}
	removeCount := atomic.Int64{}
	getCount := atomic.Int64{}

	// Track active VNIs
	activeVNIs := make(chan uint32, 100)

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		counter := vniCounter.Add(1)
		action := counter % 10

		switch {
		case action < 5: // 50% add VNI
			vni := uint32(1000 + (counter % 4000))
			vlan := uint16((counter % 4094) + 1)

			vniConfig := &overlay.VNIConfig{
				VNI:  vni,
				VLAN: vlan,
			}

			err := controller.AddVNI(ctx, vniConfig)
			if err == nil {
				addCount.Add(1)
				select {
				case activeVNIs <- vni:
				default:
				}
			}
			return err

		case action < 7: // 20% get VNI
			select {
			case vni := <-activeVNIs:
				_, err := controller.GetVNI(ctx, vni)
				if err == nil {
					getCount.Add(1)
				}
				select {
				case activeVNIs <- vni:
				default:
				}
				return err
			default:
				return nil
			}

		default: // 30% remove VNI
			select {
			case vni := <-activeVNIs:
				err := controller.RemoveVNI(ctx, vni)
				if err == nil {
					removeCount.Add(1)
				}
				return err
			default:
				return nil
			}
		}
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("VNIs added: %d, VNIs removed: %d, VNI gets: %d",
		addCount.Load(), removeCount.Load(), getCount.Load())

	if result.SuccessRate() < 80 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 80%%)", result.SuccessRate())
	}
}

// TestOverlayMACWithIPLearningStress tests MAC/IP learning from EVPN.
func TestOverlayMACWithIPLearningStress(t *testing.T) {
	underlayIface := skipIfNoUnderlayInterface(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	controller := createTestOverlayController(t, "stress-node-5", underlayIface)

	if err := controller.Start(ctx); err != nil {
		t.Fatalf("Failed to start controller: %v", err)
	}
	defer func() {
		if err := controller.Stop(ctx); err != nil {
			t.Logf("Error stopping controller: %v", err)
		}
	}()

	// Create VNI
	vniConfig := &overlay.VNIConfig{
		VNI:  200,
		VLAN: 20,
	}
	if err := controller.AddVNI(ctx, vniConfig); err != nil {
		t.Fatalf("Failed to add VNI: %v", err)
	}

	config := StressConfig{
		Name:           "Overlay MAC/IP Learning Stress",
		Duration:       8 * time.Second,
		Concurrency:    25,
		RateLimit:      1500,
		ReportInterval: 3 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	counter := atomic.Uint64{}
	learnedCount := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c := counter.Add(1)
		mac := generateTestMAC(c)

		// Generate unique IP
		octet3 := byte((c >> 8) & 0xFF)
		octet4 := byte(c & 0xFF)
		ip := netip.MustParseAddr(fmt.Sprintf("192.168.%d.%d", octet3, octet4))

		// Generate remote VTEP
		vtepOctet := byte((c % 254) + 1)
		remoteVTEP := netip.MustParseAddr(fmt.Sprintf("10.0.3.%d", vtepOctet))

		err := controller.LearnMACWithIP(ctx, mac, ip, 200, remoteVTEP)
		if err == nil {
			learnedCount.Add(1)
		}
		return err
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("MAC/IP entries learned: %d", learnedCount.Load())

	if result.SuccessRate() < 95 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 95%%)", result.SuccessRate())
	}
}

// TestOverlayCombinedStress tests all overlay operations under combined load.
func TestOverlayCombinedStress(t *testing.T) {
	underlayIface := skipIfNoUnderlayInterface(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	controller := createTestOverlayController(t, "stress-node-6", underlayIface)

	if err := controller.Start(ctx); err != nil {
		t.Fatalf("Failed to start controller: %v", err)
	}
	defer func() {
		if err := controller.Stop(ctx); err != nil {
			t.Logf("Error stopping controller: %v", err)
		}
	}()

	// Pre-create some VNIs
	for vni := uint32(300); vni <= 310; vni++ {
		vniConfig := &overlay.VNIConfig{
			VNI:  vni,
			VLAN: uint16(vni - 290),
		}
		if err := controller.AddVNI(ctx, vniConfig); err != nil {
			t.Fatalf("Failed to add VNI %d: %v", vni, err)
		}
	}

	config := StressConfig{
		Name:           "Overlay Combined Stress",
		Duration:       8 * time.Second,
		Concurrency:    30,
		RateLimit:      800,
		ReportInterval: 3 * time.Second,
		WarmupDuration: 1 * time.Second,
	}

	counter := atomic.Uint64{}
	macLearnCount := atomic.Int64{}
	vtepAddCount := atomic.Int64{}
	vniGetCount := atomic.Int64{}

	op := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c := counter.Add(1)
		action := c % 10

		switch {
		case action < 6: // 60% MAC learning
			mac := generateTestMAC(c)
			vni := uint32(300 + (c % 11))
			vtepOctet := byte((c % 254) + 1)
			remoteVTEP := netip.MustParseAddr(fmt.Sprintf("10.0.4.%d", vtepOctet))

			err := controller.LearnMAC(ctx, mac, vni, remoteVTEP)
			if err == nil {
				macLearnCount.Add(1)
			}
			return err

		case action < 8: // 20% VNI lookups
			vni := uint32(300 + (c % 11))
			_, err := controller.GetVNI(ctx, vni)
			if err == nil {
				vniGetCount.Add(1)
			}
			return err

		default: // 20% VTEP operations
			octet := byte((c % 250) + 1)
			vtepIP := netip.MustParseAddr(fmt.Sprintf("10.0.5.%d", octet))

			vtep := &overlay.VTEPInfo{
				NodeID:      fmt.Sprintf("remote-node-%d", c),
				IP:          vtepIP,
				Healthy:     true,
				LastSeen:    time.Now(),
				EVPNEnabled: true,
			}

			err := controller.AddVTEP(ctx, vtep)
			if err == nil {
				vtepAddCount.Add(1)
				return nil
			}

			// Under combined load with a limited IP space (250 addresses),
			// duplicate VTEP adds are expected. Treat "already exists" as
			// success since the VTEP is present in state.
			if isVTEPAlreadyExistsErr(err) {
				return nil
			}
			return err
		}
	}

	reporter := NewTableReporter(os.Stdout)
	result, err := RunStressTest(ctx, config.Name, config, op, reporter)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	t.Logf("MAC learns: %d, VNI gets: %d, VTEP adds: %d",
		macLearnCount.Load(), vniGetCount.Load(), vtepAddCount.Load())

	if result.SuccessRate() < 85 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 85%%)", result.SuccessRate())
	}

	// Check state consistency
	state := controller.GetState()
	t.Logf("Final state - VNIs: %d, VTEPs: %d, Remote MACs: %d",
		len(state.VNIs), len(state.VTEPs), len(state.RemoteMACs))
}
