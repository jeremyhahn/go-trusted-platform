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

package commands

import (
	"context"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// initSDNEnrollmentHook constructs the SDNEnrollmentHook with a real PortBinder
// wired so that successful device activations stamp device.NetworkPortID onto the
// persisted device record, making the port mapping restart-survivable.
//
// Returns nil when any required dependency (device service, profile service, or
// policy engine) is unavailable. The webservice registry treats a nil hook as
// "SDN network transitions disabled" and skips hook registration, so the node
// continues to function without SDN.
//
// The PortBinder callback:
//  1. Looks up the device by serial number.
//  2. Sets device.NetworkPortID to the real OVS tap/interface name.
//  3. Persists the record via device.DeviceService.Save.
//
// The quarantine observer (wireQuarantineObserver) then reads NetworkPortID
// from the device record at violation / restore time instead of fabricating a
// port name from the device ID.
//
// zones is the resolved SDN zone set. It wires BOTH the certificate zone
// extractor (so buildPortPolicy cross-checks the OIDTPNetworkZone extension
// in issued certificates against the profile zone — without it a mismatched
// certificate zone is silently accepted) and the quarantine-zone resolution
// used when a mismatch is detected.
func initSDNEnrollmentHook(
	policyEngine policy.PolicyEngine,
	deviceService device.DeviceService,
	profileService *device.ProfileService,
	zones []zone.ZoneConfig,
	logger *logging.Logger,
) *policy.SDNEnrollmentHook {
	if policyEngine == nil {
		return nil
	}
	if deviceService == nil {
		return nil
	}
	if profileService == nil {
		return nil
	}

	slogger := logger.Slog()

	hook, err := policy.NewSDNEnrollmentHook(
		newSDNEnrollmentHookConfig(policyEngine, deviceService, profileService, zones, slogger))
	if err != nil {
		slogger.Error("failed to construct SDN enrollment hook",
			slog.String("error", err.Error()))
		return nil
	}

	slogger.Info("SDN enrollment hook initialized with port binder and zone cross-check",
		slog.Int("resolved_zones", len(zones)))
	return hook
}

// newSDNEnrollmentHookConfig builds the production SDNEnrollmentHookConfig:
// the port-binder that stamps device.NetworkPortID, and the certificate zone
// extractor plus resolved zones that make buildPortPolicy cross-check issued
// certificates against the profile zone. Tests exercise this exact config
// (overriding only the MAC extractor, which defaults to ARP-table lookup) to
// prove the production wiring detects a zone mismatch and quarantines.
func newSDNEnrollmentHookConfig(
	policyEngine policy.PolicyEngine,
	deviceService device.DeviceService,
	profileService *device.ProfileService,
	zones []zone.ZoneConfig,
	slogger *slog.Logger,
) policy.SDNEnrollmentHookConfig {
	// portBinder stamps the real OVS port name onto the device record so the
	// quarantine observer can look it up without fabricating a name.
	portBinder := func(ctx context.Context, serial, portID string) error {
		d, err := deviceService.FindBySerial(ctx, serial)
		if err != nil {
			return err
		}
		d.NetworkPortID = portID
		if err := deviceService.Save(ctx, d); err != nil {
			return err
		}
		slogger.Info("stamped NetworkPortID on device record",
			slog.String("serial", serial),
			slog.String("port_id", portID),
			slog.Uint64("device_id", d.ID))
		return nil
	}

	return policy.SDNEnrollmentHookConfig{
		Logger:       slogger,
		PolicyEngine: policyEngine,
		ProfileDAO:   profileService.DAO(),
		PortBinder:   portBinder,
		Extractor:    policy.NewX509PolicyExtractor(policy.WithPolicyExtractorZones(zones)),
		Zones:        zones,
	}
}
