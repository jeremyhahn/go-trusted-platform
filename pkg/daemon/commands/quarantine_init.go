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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// deviceStateStoreAdapter adapts device.DeviceService to the
// policy.DeviceStateStore interface. It bridges the attestation quarantine
// loop to the real device datastore without coupling the policy package to the
// device package directly.
type deviceStateStoreAdapter struct {
	svc device.DeviceService
}

// SaveDevice persists the device record via the device service.
func (a *deviceStateStoreAdapter) SaveDevice(ctx context.Context, d *entities.Device) error {
	return a.svc.Save(ctx, d)
}

// GetDevice retrieves a device record by ID via the device service.
func (a *deviceStateStoreAdapter) GetDevice(ctx context.Context, id uint64) (*entities.Device, error) {
	return a.svc.Get(ctx, id)
}

// deviceResolverAdapter adapts device.DeviceService to the attestation
// DeviceResolver interface. It maps IDevID host identifiers (CNs / FQDNs
// embedded in attestation manifests) to platform device record IDs so
// observers can work with typed device IDs rather than raw strings.
type deviceResolverAdapter struct {
	svc    device.DeviceService
	logger *slog.Logger
}

// DeviceForHost looks up the device ID for the given host identifier (IDevID
// CN / FQDN). Returns (0, false) when no matching device exists.
func (r *deviceResolverAdapter) DeviceForHost(hostID string) (uint64, bool) {
	d, err := r.svc.FindByHostname(context.Background(), hostID)
	if err != nil {
		r.logger.Debug("quarantine: device not found by hostname",
			slog.String("host_id", hostID),
			slog.String("error", err.Error()))
		return 0, false
	}
	return d.ID, true
}

// quarantineObserver implements the attestation AttestationObserver interface.
// It translates attestation outcomes into ViolationEvents and
// RestoreAttestation calls on the underlying QuarantineManager.
//
// The observer reads device.NetworkPortID from the persisted device record to
// identify the OVS port for quarantine and restore operations. If NetworkPortID
// is empty the event is skipped with a warning because it means the device
// was never activated through the SDN enrollment hook and acting on a guessed
// port name would silently target the wrong (or nonexistent) port.
type quarantineObserver struct {
	manager     *policy.QuarantineManager
	deviceStore policy.DeviceStateStore
	logger      *slog.Logger
}

// OnAttestationFailed translates a failed verification into a ViolationEvent
// and passes it to the QuarantineManager. Events with deviceID == 0 are
// skipped with a warning because no device record was resolved from the host
// identifier, and a ViolationEvent with DeviceID=0 would fail validation.
// Events whose device record has an empty NetworkPortID are also skipped: the
// device was never activated on the SDN fabric and quarantining a fabricated
// port name would silently do nothing or corrupt another port's flows.
func (o *quarantineObserver) OnAttestationFailed(ctx context.Context, deviceID uint64, hostID, detail string) {
	if deviceID == 0 {
		o.logger.Warn("quarantine observer: skipping failed attestation, device unresolvable",
			slog.String("host_id", hostID),
			slog.String("detail", detail))
		return
	}

	portID, ok := o.resolvePortID(ctx, deviceID, hostID)
	if !ok {
		return
	}

	ev := &entities.ViolationEvent{
		DeviceID:   deviceID,
		Severity:   entities.ViolationSeverityWarning,
		Source:     entities.ViolationSourceAttestation,
		Detail:     detail,
		OccurredAt: time.Now().UTC(),
	}

	if err := o.manager.HandleViolation(ctx, ev, portID); err != nil {
		o.logger.Error("quarantine observer: handle violation failed",
			slog.Uint64("device_id", deviceID),
			slog.String("host_id", hostID),
			slog.String("error", err.Error()))
	}
}

// OnAttestationPassed triggers the quarantine restore path for a device that
// has re-attested successfully. Events with deviceID == 0 are skipped with a
// warning for the same reason as OnAttestationFailed.
func (o *quarantineObserver) OnAttestationPassed(ctx context.Context, deviceID uint64, hostID string) {
	if deviceID == 0 {
		o.logger.Warn("quarantine observer: skipping passed attestation, device unresolvable",
			slog.String("host_id", hostID))
		return
	}

	portID, ok := o.resolvePortID(ctx, deviceID, hostID)
	if !ok {
		return
	}

	if err := o.manager.HandleRestoreAttestation(ctx, deviceID, portID); err != nil {
		o.logger.Error("quarantine observer: handle restore failed",
			slog.Uint64("device_id", deviceID),
			slog.String("host_id", hostID),
			slog.String("error", err.Error()))
	}
}

// resolvePortID fetches the device record and returns its NetworkPortID. If the
// record cannot be fetched or NetworkPortID is empty, it logs a warning and
// returns ("", false). Callers must treat false as "skip this event".
func (o *quarantineObserver) resolvePortID(ctx context.Context, deviceID uint64, hostID string) (string, bool) {
	d, err := o.deviceStore.GetDevice(ctx, deviceID)
	if err != nil {
		o.logger.Warn("quarantine observer: could not load device record, skipping event",
			slog.Uint64("device_id", deviceID),
			slog.String("host_id", hostID),
			slog.String("error", err.Error()))
		return "", false
	}
	if d.NetworkPortID == "" {
		o.logger.Warn("quarantine observer: device has no NetworkPortID (never SDN-activated), skipping event",
			slog.Uint64("device_id", deviceID),
			slog.String("host_id", hostID))
		return "", false
	}
	return d.NetworkPortID, true
}

// sdnPolicyComponents bundles the shared SDN flow-policy machinery built once
// at daemon startup and consumed by both the quarantine observer and the SDN
// enrollment hook so they operate on a single engine (one port-policy state).
type sdnPolicyComponents struct {
	Engine          *policy.Engine
	ZoneFlowManager *policy.ZoneFlowManager
	ResolvedZones   []zone.ZoneConfig
}

// initSDNPolicy constructs the shared SDN policy engine, zone flow manager,
// and resolved zone set from the application's SDN configuration. It returns
// nil when SDN is disabled or its prerequisites (OVS client, bridge) are
// unavailable, so boot behavior is unchanged on nodes without OVS.
func initSDNPolicy(a *app.App, slogger *slog.Logger) *sdnPolicyComponents {
	if a == nil {
		return nil
	}

	// SDN must be enabled and validated so we have a resolved zone list.
	if a.SDNConfig == nil || !a.SDNConfig.Enabled {
		return nil
	}
	resolvedZones := a.SDNConfig.ResolvedZones()
	if len(resolvedZones) == 0 {
		// Fall back to built-in zone defaults so the policy machinery
		// functions on configurations that define no custom zones.
		resolvedZones = zone.Defaults()
	}

	// Both ZoneFlowManager and PolicyEngine require a concrete *ovs.Client.
	// If the interface is backed by something else (mock, future transport), we
	// skip wiring and log. This is an explicit guard rather than a silent no-op.
	ovsIface := a.OVSClient()
	if ovsIface == nil {
		slogger.Info("sdn policy: OVS client unavailable, flow policy not initialized")
		return nil
	}
	concreteClient, ok := ovsIface.(*ovs.Client)
	if !ok {
		slogger.Warn("sdn policy: OVS client is not *ovs.Client, flow policy not initialized")
		return nil
	}
	if a.SDNConfig.OVS == nil || a.SDNConfig.OVS.Bridge == "" {
		slogger.Warn("sdn policy: no OVS bridge configured, flow policy not initialized")
		return nil
	}
	bridgeName := a.SDNConfig.OVS.Bridge

	// Construct the shared flow controller.
	fc, err := policy.NewOVSFlowController(concreteClient)
	if err != nil {
		slogger.Error("sdn policy: failed to create flow controller",
			slog.String("error", err.Error()))
		return nil
	}

	// Build a ZoneIndex when network configs are present; ZoneFlowManager
	// falls back to built-in VLAN defaults when ZoneIndex is nil.
	var zoneIdx *sdn.ZoneIndex
	if len(a.SDNConfig.Networks) > 0 {
		zoneIdx, err = sdn.BuildZoneIndex(resolvedZones, a.SDNConfig.Networks)
		if err != nil {
			slogger.Warn("sdn policy: failed to build zone index, using default VLAN mappings",
				slog.String("error", err.Error()))
		}
	}

	zfm, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName:     bridgeName,
		FlowController: fc,
		PortController: fc,
		ZoneIndex:      zoneIdx,
		Zones:          resolvedZones,
		Logger:         slogger,
	})
	if err != nil {
		slogger.Warn("sdn policy: zone flow manager unavailable, zone flow paths disabled",
			slog.String("error", err.Error()))
		zfm = nil
	}

	eng, err := policy.NewEngine(policy.Config{
		BridgeName:      bridgeName,
		FlowController:  fc,
		PortController:  fc,
		ZoneFlowManager: zfm,
		Zones:           resolvedZones,
		Logger:          slogger,
	})
	if err != nil {
		slogger.Error("sdn policy: failed to build policy engine",
			slog.String("error", err.Error()))
		return nil
	}

	slogger.Info("sdn flow policy initialized",
		slog.String("bridge", bridgeName),
		slog.Bool("zone_flow_manager", zfm != nil),
		slog.Int("resolved_zones", len(resolvedZones)))

	return &sdnPolicyComponents{
		Engine:          eng,
		ZoneFlowManager: zfm,
		ResolvedZones:   resolvedZones,
	}
}

// wireQuarantineObserver constructs the QuarantineManager on the shared SDN
// policy components and connects it to the attestation service as an
// observer. It is a no-op when either the attestation service or the SDN
// policy machinery is unavailable, so boot behavior is unchanged on nodes
// without OVS or without attestation storage.
//
// The ZoneFlowManager provides the zone flow enforcement path for
// Warning-severity violations. When unavailable, Severe violations
// (BlockPort) still function; Warning violations will log an error via the
// observer.
func wireQuarantineObserver(
	svcs *attestationServices,
	sdnPolicy *sdnPolicyComponents,
	deviceService device.DeviceService,
	logger *logging.Logger,
) {
	if svcs == nil || svcs.Service == nil {
		return
	}
	if sdnPolicy == nil || sdnPolicy.Engine == nil {
		return
	}
	if deviceService == nil {
		return
	}

	slogger := logger.Slog()

	store := &deviceStateStoreAdapter{svc: deviceService}
	manager, err := policy.NewQuarantineManager(policy.QuarantineManagerConfig{
		PolicyEngine:     sdnPolicy.Engine,
		ZoneFlowManager:  sdnPolicy.ZoneFlowManager,
		ResolvedZones:    sdnPolicy.ResolvedZones,
		DeviceStateStore: store,
		Logger:           slogger,
	})
	if err != nil {
		slogger.Error("quarantine observer: failed to construct manager, observer not registered",
			slog.String("error", err.Error()))
		return
	}

	obs := &quarantineObserver{
		manager:     manager,
		deviceStore: store,
		logger:      slogger,
	}
	resolver := &deviceResolverAdapter{svc: deviceService, logger: slogger}

	svcs.Service.SetDeviceResolver(resolver)
	svcs.Service.RegisterObserver(obs)

	slogger.Info("quarantine observer registered",
		slog.Bool("zone_flow_manager", sdnPolicy.ZoneFlowManager != nil),
		slog.Int("resolved_zones", len(sdnPolicy.ResolvedZones)))
}
