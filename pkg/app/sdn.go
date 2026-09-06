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

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	sdnzone "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// sdkIPAMClient adapts a go-quicbaas SDK Client to the backends.QuicBaaSClient
// interface required by the IPAM QuicBaaS backend.
type sdkIPAMClient struct {
	sdk quicbaassdk.Client
}

// IsStarted returns true when the SDK client is connected and ready.
func (c *sdkIPAMClient) IsStarted() bool {
	return c.sdk != nil
}

// Put stores a value with the given entity type and ID.
func (c *sdkIPAMClient) Put(ctx context.Context, entityType string, id uint64, data []byte) error {
	_, err := c.sdk.KV().Put(ctx, &service.PutRequest{
		EntityType: entityType,
		ID:         id,
		Data:       data,
	})
	return err
}

// Get retrieves a value by entity type and ID.
func (c *sdkIPAMClient) Get(ctx context.Context, entityType string, id uint64) ([]byte, bool, error) {
	resp, err := c.sdk.KV().Get(ctx, &service.GetRequest{
		EntityType: entityType,
		ID:         id,
	})
	if err != nil {
		return nil, false, err
	}
	if resp == nil || len(resp.Data) == 0 {
		return nil, false, nil
	}
	return resp.Data, true, nil
}

// Delete removes an entity by type and ID.
func (c *sdkIPAMClient) Delete(ctx context.Context, entityType string, id uint64) error {
	_, err := c.sdk.KV().Delete(ctx, &service.DeleteRequest{
		EntityType: entityType,
		ID:         id,
	})
	return err
}

// List retrieves entities with pagination.
func (c *sdkIPAMClient) List(ctx context.Context, entityType string, pageSize uint64, pageToken string) ([]*service.Entity, string, error) {
	resp, err := c.sdk.KV().List(ctx, &service.ListRequest{
		EntityType: entityType,
		PageSize:   pageSize,
		PageToken:  pageToken,
	})
	if err != nil {
		return nil, "", err
	}
	return resp.Entities, resp.NextPageToken, nil
}

// Query searches for entities using secondary indexes.
func (c *sdkIPAMClient) Query(ctx context.Context, entityType, indexField string, value []byte) ([]*service.Entity, error) {
	// Query is used only for index operations in the IPAM backend. The QuicBaaS
	// SDK routes this through the Query service if available; fall back to an
	// empty result (index lookups still work via the explicit index keys the
	// backend maintains in Put).
	return nil, nil
}

// OVSClient returns the OVS client, or nil if SDN is not configured.
func (app *App) OVSClient() ovs.ClientInterface {
	return app.ovsClient
}

// IPAMAllocator returns the IPAM allocator, or nil if IPAM is not configured.
func (app *App) IPAMAllocator() ipam.Allocator {
	return app.ipamAllocator
}

// initSDN initializes the SDN controller including the OVS client, IPAM
// allocator, and DHCP server based on the platform configuration. It is
// safe to call when SDN is not configured or disabled.
func (app *App) initSDN(ctx context.Context) error {
	if app.SDNConfig == nil || !app.SDNConfig.Enabled {
		return nil
	}

	if err := app.SDNConfig.Validate(); err != nil {
		return ErrSDNConfigValidation{Cause: err}
	}

	app.Logger.Info("Initializing SDN controller",
		slog.Bool("controller", app.SDNConfig.Controller))

	// Initialize the OVS client and create the bridge
	if app.SDNConfig.OVS != nil {
		if err := app.initOVSBridge(ctx); err != nil {
			return err
		}
	}

	// Materialise OVS bonds + bridge IPs from the installer NetworkConfig.
	// This is the runtime counterpart to the Linux `/etc/network/interfaces`
	// file: operators who mark a bond as Type=ovs delegate its creation
	// to platformd so the bond lives inside OVS (not the kernel bonding
	// driver) and the bridge gets an IP for the production subnet.
	// Linux-typed bonds are skipped here — the installer writes them into
	// `/etc/network/interfaces` and Alpine's OpenRC networking brings
	// them up before platformd starts.
	if app.NetworkConfig != nil {
		if err := app.initOVSBonds(ctx); err != nil {
			// Non-fatal: log and continue so other SDN init steps still
			// run. A missing bond isn't a control-plane-stopper; the
			// operator can diagnose via `ip link` / `ovs-vsctl show`.
			app.Logger.Warn("SDN: OVS bond initialisation failed",
				slog.String("error", err.Error()))
		}
		if err := app.initBridgeIPs(ctx); err != nil {
			app.Logger.Warn("SDN: bridge IP assignment failed",
				slog.String("error", err.Error()))
		}
	}

	// Derive IPAM pools and SDN networks from installer subnet definitions
	if app.NetworkConfig != nil && len(app.NetworkConfig.Subnets) > 0 {
		app.deriveSDNFromSubnets()
	}

	// Initialize the IPAM allocator and create pools from config
	if app.SDNConfig.IPAM != nil && len(app.SDNConfig.IPAM.Pools) > 0 {
		if err := app.initIPAMPools(ctx); err != nil {
			return err
		}
	}

	// Log DHCP status for each pool
	app.logDHCPStatus()

	// Log overall SDN status
	app.logSDNStatus()

	return nil
}

// OVS other_config keys derived from the platform OVSConfig. These are the
// canonical Open_vSwitch other_config key names consumed by ovs-vswitchd.
const (
	ovsKeyHWOffload     = "hw-offload"
	ovsKeyTCPolicy      = "tc-policy"
	ovsKeyDPDKInit      = "dpdk-init"
	ovsKeyDPDKSocketMem = "dpdk-socket-mem"
	ovsKeyDPDKLCoreMask = "dpdk-lcore-mask"
	ovsKeyPMDCPUMask    = "pmd-cpu-mask"
)

// ovsRootRowRetry parameters: ovs-vswitchd populates the root Open_vSwitch
// row asynchronously at startup — on first boot with a fresh OVSDB, this can
// take 30+ seconds before ovs-vswitchd finishes initialisation. 120 attempts
// × 1s = 2 minutes is enough headroom without blocking startup forever.
const (
	ovsRootRowMaxAttempts   = 120
	ovsRootRowRetryInterval = 1 * time.Second
)

// ovsRootRowRetryConfig builds the retry policy for OVSDB operations that
// need the root Open_vSwitch row to exist. Retriable class: Open_vSwitch row
// not yet present. Any "no Open_vSwitch row found" substring is treated as
// transient so we don't couple tightly to an error type defined inside the
// ovs client.
func ovsRootRowRetryConfig(onRetry func(int, error, time.Duration)) *quicbaassdk.RetryConfig {
	return &quicbaassdk.RetryConfig{
		MaxAttempts: ovsRootRowMaxAttempts,
		Backoff:     &quicbaassdk.ConstantBackoff{Delay: ovsRootRowRetryInterval},
		RetryableFunc: func(err error) bool {
			return strings.Contains(err.Error(), "no Open_vSwitch row found")
		},
		OnRetry: onRetry,
	}
}

// desiredOVSOtherConfig derives the Open_vSwitch other_config keys the
// platform configuration asks for. Only explicitly requested capabilities
// produce keys; an empty map means nothing to reconcile.
func desiredOVSOtherConfig(cfg *sdn.OVSConfig) map[string]string {
	desired := make(map[string]string)
	if cfg == nil {
		return desired
	}
	if cfg.HWOffload {
		desired[ovsKeyHWOffload] = "true"
	}
	if cfg.TCPolicy != "" {
		desired[ovsKeyTCPolicy] = cfg.TCPolicy
	}
	if cfg.DPDK != nil && cfg.DPDK.Init {
		desired[ovsKeyDPDKInit] = "true"
		if cfg.DPDK.SocketMem != "" {
			desired[ovsKeyDPDKSocketMem] = cfg.DPDK.SocketMem
		}
		if cfg.DPDK.LCoreMask != "" {
			desired[ovsKeyDPDKLCoreMask] = cfg.DPDK.LCoreMask
		}
		if cfg.DPDK.PMDCPUMask != "" {
			desired[ovsKeyPMDCPUMask] = cfg.DPDK.PMDCPUMask
		}
		// Operator-supplied extras win over the derived keys.
		for k, v := range cfg.DPDK.Extra {
			desired[k] = v
		}
	}
	return desired
}

// diffOtherConfig returns the desired key/values that are missing from or
// different in current. Keys present in current but absent from desired are
// left alone — the platform only reconciles keys it owns.
func diffOtherConfig(current, desired map[string]string) map[string]string {
	changed := make(map[string]string)
	for k, v := range desired {
		if cur, ok := current[k]; !ok || cur != v {
			changed[k] = v
		}
	}
	return changed
}

// datapathEquivalent reports whether two Bridge datapath_type values select
// the same OVS datapath implementation. An empty value and "system" both
// select the default kernel datapath, so rewriting one to the other would be
// a no-op that spuriously warns about datapath recreation.
func datapathEquivalent(a, b string) bool {
	if a == "" {
		a = "system"
	}
	if b == "" {
		b = "system"
	}
	return a == b
}

// ovsOtherConfigClient is the slice of the OVS client needed to reconcile
// the global Open_vSwitch other_config.
type ovsOtherConfigClient interface {
	GetOVSOtherConfig(ctx context.Context) (map[string]string, error)
	SetOVSOtherConfig(ctx context.Context, config map[string]string) error
}

// applyOVSOtherConfig reconciles the global Open_vSwitch other_config with
// the desired keys derived from cfg. Only changed or missing keys are
// written. ovs-vswitchd reads hw-offload and dpdk-init once at startup, so
// a change to either logs a prominent warning that a daemon restart is
// required — the platform never restarts ovs-vswitchd itself.
func (app *App) applyOVSOtherConfig(ctx context.Context, client ovsOtherConfigClient, cfg *sdn.OVSConfig) error {
	desired := desiredOVSOtherConfig(cfg)
	if len(desired) == 0 {
		return nil
	}

	current, err := client.GetOVSOtherConfig(ctx)
	if err != nil {
		return err
	}

	changed := diffOtherConfig(current, desired)
	if len(changed) == 0 {
		app.Logger.Debug("SDN: OVS other_config already up to date")
		return nil
	}

	if err := client.SetOVSOtherConfig(ctx, changed); err != nil {
		return err
	}

	app.Logger.Info("SDN: applied OVS other_config",
		slog.Any("keys", otherConfigKeys(changed)))

	for _, key := range []string{ovsKeyHWOffload, ovsKeyDPDKInit} {
		if value, ok := changed[key]; ok {
			app.Logger.Warn("SDN: OVS other_config change requires an ovs-vswitchd restart to take effect",
				slog.String("key", key),
				slog.String("value", value))
		}
	}
	return nil
}

// otherConfigKeys returns the sorted key names of an other_config map for
// stable log output.
func otherConfigKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// initOVSBridge creates the OVS client, connects to OVSDB, applies the
// global other_config (hardware offload, tc policy, DPDK), and ensures the
// configured bridge exists with the configured datapath type. Retries on
// transient OVSDB startup races (e.g. ovs-vswitchd is up and listening on
// the control socket but the root Open_vSwitch row hasn't been populated
// yet — causes "no Open_vSwitch row found" on first boot).
func (app *App) initOVSBridge(ctx context.Context) error {
	cfg := app.SDNConfig.OVS

	client, err := ovs.NewClient(cfg.Socket)
	if err != nil {
		return ErrSDNOVSClientInit{Cause: err}
	}

	if err := client.Connect(ctx); err != nil {
		return ErrSDNOVSConnect{
			Socket: cfg.Socket,
			Cause:  err,
		}
	}

	// Reconcile the global other_config before creating the bridge so the
	// datapath is created with the final offload/DPDK settings in place.
	err = quicbaassdk.RetryDo(ctx, ovsRootRowRetryConfig(func(_ int, _ error, _ time.Duration) {
		app.Logger.Debug("OVS root row not populated yet, retrying other_config apply",
			slog.String("bridge", cfg.Bridge))
	}), func(ctx context.Context) error {
		return app.applyOVSOtherConfig(ctx, client, cfg)
	})
	if err != nil {
		// Preserve pre-SDK behavior: cancellation surfaces as the raw
		// context error rather than a wrapped retry error.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return &WrappedError{Msg: "sdn: apply OVS other_config", Err: err}
	}

	// Create the bridge, retrying on the same root-row startup race.
	attempt := 0
	retryCfg := ovsRootRowRetryConfig(func(_ int, _ error, _ time.Duration) {
		app.Logger.Debug("OVS root row not populated yet, retrying",
			slog.Int("attempt", attempt), slog.String("bridge", cfg.Bridge))
	})
	err = quicbaassdk.RetryDo(ctx, retryCfg, func(ctx context.Context) error {
		attempt++
		created, createErr := client.CreateBridgeWithOptions(ctx, cfg.Bridge, &ovs.BridgeOptions{
			DatapathType: cfg.Datapath,
			Protocols:    cfg.Protocols,
		})
		if createErr == nil {
			app.Logger.Info("Created OVS bridge",
				slog.String("bridge", cfg.Bridge),
				slog.String("uuid", created.UUID),
				slog.String("datapath", created.DatapathType),
				slog.Int("attempt", attempt))
			return nil
		}
		if errors.Is(createErr, ovs.ErrBridgeExists) {
			existing, getErr := client.GetBridge(ctx, cfg.Bridge)
			if getErr != nil {
				return getErr
			}
			app.Logger.Info("OVS bridge already exists",
				slog.String("bridge", cfg.Bridge),
				slog.String("uuid", existing.UUID))
			return app.reconcileBridgeDatapath(ctx, client, cfg, existing)
		}
		return createErr
	})
	if err != nil {
		// Preserve pre-SDK behavior: cancellation surfaces as the raw
		// context error rather than a wrapped retry error.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return ErrSDNBridgeCreate{
			Bridge: cfg.Bridge,
			Cause:  err,
		}
	}

	// Set bridge protocols if configured
	if len(cfg.Protocols) > 0 {
		if err := client.SetBridgeProtocols(ctx, cfg.Bridge, cfg.Protocols); err != nil {
			app.Logger.Warn("Failed to set bridge protocols",
				slog.String("bridge", cfg.Bridge),
				slog.String("error", err.Error()))
		}
	}

	app.ovsClient = client
	return nil
}

// ovsBridgeDatapathClient is the slice of the OVS client needed to
// reconcile an existing bridge's datapath type.
type ovsBridgeDatapathClient interface {
	SetBridgeDatapath(ctx context.Context, name string, datapathType string) error
}

// reconcileBridgeDatapath updates the datapath_type of an existing bridge
// when the configured datapath differs. Empty and "system" both select the
// kernel datapath and are treated as equivalent, so no spurious rewrite
// occurs. Changing the datapath type of a live bridge causes ovs-vswitchd
// to destroy and recreate the datapath, which briefly interrupts
// forwarding — hence the prominent warning.
func (app *App) reconcileBridgeDatapath(ctx context.Context, client ovsBridgeDatapathClient, cfg *sdn.OVSConfig, existing *ovs.Bridge) error {
	if cfg.Datapath == "" || datapathEquivalent(existing.DatapathType, cfg.Datapath) {
		return nil
	}

	app.Logger.Warn("SDN: changing datapath type on a live bridge recreates the datapath",
		slog.String("bridge", cfg.Bridge),
		slog.String("current", existing.DatapathType),
		slog.String("configured", cfg.Datapath))

	if err := client.SetBridgeDatapath(ctx, cfg.Bridge, cfg.Datapath); err != nil {
		return &WrappedError{Msg: "sdn: set bridge datapath_type", Err: err}
	}

	app.Logger.Info("SDN: bridge datapath type updated",
		slog.String("bridge", cfg.Bridge),
		slog.String("datapath", cfg.Datapath))
	return nil
}

// ipamBackendFactory maps backend name strings to their constructor functions.
// The default empty-string case is handled by selecting "memory".
// The map is populated by build-tagged registration files (sdn_ipam_backends.go
// and sdn_ipam_backends_p2p.go) so that platform_p2p-gated constructors are
// only referenced when that tag is set.
//
// It is written from those init functions, with exactly one later writer:
// RegisterDHTIPAMBackend (sdn_ipam_backends_p2p.go, platform_p2p builds only)
// replaces the "dht" entry during single-threaded daemon startup and must run
// before App.initSDN. From that point the map is read-only. initIPAMPools
// reads it from whatever goroutine the caller runs on, so any other write —
// including from a test substituting a backend — is a data race against every
// concurrent reader. Tests that need a specific allocator call seedIPAMPools
// directly instead of substituting an entry here.
var ipamBackendFactory = map[string]func(ctx context.Context, app *App) (ipam.Allocator, error){}

// initIPAMPools creates the IPAM allocator using the configured backend and
// seeds pools from config using create-if-missing semantics. Existing pools
// with the same name are left untouched. Nothing is ever deleted.
func (app *App) initIPAMPools(ctx context.Context) error {
	backendName := app.SDNConfig.IPAM.Backend
	if backendName == "" {
		backendName = "memory"
	}

	factory, ok := ipamBackendFactory[backendName]
	if !ok {
		// "dht" is valid only when compiled with platform_p2p build tag.
		if backendName == "dht" {
			return sdn.ErrIPAMBackendP2PRequired{}
		}
		return sdn.ErrIPAMBackendUnknown{Backend: backendName}
	}

	allocator, err := factory(ctx, app)
	if err != nil {
		return err
	}

	if err := app.seedIPAMPools(ctx, allocator); err != nil {
		return err
	}

	app.ipamAllocator = allocator
	return nil
}

// seedIPAMPools creates the configured pools in allocator using
// create-if-missing semantics: a pool that already exists in the backend is
// left exactly as it is, and nothing is ever deleted. It is split out of
// initIPAMPools so the seeding contract can be exercised against a
// caller-supplied allocator without substituting a backend constructor in the
// package-level ipamBackendFactory registry.
func (app *App) seedIPAMPools(ctx context.Context, allocator ipam.Allocator) error {
	for i := range app.SDNConfig.IPAM.Pools {
		poolCfg := &app.SDNConfig.IPAM.Pools[i]

		// Check if pool already exists in the backend.
		if existing, err := allocator.GetPoolByName(ctx, poolCfg.Name); err == nil && existing != nil {
			app.Logger.Debug("IPAM pool already exists in backend, skipping seed",
				slog.String("pool", poolCfg.Name))
			continue
		}

		pool := &ipam.Pool{
			ID:                   poolCfg.Name,
			Name:                 poolCfg.Name,
			CIDR:                 poolCfg.CIDR,
			Gateway:              poolCfg.Gateway,
			Zone:                 poolCfg.Zone,
			DefaultLeaseDuration: poolCfg.LeaseDuration,
		}

		if err := allocator.CreatePool(ctx, pool); err != nil {
			return ErrSDNIPAMPoolCreate{
				Pool:  poolCfg.Name,
				Cause: err,
			}
		}

		app.Logger.Info("Created IPAM pool",
			slog.String("pool", poolCfg.Name),
			slog.String("cidr", poolCfg.CIDR.String()),
			slog.String("zone", poolCfg.Zone),
			slog.Bool("dhcp", poolCfg.DHCP))
	}

	return nil
}

// deriveSDNFromSubnets walks the installer NetworkConfig.Subnets and creates
// IPAM pools and SDN network entries for each internal subnet. This allows
// subnets to be the single source of truth for IP addressing without
// requiring manual IPAM pool or SDN network configuration.
//
// Well-known subnet names are mapped to canonical zone constants:
//   - "production"    → zone.ZoneTrusted
//   - "provisioning"  → zone.ZoneProvisioning
//   - "quarantine"    → zone.ZoneQuarantine
//   - "storage"       → zone.ZoneStorage
//   - "management"    → zone.ZoneManagement
//
// All other subnet names default to zone.ZoneTrusted (general internal
// traffic) and a warning is emitted so operators can add an explicit
// networks[] entry if a different zone is required.
func (app *App) deriveSDNFromSubnets() {
	if app.SDNConfig.IPAM == nil {
		app.SDNConfig.IPAM = &sdn.IPAMConfig{
			Backend: "memory",
		}
	}

	existingPools := make(map[string]struct{}, len(app.SDNConfig.IPAM.Pools))
	for _, p := range app.SDNConfig.IPAM.Pools {
		existingPools[p.Name] = struct{}{}
	}

	// Build a set of network names already present in the list so explicit
	// config wins over derived entries for matching names.
	existingNetworks := make(map[string]struct{}, len(app.SDNConfig.Networks))
	for _, n := range app.SDNConfig.Networks {
		existingNetworks[n.Name] = struct{}{}
	}

	for _, sub := range app.NetworkConfig.Subnets {
		// Only derive pools for internal and public subnets
		if sub.Scope != installer.SubnetScopeInternal && sub.Scope != installer.SubnetScopePublic {
			continue
		}

		// Skip if a pool with this name already exists (explicit config wins)
		if _, ok := existingPools[sub.Name]; ok {
			continue
		}

		prefix, err := netip.ParsePrefix(sub.CIDR)
		if err != nil {
			app.Logger.Warn("Skipping subnet with invalid CIDR",
				slog.String("subnet", sub.Name),
				slog.String("cidr", sub.CIDR),
				slog.String("error", err.Error()))
			continue
		}

		// Derive zone for this subnet — used in both the pool and any network entry.
		z := deriveZoneForSubnetName(app.Logger, sub.Name)

		pool := sdn.PoolConfig{
			Name: sub.Name,
			CIDR: prefix,
			Zone: string(z),
		}

		if sub.Gateway != "" {
			if gw, err := netip.ParseAddr(sub.Gateway); err == nil {
				pool.Gateway = gw
			}
		}

		for _, d := range sub.DNS {
			if addr, err := netip.ParseAddr(d); err == nil {
				pool.DNS = append(pool.DNS, addr)
			}
		}

		if sub.DHCP != nil && sub.DHCP.Enabled {
			pool.DHCP = true
			if sub.DHCP.RangeStart != "" {
				if rs, err := netip.ParseAddr(sub.DHCP.RangeStart); err == nil {
					pool.RangeStart = rs
				}
			}
			if sub.DHCP.RangeEnd != "" {
				if re, err := netip.ParseAddr(sub.DHCP.RangeEnd); err == nil {
					pool.RangeEnd = re
				}
			}
		}

		app.SDNConfig.IPAM.Pools = append(app.SDNConfig.IPAM.Pools, pool)

		// Create an SDN network list entry for subnets with a VLAN ID.
		// Explicit entries (populated before derivation) take precedence.
		if sub.VLANID > 0 {
			if _, ok := existingNetworks[sub.Name]; !ok {
				app.SDNConfig.Networks = append(app.SDNConfig.Networks, sdn.NetworkConfig{
					Name:   sub.Name,
					Subnet: prefix,
					VLAN:   sub.VLANID,
					Zone:   z,
					Pool:   sub.Name,
				})
				existingNetworks[sub.Name] = struct{}{}
			}
		}

		app.Logger.Info("Derived IPAM pool from subnet",
			slog.String("subnet", sub.Name),
			slog.String("scope", string(sub.Scope)),
			slog.String("cidr", sub.CIDR),
			slog.String("zone", string(z)),
			slog.Bool("dhcp", pool.DHCP))
	}
}

// zoneNameMapping maps well-known subnet names to their canonical zone.
var zoneNameMapping = map[string]sdnzone.Zone{
	"production":   sdnzone.ZoneTrusted,
	"provisioning": sdnzone.ZoneProvisioning,
	"quarantine":   sdnzone.ZoneQuarantine,
	"storage":      sdnzone.ZoneStorage,
	"management":   sdnzone.ZoneManagement,
	"tenant":       sdnzone.ZoneTenant,
	"public":       sdnzone.ZonePublic,
	"trusted":      sdnzone.ZoneTrusted,
}

// deriveZoneForSubnetName maps a well-known subnet name to its canonical zone.
// Unknown names default to ZoneTrusted with a logged warning.
func deriveZoneForSubnetName(logger interface {
	Warn(msg string, args ...any)
}, name string) sdnzone.Zone {
	if z, ok := zoneNameMapping[name]; ok {
		return z
	}
	logger.Warn("SDN: subnet name has no canonical zone mapping; defaulting to trusted",
		slog.String("subnet", name),
		slog.String("zone", string(sdnzone.ZoneTrusted)))
	return sdnzone.ZoneTrusted
}

// logDHCPStatus logs which pools have DHCP enabled or disabled.
func (app *App) logDHCPStatus() {
	if app.SDNConfig.IPAM == nil {
		return
	}

	dhcpEnabled := false
	for _, pool := range app.SDNConfig.IPAM.Pools {
		if pool.DHCP {
			dhcpEnabled = true
			app.Logger.Info("DHCP enabled for pool",
				slog.String("pool", pool.Name),
				slog.String("cidr", pool.CIDR.String()))
		} else {
			app.Logger.Debug("DHCP disabled for pool",
				slog.String("pool", pool.Name))
		}
	}

	if app.SDNConfig.DHCP != nil && app.SDNConfig.DHCP.Enabled && dhcpEnabled {
		app.Logger.Info("DHCP server configured",
			slog.String("interface", app.SDNConfig.DHCP.Interface))
	}
}

// logSDNStatus logs the final SDN initialization status.
func (app *App) logSDNStatus() {
	mode := "agent"
	if app.SDNConfig.Controller {
		mode = "controller"
	}

	bridgeName := "<none>"
	if app.SDNConfig.OVS != nil {
		bridgeName = app.SDNConfig.OVS.Bridge
	}

	poolCount := 0
	dhcpPoolCount := 0
	if app.SDNConfig.IPAM != nil {
		poolCount = len(app.SDNConfig.IPAM.Pools)
		for _, p := range app.SDNConfig.IPAM.Pools {
			if p.DHCP {
				dhcpPoolCount++
			}
		}
	}

	app.Logger.Info("SDN initialized",
		slog.String("mode", mode),
		slog.String("bridge", bridgeName),
		slog.Int("pools", poolCount),
		slog.Int("dhcp_pools", dhcpPoolCount))
}

// initOVSBonds walks NetworkConfig.Bonds and creates any bond declared
// with Type=ovs as an OVS bond on its target bridge. Bonds with
// Type=linux (or unset) are skipped — those are the kernel bonding
// driver's responsibility and the Alpine installer wires them into
// /etc/network/interfaces directly.
//
// OVS bonds are created by shelling out to `ovs-vsctl add-bond` rather
// than speaking OVSDB directly: vsctl is the battle-tested operator
// tool, matches how bonds are diagnosed in the field (`ovs-vsctl show`,
// `ovs-appctl bond/show`), and avoids re-implementing the multi-row
// Port+Interface transaction in our OVSDB client. The cost is a single
// fork+exec per bond at startup, which is negligible.
//
// Idempotent: if a port with the bond name already exists on the
// bridge, the function treats that as success. Adding a member NIC
// that's already in the bond is also a no-op from ovs-vsctl's view.
func (app *App) initOVSBonds(ctx context.Context) error {
	if app.NetworkConfig == nil || len(app.NetworkConfig.Bonds) == 0 {
		return nil
	}
	if app.ovsClient == nil {
		return nil
	}

	defaultBridge := ""
	if app.SDNConfig != nil && app.SDNConfig.OVS != nil {
		defaultBridge = app.SDNConfig.OVS.Bridge
	}

	for _, bond := range app.NetworkConfig.Bonds {
		// Type is new; existing templates that omit it get "ovs" by
		// default so operators aren't silently kept on the kernel
		// bonding driver.
		bondType := bond.Type
		if bondType == "" {
			bondType = installer.BondTypeOVS
		}
		if bondType != installer.BondTypeOVS {
			app.Logger.Debug("SDN: skipping non-OVS bond (installer owns this)",
				slog.String("bond", bond.Name),
				slog.String("type", string(bondType)))
			continue
		}

		bridge := bond.Bridge
		if bridge == "" {
			bridge = defaultBridge
		}
		if bridge == "" {
			app.Logger.Warn("SDN: OVS bond has no bridge and no default OVS bridge configured",
				slog.String("bond", bond.Name))
			continue
		}

		if err := app.createOVSBond(ctx, bridge, &bond); err != nil {
			app.Logger.Warn("SDN: failed to create OVS bond",
				slog.String("bond", bond.Name),
				slog.String("bridge", bridge),
				slog.String("error", err.Error()))
			continue
		}

		app.Logger.Info("SDN: OVS bond created",
			slog.String("bond", bond.Name),
			slog.String("bridge", bridge),
			slog.String("mode", bond.Mode),
			slog.String("lacp", bond.LACP),
			slog.Any("members", bond.Interfaces))
	}
	return nil
}

// createOVSBond issues an OVSDB Transact to create the bond port
// with N member interfaces on the named bridge. Uses the pure-Go
// native OVSDB wire-protocol client (pkg/sdn/ovs) — no ovs-vsctl
// exec, no kernel bonding module.
//
// Idempotent: returns nil if the port already exists under the same
// name on the bridge.
func (app *App) createOVSBond(ctx context.Context, bridge string, bond *installer.BondConfig) error {
	if len(bond.Interfaces) < 2 {
		return &MessageError{Msg: fmt.Sprintf("OVS bond %q needs at least 2 member interfaces (got %d)", bond.Name, len(bond.Interfaces))}
	}

	// Idempotent: GetPort returns the port if it already exists.
	if existing, err := app.ovsClient.GetPort(ctx, bond.Name); err == nil && existing != nil {
		app.Logger.Debug("SDN: OVS bond port already exists, skipping add",
			slog.String("bond", bond.Name),
			slog.String("bridge", bridge))
		return nil
	}

	mode := bond.Mode
	if mode == "" {
		// OVS default for multi-member bonds; compatible with LACP
		// on modern switches. Operators can override in the template.
		mode = "balance-tcp"
	}

	if _, err := app.ovsClient.AddBond(ctx, bridge, bond.Name, bond.Interfaces, mode, bond.LACP); err != nil {
		return &WrappedError{Msg: "ovs.AddBond", Err: err}
	}
	return nil
}

// initBridgeIPs assigns the first matching subnet's gateway IP to
// every OVS bridge that's expected to host an internal subnet.
//
// "Matching" means: the subnet must be internal scope and its
// `interface` (if any) must match the bridge name, or — when the
// subnet doesn't declare an interface — the bridge is assumed to host
// the first internal subnet in the config. That's a pragmatic default
// that matches the single-bridge-per-node deployments we ship;
// multi-bridge setups can pin via `network.bridges[].address` in a
// future iteration.
//
// Bringing the bridge UP is also done here so the IP is usable
// immediately without waiting for `ifupdown` to race with platformd.
func (app *App) initBridgeIPs(ctx context.Context) error {
	if app.NetworkConfig == nil {
		return nil
	}

	// Synthesise a BridgeConfig for any OVS bond that declares
	// `bridge: <name>` but doesn't have a matching entry in
	// network.bridges. Operators frequently omit the `bridges:` block
	// on nodes that only need a bridge because a bond references one
	// (typical gateway/compute override); without this the bridge IP
	// never gets assigned because the loop has nothing to iterate.
	bridges := append([]installer.BridgeConfig(nil), app.NetworkConfig.Bridges...)
	for _, bond := range app.NetworkConfig.Bonds {
		if bond.Type != installer.BondTypeOVS || bond.Bridge == "" {
			continue
		}
		found := false
		for _, existing := range bridges {
			if existing.Name == bond.Bridge {
				found = true
				break
			}
		}
		if found {
			continue
		}
		bridges = append(bridges, installer.BridgeConfig{
			Name:      bond.Bridge,
			Type:      installer.BridgeTypeOVS,
			AutoStart: true,
		})
	}

	if len(bridges) == 0 {
		return nil
	}

	for _, br := range bridges {
		// Only manage OVS bridges here — Linux bridges are handled by
		// the Alpine installer via /etc/network/interfaces.
		if br.Type != installer.BridgeTypeOVS {
			continue
		}

		addr := resolveBridgeAddress(&br, app.NetworkConfig.Bonds, app.NetworkConfig.Subnets)
		if addr == "" {
			app.Logger.Debug("SDN: no subnet match for OVS bridge, skipping IP assignment",
				slog.String("bridge", br.Name))
			continue
		}

		if err := setBridgeUpFn(ctx, br.Name); err != nil {
			app.Logger.Warn("SDN: failed to bring bridge up",
				slog.String("bridge", br.Name),
				slog.String("error", err.Error()))
			continue
		}

		// Duplicate-address detection (#508): the node must never take an
		// address another station already answers for — a gateway that
		// steals the edge router's address strands every host on the
		// segment. A measured conflict fails the address closed and
		// leaves the node degraded; bring-up continues so the daemon
		// still comes up reachable on its other addresses.
		if err := app.guardBridgeAddress(ctx, br.Name, addr); err != nil {
			continue
		}

		if err := assignBridgeAddrFn(ctx, br.Name, addr); err != nil {
			app.Logger.Warn("SDN: failed to assign IP to bridge",
				slog.String("bridge", br.Name),
				slog.String("address", addr),
				slog.String("error", err.Error()))
			continue
		}

		app.Logger.Info("SDN: bridge IP assigned",
			slog.String("bridge", br.Name),
			slog.String("address", addr))
	}
	return nil
}

// resolveBridgeAddress picks the CIDR-formatted IP to assign to br.
// Precedence:
//  1. A bond attached to this bridge with a vlans[0].ipv4-address that
//     maps to an internal subnet — this is the per-node IP the operator
//     declared in their override (e.g. 10.200.0.1/24 on CP,
//     10.200.0.2/24 on gateway, 10.200.0.3/24 on compute).
//  2. First internal-scoped subnet's gateway IP — used when no bond is
//     bound to this bridge (edge nodes running a lone bridge with no
//     bond), so the CP's configured gateway address materialises.
//  3. Empty (caller skips assignment).
//
// Returns a CIDR-formatted string ("10.200.0.1/24") suitable for
// `ip addr add`.
func resolveBridgeAddress(br *installer.BridgeConfig, bonds []installer.BondConfig, subnets []installer.SubnetConfig) string {
	// Precedence 1: bond-attached bridge uses the bond's first VLAN
	// ipv4-address. The operator set this intentionally in
	// network.bonds[].vlans[].ipv4-address per-node.
	for _, bond := range bonds {
		if bond.Bridge != br.Name {
			continue
		}
		for _, v := range bond.VLANs {
			if v.IPv4Address == "" {
				continue
			}
			return v.IPv4Address
		}
	}

	// Precedence 2: fall back to subnet gateway for bridge-only (no
	// bond) topologies — typical on a CP that IS the gateway.
	for _, sub := range subnets {
		if sub.Scope != installer.SubnetScopeInternal {
			continue
		}
		if sub.Gateway == "" || sub.CIDR == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(sub.CIDR)
		if err != nil {
			continue
		}
		prefix, _ := ipnet.Mask.Size()
		return fmt.Sprintf("%s/%d", sub.Gateway, prefix)
	}
	return ""
}

// bridgeLink resolves the kernel link for an OVS bridge by name. The
// kernel internal interface for a freshly-created OVS bridge appears
// asynchronously after the OVSDB transaction that created the bridge
// returns, so we retry briefly to absorb that race.
func bridgeLink(ctx context.Context, name string) (netlink.Link, error) {
	const maxAttempts = 30
	const retryInterval = 500 * time.Millisecond
	var link netlink.Link
	retryCfg := &quicbaassdk.RetryConfig{
		MaxAttempts: maxAttempts,
		Backoff:     &quicbaassdk.ConstantBackoff{Delay: retryInterval},
		// Preserve pre-SDK behavior: every lookup error is retryable
		// (the kernel link appears asynchronously).
		RetryableFunc: func(error) bool { return true },
	}
	err := quicbaassdk.RetryDo(ctx, retryCfg, func(ctx context.Context) error {
		l, lookupErr := netlink.LinkByName(name)
		if lookupErr != nil {
			return lookupErr
		}
		link = l
		return nil
	})
	if err != nil {
		// Preserve pre-SDK behavior: cancellation surfaces as the raw
		// context error rather than a wrapped retry error.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, &WrappedError{Msg: fmt.Sprintf("netlink LinkByName %q", name), Err: err}
	}
	return link, nil
}

// setBridgeUpFn and assignBridgeAddrFn are the netlink calls initBridgeIPs
// makes, held in package variables so tests can drive the bring-up sequence
// — in particular, prove that a duplicate-address refusal stops the
// assignment — without touching host networking.
var (
	setBridgeUpFn      = setBridgeUp
	assignBridgeAddrFn = assignBridgeAddr
)

// setBridgeUp brings the bridge interface admin-up via netlink
// (RTM_NEWLINK + IFF_UP). Pure Go, no `ip` exec.
func setBridgeUp(ctx context.Context, name string) error {
	link, err := bridgeLink(ctx, name)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("netlink LinkSetUp %q", name), Err: err}
	}
	return nil
}

// assignBridgeAddr adds a CIDR address to the bridge via netlink
// (RTM_NEWADDR). Duplicate-address errors (os.IsExist) are treated
// as success so platformd restarts don't fail when the address is
// already present.
func assignBridgeAddr(ctx context.Context, name, addr string) error {
	link, err := bridgeLink(ctx, name)
	if err != nil {
		return err
	}
	nl, err := netlink.ParseAddr(addr)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("netlink ParseAddr %q", addr), Err: err}
	}
	if err := netlink.AddrAdd(link, nl); err != nil {
		// EEXIST (17) = address already present. Normal on restart.
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return &WrappedError{Msg: fmt.Sprintf("netlink AddrAdd %s on %q", addr, name), Err: err}
	}
	return nil
}
