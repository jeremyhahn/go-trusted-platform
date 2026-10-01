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
	"net/netip"
	"slices"
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
	// Every zone path into control-plane or management beyond the
	// reference is an audited override: record it on every load.
	app.SDNConfig.LogPrivilegedPaths(app.Logger.Slog())

	app.Logger.Info("Initializing SDN controller",
		slog.Bool("controller", app.SDNConfig.Controller))

	// Initialize the OVS client and create the bridge
	if app.SDNConfig.OVS != nil {
		if err := app.initOVSBridge(ctx); err != nil {
			return err
		}
	}

	// Materialise OVS bonds + zone addresses from the installer
	// NetworkConfig. This is the runtime counterpart to the Linux
	// `/etc/network/interfaces` file: operators who mark a bond as Type=ovs
	// delegate its creation to platformd so the bond lives inside OVS (not
	// the kernel bonding driver), and every host address the bond declares
	// lands on a tagged internal port of its zone.
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
		if err := app.initZoneAddresses(ctx); err != nil {
			app.Logger.Warn("SDN: zone address assignment failed",
				slog.String("error", err.Error()))
		}
	}

	// The controller owns IPAM: it seeds the plan's pools (one per zone,
	// plus the IPAM ranges) and the explicit sdn.ipam.pools. A node with
	// an explicit ipam section seeds the same set, create-if-missing.
	if app.SDNConfig.Controller || app.SDNConfig.IPAM != nil {
		if err := app.initIPAMPools(ctx); err != nil {
			return err
		}
	}

	// Report which zones this node would serve DHCP on.
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
	backendName := ""
	if app.SDNConfig.IPAM != nil {
		backendName = app.SDNConfig.IPAM.Backend
	}
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

// seedIPAMPools creates the network plan's pools and the explicit
// sdn.ipam.pools in allocator using create-if-missing semantics: a pool that
// already exists in the backend is left exactly as it is, and nothing is
// ever deleted. It is split out of initIPAMPools so the seeding contract can
// be exercised against a caller-supplied allocator without substituting a
// backend constructor in the package-level ipamBackendFactory registry.
func (app *App) seedIPAMPools(ctx context.Context, allocator ipam.Allocator) error {
	pools, err := app.ipamSeedPools()
	if err != nil {
		return err
	}
	for _, pool := range pools {
		if existing, err := allocator.GetPoolByName(ctx, pool.Name); err == nil && existing != nil {
			if drift := poolDrift(existing, pool); drift != nil {
				return drift
			}
			app.Logger.Debug("IPAM pool already exists in backend, skipping seed",
				slog.String("pool", pool.Name))
			continue
		}

		if err := allocator.CreatePool(ctx, pool); err != nil {
			return ErrSDNIPAMPoolCreate{
				Pool:  pool.Name,
				Cause: err,
			}
		}

		app.Logger.Info("Created IPAM pool",
			slog.String("pool", pool.Name),
			slog.String("cidr", pool.CIDR.String()),
			slog.String("zone", pool.Zone))
	}

	return nil
}

// poolDrift compares a stored pool with the pool the seed wants under the
// same name. A pool that matches is kept as stored (seeding never mutates);
// one that differs in prefix, gateway, dynamic window or reserved prefixes
// is a configuration from another network model and is refused loudly
// rather than silently overriding the plan.
func poolDrift(stored, want *ipam.Pool) error {
	same := stored.CIDR == want.CIDR &&
		stored.Gateway == want.Gateway &&
		stored.RangeStart == want.RangeStart &&
		stored.RangeEnd == want.RangeEnd &&
		slices.Equal(stored.Reserved, want.Reserved)
	if same {
		return nil
	}
	describe := func(p *ipam.Pool) string {
		return fmt.Sprintf("cidr %s gateway %s range %s-%s reserved %v",
			p.CIDR, p.Gateway, p.RangeStart, p.RangeEnd, p.Reserved)
	}
	return ErrSDNIPAMPoolDrift{Pool: want.Name, Stored: describe(stored), Plan: describe(want)}
}

// ipamSeedPools returns the pools to seed: the network plan's pools first
// (zone pools carry the zone, the gateway and the reserved gateway address,
// and a dynamic range from .50), then the explicit sdn.ipam.pools.
func (app *App) ipamSeedPools() ([]*ipam.Pool, error) {
	plan := app.SDNConfig.Plan()
	if plan == nil {
		return nil, sdn.ErrEnvironmentRequired{}
	}
	var out []*ipam.Pool
	for _, p := range plan.Pools() {
		out = append(out, &ipam.Pool{
			ID:          p.Name,
			Name:        p.Name,
			CIDR:        p.Prefix,
			Gateway:     p.Gateway,
			Zone:        string(p.Zone),
			Reserved:    p.Reserved,
			RangeStart:  p.RangeStart,
			RangeEnd:    p.RangeEnd,
			Description: "derived from the network plan",
		})
	}
	if app.SDNConfig.IPAM != nil {
		for i := range app.SDNConfig.IPAM.Pools {
			cfg := &app.SDNConfig.IPAM.Pools[i]
			pool := &ipam.Pool{
				ID:                   cfg.Name,
				Name:                 cfg.Name,
				CIDR:                 cfg.CIDR,
				Gateway:              cfg.Gateway,
				Zone:                 cfg.Zone,
				RangeStart:           cfg.RangeStart,
				RangeEnd:             cfg.RangeEnd,
				DefaultLeaseDuration: cfg.LeaseDuration,
			}
			if cfg.Gateway.IsValid() {
				pool.Reserved = []netip.Prefix{netip.PrefixFrom(cfg.Gateway, cfg.Gateway.BitLen())}
			}
			out = append(out, pool)
		}
	}
	return out, nil
}

// dhcpZones returns the zones this node serves DHCP on: a zone whose policy
// lists the "dhcp" service (provisioning and quarantine in the reference),
// and on which this host holds an address (a bond VLAN of that zone). On a
// reference control-plane node the result is empty: the gateway is the host
// addressed on provisioning and quarantine.
func (app *App) dhcpZones() []sdnzone.Zone {
	held := app.heldZones()
	var out []sdnzone.Zone
	for _, z := range app.SDNConfig.ResolvedZones() {
		if _, ok := held[z.Name]; !ok {
			continue
		}
		for _, svc := range z.Services {
			if svc == "dhcp" {
				out = append(out, z.Name)
				break
			}
		}
	}
	return out
}

// heldZones returns the zones this host has an address on, from the bond
// VLANs of the installer network configuration.
func (app *App) heldZones() map[sdnzone.Zone]struct{} {
	held := make(map[sdnzone.Zone]struct{})
	if app.NetworkConfig == nil {
		return held
	}
	for _, bond := range app.NetworkConfig.Bonds {
		for _, v := range bond.VLANs {
			if v.Zone != "" && v.IPv4Address != "" {
				held[sdnzone.Zone(v.Zone)] = struct{}{}
			}
		}
	}
	return held
}

// logDHCPStatus reports the zones this node would serve DHCP on. When
// sdn.dhcp is enabled but no zone qualifies, it says so plainly: the node
// holds no address on a DHCP zone, so it serves nothing.
func (app *App) logDHCPStatus() {
	if app.SDNConfig.DHCP == nil || !app.SDNConfig.DHCP.Enabled {
		return
	}
	zones := app.dhcpZones()
	if len(zones) == 0 {
		app.Logger.Warn("SDN: sdn.dhcp is enabled but this node holds no address on a zone that serves dhcp; it serves no DHCP",
			slog.String("interface", app.SDNConfig.DHCP.Interface))
		return
	}
	for _, z := range zones {
		app.Logger.Info("SDN: DHCP zone",
			slog.String("zone", string(z)),
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

	environment := uint16(0)
	if plan := app.SDNConfig.Plan(); plan != nil {
		environment = plan.Environment().ID
	}

	app.Logger.Info("SDN initialized",
		slog.String("mode", mode),
		slog.String("bridge", bridgeName),
		slog.Int("environment", int(environment)),
		slog.Int("zones", len(app.SDNConfig.ResolvedZones())),
		slog.Int("dhcp_zones", len(app.dhcpZones())))
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

// ErrSDNUnknownZoneAddress is returned when an OVS bond VLAN entry names a
// zone the network plan does not hold, or a bond has no bridge to put the
// zone port on.
type ErrSDNUnknownZoneAddress struct {
	// Bond is the bond declaring the address.
	Bond string
	// Zone is the zone the entry names.
	Zone string
	// NoBridge is set when the zone is known but the bond has no bridge
	// and no default sdn.ovs.bridge exists.
	NoBridge bool
}

// Error implements the error interface.
func (e ErrSDNUnknownZoneAddress) Error() string {
	if e.NoBridge {
		return fmt.Sprintf("app: bond %q address on zone %q has no OVS bridge (set bonds[].bridge or sdn.ovs.bridge)", e.Bond, e.Zone)
	}
	return fmt.Sprintf("app: bond %q declares an address on zone %q, which the network plan does not hold", e.Bond, e.Zone)
}

// ErrSDNDuplicateZoneAddress is returned when two bond VLAN entries hold an
// address on the same zone: a host has one zone<VLAN> port per zone, so the
// second address would silently land on the first entry's port.
type ErrSDNDuplicateZoneAddress struct {
	// Zone is the zone named twice.
	Zone string
	// Bonds are the two bonds naming it (they may be the same bond).
	Bonds [2]string
}

// Error implements the error interface.
func (e ErrSDNDuplicateZoneAddress) Error() string {
	return fmt.Sprintf("app: zone %q holds addresses on both bond %q and bond %q; a host addresses each zone once",
		e.Zone, e.Bonds[0], e.Bonds[1])
}

// ErrSDNIPAMPoolDrift is returned when the backend already holds a pool under
// a plan pool's name but with a different prefix, gateway or window — for
// example a pool left by an earlier network model. Pre-release there is no
// migration: wipe the IPAM store and re-bootstrap.
type ErrSDNIPAMPoolDrift struct {
	// Pool is the pool name.
	Pool string
	// Stored describes the pool the backend holds.
	Stored string
	// Plan describes the pool the network plan derives.
	Plan string
}

// Error implements the error interface.
func (e ErrSDNIPAMPoolDrift) Error() string {
	return fmt.Sprintf("app: ipam pool %q in the store (%s) differs from the network plan (%s); "+
		"the pre-release upgrade path is to wipe the IPAM store and re-bootstrap", e.Pool, e.Stored, e.Plan)
}

// zonePortName returns the OVS internal port that carries a host address
// on VLAN vlan: "zone<VLAN>" (zone406), at most 8 characters, well inside
// IFNAMSIZ.
func zonePortName(vlan uint16) string {
	return fmt.Sprintf("zone%d", vlan)
}

// zoneAddress is one host address to realise on a zone's internal port.
type zoneAddress struct {
	bridge string
	port   string
	vlan   uint16
	addr   string
}

// zoneAddresses resolves every OVS bond VLAN entry {zone, ipv4-address} of
// the installer network configuration into the internal port, bridge and
// VLAN that carry it. The bridge's own internal interface never gets an
// address: an untagged address there would land on the trunk's native
// VLAN (provisioning).
func (app *App) zoneAddresses() ([]zoneAddress, error) {
	plan := app.SDNConfig.Plan()
	defaultBridge := ""
	if app.SDNConfig.OVS != nil {
		defaultBridge = app.SDNConfig.OVS.Bridge
	}
	var out []zoneAddress
	seen := make(map[string]string)
	for _, bond := range app.NetworkConfig.Bonds {
		if bond.Type != "" && bond.Type != installer.BondTypeOVS {
			continue
		}
		bridge := bond.Bridge
		if bridge == "" {
			bridge = defaultBridge
		}
		for _, v := range bond.VLANs {
			if v.IPv4Address == "" {
				continue
			}
			if plan == nil {
				return nil, sdn.ErrEnvironmentRequired{}
			}
			n, ok := plan.Zone(sdnzone.Zone(v.Zone))
			if !ok {
				return nil, ErrSDNUnknownZoneAddress{Bond: bond.Name, Zone: v.Zone}
			}
			if bridge == "" {
				return nil, ErrSDNUnknownZoneAddress{Bond: bond.Name, Zone: v.Zone, NoBridge: true}
			}
			if first, dup := seen[v.Zone]; dup {
				return nil, ErrSDNDuplicateZoneAddress{Zone: v.Zone, Bonds: [2]string{first, bond.Name}}
			}
			seen[v.Zone] = bond.Name
			out = append(out, zoneAddress{
				bridge: bridge,
				port:   zonePortName(n.VLAN),
				vlan:   n.VLAN,
				addr:   v.IPv4Address,
			})
		}
	}
	return out, nil
}

// zonePortClient is the slice of the OVS client that creates zone ports.
type zonePortClient interface {
	GetPort(ctx context.Context, name string) (*ovs.Port, error)
	AddPort(ctx context.Context, bridgeName, portName string) (*ovs.Port, error)
	SetInterfaceType(ctx context.Context, name, ifType string) error
	SetPortVLAN(ctx context.Context, portName string, tag int64) error
}

// ensureZonePort creates (idempotently) the internal port of a zone address
// on its bridge, tagged with the zone's VLAN.
func ensureZonePort(ctx context.Context, client zonePortClient, za zoneAddress) error {
	if existing, err := client.GetPort(ctx, za.port); err != nil || existing == nil {
		if _, err := client.AddPort(ctx, za.bridge, za.port); err != nil && !errors.Is(err, ovs.ErrPortExists) {
			return &WrappedError{Msg: fmt.Sprintf("ovs AddPort %s on %s", za.port, za.bridge), Err: err}
		}
	}
	if err := client.SetInterfaceType(ctx, za.port, "internal"); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("ovs SetInterfaceType %s internal", za.port), Err: err}
	}
	if err := client.SetPortVLAN(ctx, za.port, int64(za.vlan)); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("ovs SetPortVLAN %s %d", za.port, za.vlan), Err: err}
	}
	return nil
}

// initZoneAddresses realises the host's zone addresses: for every OVS bond
// VLAN entry it creates the zone<VLAN> internal port on the bond's bridge,
// tagged with the zone's VLAN from the network plan, brings it up, runs the
// duplicate-address guard (#508) and assigns the address. An unknown zone or
// a missing plan fails the whole step with a typed error before any port is
// touched.
func (app *App) initZoneAddresses(ctx context.Context) error {
	client := zonePortClientFn(app)
	if app.NetworkConfig == nil || client == nil {
		return nil
	}
	addrs, err := app.zoneAddresses()
	if err != nil {
		return err
	}
	for _, za := range addrs {
		if err := ensureZonePort(ctx, client, za); err != nil {
			app.Logger.Warn("SDN: failed to create zone port",
				slog.String("port", za.port),
				slog.String("bridge", za.bridge),
				slog.String("error", err.Error()))
			continue
		}

		if err := setBridgeUpFn(ctx, za.port); err != nil {
			app.Logger.Warn("SDN: failed to bring zone port up",
				slog.String("port", za.port),
				slog.String("error", err.Error()))
			continue
		}

		// Duplicate-address detection (#508): the node must never take an
		// address another station already answers for. A measured
		// conflict fails the address closed and leaves the node degraded;
		// bring-up continues with its other addresses.
		if err := app.guardBridgeAddress(ctx, za.port, za.addr); err != nil {
			continue
		}

		if err := assignBridgeAddrFn(ctx, za.port, za.addr); err != nil {
			app.Logger.Warn("SDN: failed to assign zone address",
				slog.String("port", za.port),
				slog.String("address", za.addr),
				slog.String("error", err.Error()))
			continue
		}

		app.Logger.Info("SDN: zone address assigned",
			slog.String("port", za.port),
			slog.String("bridge", za.bridge),
			slog.Int("vlan", int(za.vlan)),
			slog.String("address", za.addr))
	}
	return nil
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

// zonePortClientFn returns the OVS client initZoneAddresses creates zone
// ports with: the app's OVS client, or nil when OVS is not connected. A
// package variable so tests drive bring-up without an OVSDB server.
var zonePortClientFn = func(app *App) zonePortClient {
	if app.ovsClient == nil {
		return nil
	}
	return app.ovsClient
}

// setBridgeUpFn and assignBridgeAddrFn are the netlink calls
// initZoneAddresses makes, held in package variables so tests can drive the bring-up sequence
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
