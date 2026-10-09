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

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/firewall"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// backedService is the lifecycle every real service implementation behind
// a config section already has. A handler is only ever "active" because
// the service it drives says so — there is no bool a handler can flip to
// report a service that programmed nothing (#568).
type backedService interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Active() bool
	// Healthy reports the service's own health verdict.
	Healthy() bool
}

// serviceBuilder constructs the service behind one config section from the
// gateway's configuration and injected runtimes. It runs at Start, never at
// construction, so a gateway built from configuration alone stays
// inspectable and a dependency the daemon did not inject is a typed start
// error naming the service.
type serviceBuilder func(g *Gateway) (backedService, error)

// serviceBuilders is the map-dispatched builder table: one entry per
// service section the gateway can actually run. A section present in
// GatewayConfig but absent here is refused at Start with the reason in
// serviceRefusals — never silently reported running.
var serviceBuilders = map[string]serviceBuilder{
	ServiceFirewall:     buildFirewall,
	ServiceLoadBalancer: buildLoadBalancer,
	ServiceNAT:          buildNAT,
	ServiceNAT64:        buildNAT64,
	ServiceHostFW:       buildHostFW,
	ServiceTunnels:      buildTunnels,
	ServiceOverlay:      buildOverlay,
	ServiceTransit:      buildTransit,
}

// serviceRefusals names, per unbuildable section, the blocker that stands
// between the config surface and a running service. The text is what the
// operator reads in ErrServiceUnavailable; it names the missing piece, not
// a promise.
var serviceRefusals = map[string]string{
	ServiceEdge: "the edge service constructor (modes.NewEdgeModeHandler) needs an IPv6 pool, ACME endorse/enroll " +
		"toggles and a FROST pool the gateway runtime does not inject; tracked under epic #553",
	ServiceDHCP: "the DHCP service needs an IPAM allocator gatewayd does not have (GatewayRuntime carries none, " +
		"pkg/sdn/gateway/runtime.go); tracked under epic #553",
	ServicePXE: "the PXE controller (modes.NewPXEController) needs a serving interface, server address and DHCP " +
		"range the gateway PXE section does not carry; provisioning is served by platformd's iPXE server today; " +
		"tracked under epic #553",
	ServiceManagementVPN: "the management VPN is a design (docs/vpn/, #558) with no implementation; " +
		"WireGuard is non-FIPS and the MASQUE data plane is unbuilt",
}

// backedServiceHandler is the one ServiceHandler shape for every
// config-driven service: it builds the service on Start through the
// section's builder, drives its lifecycle, and derives IsActive and Health
// from the service — never from a flag of its own.
type backedServiceHandler struct {
	gateway *Gateway
	name    string
	build   serviceBuilder

	mu  sync.Mutex
	svc backedService
}

func newBackedServiceHandler(g *Gateway, name string, build serviceBuilder) *backedServiceHandler {
	return &backedServiceHandler{gateway: g, name: name, build: build}
}

func (h *backedServiceHandler) Name() string { return h.name }

func (h *backedServiceHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.svc != nil {
		return &ErrServiceAlreadyActive{Service: h.name}
	}
	svc, err := h.build(h.gateway)
	if err != nil {
		return err
	}
	if err := svc.Start(ctx); err != nil {
		return &ErrServiceStartFailed{Service: h.name, Cause: err}
	}
	h.svc = svc
	return nil
}

func (h *backedServiceHandler) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.svc == nil {
		return &ErrServiceNotActive{Service: h.name}
	}
	if err := h.svc.Stop(ctx); err != nil {
		return &ErrServiceStopFailed{Service: h.name, Cause: err}
	}
	h.svc = nil
	return nil
}

func (h *backedServiceHandler) IsActive() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.svc != nil && h.svc.Active()
}

func (h *backedServiceHandler) Health() error {
	h.mu.Lock()
	svc := h.svc
	h.mu.Unlock()

	if svc == nil || !svc.Healthy() {
		return &ErrServiceNotActive{Service: h.name}
	}
	return nil
}

// service returns the running backend, or nil when the handler has not
// started it.
func (h *backedServiceHandler) service() backedService {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.svc
}

// refusedServiceHandler stands in for a config section the gateway cannot
// run. It exists so the refusal is a Start error that names the section
// and the blocker, rather than a section that vanishes from the registry
// or — worse — a bool that reports it running.
type refusedServiceHandler struct {
	name   string
	reason string
}

func (h *refusedServiceHandler) Name() string { return h.name }

func (h *refusedServiceHandler) Start(context.Context) error {
	return &ErrServiceUnavailable{Service: h.name, Reason: h.reason}
}

func (h *refusedServiceHandler) Stop(context.Context) error {
	return &ErrServiceNotActive{Service: h.name}
}

func (h *refusedServiceHandler) IsActive() bool { return false }

func (h *refusedServiceHandler) Health() error {
	return &ErrServiceUnavailable{Service: h.name, Reason: h.reason}
}

// registerConfiguredServices registers one handler per enabled section: a
// supervisedServiceHandler for every section when a ServiceSupervisor is
// injected (#557), otherwise a backedServiceHandler when the builder table
// has the section and a refusedServiceHandler when it does not. The order is the declared order of
// enabledServices, so start order is deterministic for the datapath
// services even though the registry itself is a map.
func (g *Gateway) registerConfiguredServices() {
	for _, name := range g.config.EnabledServices() {
		if g.config.Supervisor != nil {
			g.serviceHandlers[name] = newSupervisedServiceHandler(name, g.config.Supervisor)
			g.serviceOrder = append(g.serviceOrder, name)
			continue
		}
		if build, ok := serviceBuilders[name]; ok {
			g.serviceHandlers[name] = newBackedServiceHandler(g, name, build)
		} else {
			reason, ok := serviceRefusals[name]
			if !ok {
				reason = "no builder is registered for this service"
			}
			g.serviceHandlers[name] = &refusedServiceHandler{name: name, reason: reason}
		}
		g.serviceOrder = append(g.serviceOrder, name)
	}
}

// backend returns the running backend behind a config-driven service, or
// false when the service is not registered, is refused, or has not started.
func (g *Gateway) backend(name string) (backedService, bool) {
	g.mu.RLock()
	handler, ok := g.serviceHandlers[name]
	g.mu.RUnlock()
	if !ok {
		return nil, false
	}
	backed, ok := handler.(*backedServiceHandler)
	if !ok {
		return nil, false
	}
	svc := backed.service()
	if svc == nil {
		return nil, false
	}
	return svc, true
}

// ----------------------------------------------------------------------------
// Builders and the adapters that give each service the backedService shape.
// ----------------------------------------------------------------------------

// firewallBackend adapts *firewall.Service.
type firewallBackend struct{ *firewall.Service }

func (b firewallBackend) Healthy() bool { return b.Service.Health().Active }

func buildFirewall(g *Gateway) (backedService, error) {
	runtime := g.config.Runtime
	if runtime == nil {
		return nil, &ErrRuntimeMissing{Service: ServiceFirewall}
	}
	cfg := g.config.Firewall
	bridge := runtime.Bridge
	if cfg.Bridge != "" {
		bridge = cfg.Bridge
	}
	svc, err := firewall.New(firewall.Deps{
		Controller: runtime.Controller,
		OVS:        runtime.OVS,
		Config: firewall.Config{
			DefaultPolicy: cfg.DefaultPolicy,
			Bridge:        bridge,
		},
		Zones:     runtime.Zones,
		Networks:  runtime.Networks,
		Allocator: runtime.CTZones,
		Logger:    runtime.Logger,
	})
	if err != nil {
		return nil, &ErrServiceStartFailed{Service: ServiceFirewall, Cause: err}
	}
	return firewallBackend{svc}, nil
}

// loadBalancerBackend adapts *loadbalancer.Service.
type loadBalancerBackend struct{ *loadbalancer.Service }

func (b loadBalancerBackend) Healthy() bool { return b.Service.Health().Active }

func buildLoadBalancer(g *Gateway) (backedService, error) {
	runtime := g.config.Runtime
	if runtime == nil || runtime.Groups == nil {
		return nil, &ErrRuntimeMissing{Service: ServiceLoadBalancer}
	}
	cfg := g.config.LoadBalancer
	bridge := runtime.Bridge
	if cfg.Bridge != "" {
		bridge = cfg.Bridge
	}
	hairpin, err := cfg.ServiceHairpinPrefixes()
	if err != nil {
		return nil, &ErrServiceStartFailed{Service: ServiceLoadBalancer, Cause: err}
	}
	vips := make([]loadbalancer.VIP, 0, len(cfg.VIPs))
	for i := range cfg.VIPs {
		vip, err := cfg.VIPs[i].ServiceVIP()
		if err != nil {
			return nil, err
		}
		vips = append(vips, vip)
	}
	svc, err := loadbalancer.New(loadbalancer.Deps{
		Controller: runtime.Controller,
		OVS:        runtime.OVS,
		Groups:     runtime.Groups,
		Config: loadbalancer.Config{
			Bridge:              bridge,
			Algorithm:           cfg.Algorithm,
			HealthCheckInterval: cfg.HealthCheckInterval,
			HealthCheckTimeout:  cfg.HealthCheckTimeout,
			Rise:                cfg.HealthCheckRise,
			Fall:                cfg.HealthCheckFall,
			MaxBackends:         cfg.MaxBackends,
			HairpinPrefixes:     hairpin,
			VIPs:                vips,
		},
		Allocator: runtime.CTZones,
		Logger:    runtime.Logger,
	})
	if err != nil {
		return nil, &ErrServiceStartFailed{Service: ServiceLoadBalancer, Cause: err}
	}
	return loadBalancerBackend{svc}, nil
}

// natBackend adapts *firewall.NAT.
type natBackend struct{ *firewall.NAT }

func (b natBackend) Healthy() bool { return b.NAT.Health().Active }

func buildNAT(g *Gateway) (backedService, error) {
	runtime := g.config.Runtime
	if runtime == nil {
		return nil, &ErrRuntimeMissing{Service: ServiceNAT}
	}
	cfg := g.config.NAT
	bridge := runtime.Bridge
	if cfg.Bridge != "" {
		bridge = cfg.Bridge
	}
	uplink := cfg.UplinkPort
	if uplink == "" && len(g.config.Uplinks) > 0 {
		uplink = g.config.Uplinks[0].Name
	}
	svc, err := firewall.NewNAT(firewall.Deps{
		Controller: runtime.Controller,
		OVS:        runtime.OVS,
		Allocator:  runtime.CTZones,
		Logger:     runtime.Logger,
	}, firewall.NATConfig{
		ExternalIP:     cfg.ExternalIP,
		PortRangeStart: cfg.PortRangeStart,
		PortRangeEnd:   cfg.PortRangeEnd,
		InternalCIDR:   cfg.InternalCIDR,
		UplinkPort:     uplink,
		Bridge:         bridge,
	})
	if err != nil {
		return nil, &ErrServiceStartFailed{Service: ServiceNAT, Cause: err}
	}
	return natBackend{svc}, nil
}

// nat64Backend adapts *nat64.Service. Health is the kernel's answer, not
// the configuration's: a started translator whose instance has gone
// reports unhealthy so the snapshot says so.
type nat64Backend struct{ *nat64.Service }

func (b nat64Backend) Healthy() bool {
	h := b.Health()
	return h.Active && h.InstancePresent && h.LastError == nil
}

// nat44Ranges is every IPv4 address:port range the NAT service translates
// to: each uplink's SNAT pool, the single-address external IP, and every
// static 1:1 external address, which owns all of its ports. The overlap
// check needs it, and only the gateway sees both sections.
func nat44Ranges(cfg *NATConfig) []nat64.NAT44Range {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	var out []nat64.NAT44Range
	for _, st := range cfg.Static {
		out = append(out, nat64.NAT44Range{
			Uplink: st.Uplink, Addresses: st.External, PortStart: 1, PortEnd: 65535,
		})
	}
	for _, u := range cfg.Uplinks {
		start, end := u.PortRangeStart, u.PortRangeEnd
		if start == 0 && end == 0 {
			start, end = cfg.PortRangeStart, cfg.PortRangeEnd
		}
		for _, addr := range u.Addresses {
			out = append(out, nat64.NAT44Range{
				Uplink: u.Name, Addresses: addr, PortStart: start, PortEnd: end,
			})
		}
	}
	if len(cfg.Uplinks) == 0 && cfg.ExternalIP != "" {
		out = append(out, nat64.NAT44Range{
			Addresses: cfg.ExternalIP, PortStart: cfg.PortRangeStart, PortEnd: cfg.PortRangeEnd,
		})
	}
	return out
}

// buildNAT64 builds the stateful NAT64 translator from the `nat64:`
// section. Without an injected driver it drives the real jool tool, which
// needs the kernel module: a gateway whose kernel cannot carry the
// translator refuses the section rather than reporting a service that
// translates nothing (#601, ruling R6).
func buildNAT64(g *Gateway) (backedService, error) {
	runtime := g.config.Runtime
	if runtime == nil {
		return nil, &ErrRuntimeMissing{Service: ServiceNAT64}
	}
	cfg := g.config.NAT64
	serviceCfg := cfg.ServiceConfig(runtime.Bridge)

	// Two independent allocators must never share an address and a port.
	if err := serviceCfg.CheckPoolOverlap(nat44Ranges(g.config.NAT)); err != nil {
		return nil, &ErrServiceStartFailed{Service: ServiceNAT64, Cause: err}
	}

	host := g.config.hostRuntime()
	driver := host.NAT64Driver
	if driver == nil {
		driver = nat64.NewJoolDriver()
	}
	svc, err := nat64.New(nat64.Deps{
		Driver:     driver,
		Controller: runtime.Controller,
		OVS:        runtime.OVS,
		Config:     serviceCfg,
		Logger:     host.Logger,
	})
	if err != nil {
		return nil, &ErrServiceStartFailed{Service: ServiceNAT64, Cause: err}
	}
	return nat64Backend{svc}, nil
}

// hostFWBackend adapts *hostfw.Service.
type hostFWBackend struct{ *hostfw.Service }

func (b hostFWBackend) Healthy() bool { return b.Service.Health().Active }

// buildHostFW builds the nftables host packet filter from the `hostfw:`
// section, the daemon-injected listener inventory and applier
// (HostRuntime), and the tunnel interfaces the gateway itself configures.
// Without an injected applier it opens the real netlink connection, which
// needs CAP_NET_ADMIN — the gateway's normal privilege.
func buildHostFW(g *Gateway) (backedService, error) {
	cfg := g.config.HostFW
	host := g.config.hostRuntime()
	applier := host.HostFWApplier
	if applier == nil {
		nl, err := hostfw.NewNetlinkApplier()
		if err != nil {
			return nil, &ErrServiceStartFailed{Service: ServiceHostFW, Cause: err}
		}
		applier = nl
	}
	inventory := host.Listeners
	if inventory == nil {
		inventory = hostfw.StaticInventory{}
	}
	rendered := *cfg
	// Every tunnel the gateway programs is a BGP/BFD carrier the host
	// filter must admit on; the operator need not repeat the names.
	for i := range g.config.Tunnels {
		if !slices.Contains(rendered.Tunnels, g.config.Tunnels[i].Name) {
			rendered.Tunnels = append(rendered.Tunnels, g.config.Tunnels[i].Name)
		}
	}
	svc, err := hostfw.New(hostfw.Deps{
		Applier:   applier,
		Inventory: inventory,
		Config:    rendered,
		Logger:    host.Logger,
	})
	if err != nil {
		return nil, &ErrServiceStartFailed{Service: ServiceHostFW, Cause: err}
	}
	return hostFWBackend{svc}, nil
}

// TunnelManager is the tunnel-manager surface the tunnels service drives.
// *tunnel.Manager implements it; HostRuntime lets the daemon or a test
// inject another implementation.
type TunnelManager interface {
	EnsureTunnel(ctx context.Context, config tunnel.TunnelConfig) error
	RemoveTunnel(ctx context.Context, name string) error
	ListTunnels(ctx context.Context) ([]*tunnel.TunnelStatus, error)
	// Uplinks reports the policy-routing state of the uplinks tunnels are
	// pinned to; empty when the deployment routes through the main table.
	Uplinks() []tunnel.UplinkStatus
	Close() error
}

// UplinkManager is the routing-uplink surface the tunnels service drives.
// *tunnel.UplinkManager implements it. The same instance is handed to the
// tunnel manager (tunnel.WithUplinks) so a tunnel's `uplink:` pin resolves
// against what this service programmed; Close removes every table, route and
// rule it installed.
type UplinkManager interface {
	EnsureUplink(ctx context.Context, config tunnel.UplinkConfig) error
	Close() error
}

// tunnelsBackend drives the netlink tunnel manager for the `tunnels:`
// section: the `routing-uplinks:` are programmed first, then every
// configured tunnel is ensured on Start; both are removed on Stop. The
// service is healthy while every tunnel interface reports up.
type tunnelsBackend struct {
	manager       TunnelManager
	uplinks       UplinkManager
	configs       []tunnel.TunnelConfig
	uplinkConfigs []tunnel.UplinkConfig
	logger        *slog.Logger

	mu     sync.Mutex
	active bool
}

func (b *tunnelsBackend) Start(ctx context.Context) error {
	for i := range b.uplinkConfigs {
		if err := b.uplinks.EnsureUplink(ctx, b.uplinkConfigs[i]); err != nil {
			b.closeUplinks()
			return err
		}
	}
	for i := range b.configs {
		if err := b.manager.EnsureTunnel(ctx, b.configs[i]); err != nil {
			// Undo what this call created before reporting.
			for j := i - 1; j >= 0; j-- {
				if rmErr := b.manager.RemoveTunnel(ctx, b.configs[j].Name); rmErr != nil {
					b.logger.Warn("tunnel rollback failed", slog.String("tunnel", b.configs[j].Name), slog.Any("error", rmErr))
				}
			}
			b.closeUplinks()
			return err
		}
	}
	b.mu.Lock()
	b.active = true
	b.mu.Unlock()
	return nil
}

// closeUplinks removes the routing state this service programmed. It is a
// rollback path as well as part of Stop, so a failure is logged rather than
// replacing the error the caller acts on.
func (b *tunnelsBackend) closeUplinks() {
	if b.uplinks == nil {
		return
	}
	if err := b.uplinks.Close(); err != nil {
		b.logger.Warn("routing uplink cleanup failed", slog.Any("error", err))
	}
}

func (b *tunnelsBackend) Stop(ctx context.Context) error {
	var firstErr error
	for i := len(b.configs) - 1; i >= 0; i-- {
		if err := b.manager.RemoveTunnel(ctx, b.configs[i].Name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	b.mu.Lock()
	b.active = false
	b.mu.Unlock()
	if err := b.manager.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	// Uplinks go last: the tunnels pinned to them are already gone.
	if b.uplinks != nil {
		if err := b.uplinks.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (b *tunnelsBackend) Active() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.active
}

func (b *tunnelsBackend) Healthy() bool {
	if !b.Active() {
		return false
	}
	statuses, err := b.manager.ListTunnels(context.Background())
	if err != nil {
		return false
	}
	up := make(map[string]bool, len(statuses))
	for _, st := range statuses {
		up[st.Name] = st.State == tunnel.TunnelStateUp
	}
	for i := range b.configs {
		if !up[b.configs[i].Name] {
			return false
		}
	}
	return true
}

// Tunnels reports every managed tunnel's live status, for the telemetry
// snapshot. A manager that cannot be read yields the error, never a
// half-empty list a reader would take for the truth.
func (b *tunnelsBackend) Tunnels(ctx context.Context) ([]*tunnel.TunnelStatus, error) {
	return b.manager.ListTunnels(ctx)
}

// Uplinks reports the policy-routing state behind the tunnels.
func (b *tunnelsBackend) Uplinks() []tunnel.UplinkStatus {
	return b.manager.Uplinks()
}

// buildTunnels hands the gateway's `tunnels:` and `routing-uplinks:`
// sections to the netlink tunnel manager. The manager comes from HostRuntime
// when the daemon (or a test) injected one; otherwise the real netlink
// manager is used, with the HostRuntime secret resolver as its key provider
// so `ipsec` and `wireguard` tunnels resolve their key references through the
// same store the transit speaker uses, and with the UplinkManager the
// `uplink:` pins resolve against (tunnel.WithUplinks).
func buildTunnels(g *Gateway) (backedService, error) {
	host := g.config.hostRuntime()
	routing := len(g.config.RoutingUplinks) > 0
	uplinks := host.UplinkManager
	manager := host.TunnelManager
	if manager == nil {
		var opts []tunnel.Option
		if host.SecretResolver != nil {
			opts = append(opts, tunnel.WithKeyProvider(resolverKeyProvider{resolve: host.SecretResolver}))
		}
		netlinkUplinks := tunnel.NewUplinkManager(host.Logger)
		uplinks = netlinkUplinks
		opts = append(opts, tunnel.WithUplinks(netlinkUplinks))
		manager = tunnel.NewManager(host.Logger, opts...)
	} else if routing && uplinks == nil {
		return nil, &ErrServiceUnavailable{
			Service: ServiceTunnels,
			Reason:  "routing-uplinks are configured but the injected TunnelManager comes without an UplinkManager",
		}
	}
	return &tunnelsBackend{
		manager:       manager,
		uplinks:       uplinks,
		configs:       slices.Clone(g.config.Tunnels),
		uplinkConfigs: slices.Clone(g.config.RoutingUplinks),
		logger:        host.Logger,
	}, nil
}

// resolverKeyProvider adapts the HostRuntime secret resolver to the tunnel
// package's KeyProvider: one store, one HostRuntime field, two consumers.
type resolverKeyProvider struct {
	resolve bgp.SecretResolver
}

// Key implements tunnel.KeyProvider.
func (p resolverKeyProvider) Key(ctx context.Context, ref string) ([]byte, error) {
	return p.resolve(ctx, ref)
}

// overlayBackend adapts modes.OverlayModeHandler to the gateway service
// lifecycle. It keeps the admitter beside the datapath it gates and sweeps
// what that datapath has installed against the admission policy.
type overlayBackend struct {
	config   *OverlayServiceConfig
	ovs      modes.OverlayOVSClient
	of       modes.OverlayOpenFlowClient
	ipam     OverlayIPAMReader
	devices  OverlayDeviceGetter
	verdicts OverlayVerdictReader
	stream   OverlayVerdictStream
	resolver bgp.SecretResolver
	server   bgp.BGPServerInterface
	logger   *slog.Logger
	bridge   string

	mu      sync.Mutex
	handler *modes.OverlayModeHandler
	admit   *VTEPAdmitter
	speaker *bgp.Speaker
	// stopLoops ends the admission sweep and the verdict follower; loopsDone
	// closes once both have returned.
	stopLoops context.CancelFunc
	loopsDone chan struct{}
}

// overlayDatapath is the overlay handler's view of the remote VTEPs it holds
// state for.
type overlayDatapath interface {
	InstalledVTEPs() []modes.InstalledVTEP
}

// runAdmissionSweep re-judges the datapath's installed VTEPs on every tick
// until ctx ends.
func runAdmissionSweep(ctx context.Context, ticks <-chan time.Time, datapath overlayDatapath, admitter *VTEPAdmitter, logger *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			if err := admitter.Sweep(ctx, datapath.InstalledVTEPs()); err != nil {
				logger.Warn("overlay: the admission sweep did not complete", slog.Any("error", err))
			}
		}
	}
}

// overlayVerdictFollowRetry is how long the verdict follower waits before
// following a broken verdict stream again.
const overlayVerdictFollowRetry = 5 * time.Second

// runVerdictFollower follows the platform's device verdicts until ctx ends,
// withdrawing every device whose verdict failed and replaying the refused
// VTEPs of every device whose verdict passed. A broken stream is followed
// again after retry; a verdict recorded while it was down is caught by the
// admission sweep, which re-reads the latest verdict of every installed and
// every refused VTEP.
func runVerdictFollower(ctx context.Context, stream OverlayVerdictStream, admitter *VTEPAdmitter, retry time.Duration, logger *slog.Logger) {
	for {
		err := stream.Follow(ctx, admitter.OnDeviceVerdict)
		if ctx.Err() != nil {
			return
		}
		logger.Warn("overlay: the verdict stream broke; following it again",
			slog.Any("error", err), slog.Duration("retry", retry))
		timer := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// overlayVTEPControl is the overlay handler's control of remote VTEPs the
// admitter drives.
type overlayVTEPControl interface {
	OverlayVTEPRevoker
	OverlayVTEPReplayer
}

// overlayHandlerProxy hands the admitter's revocations and replays to the
// overlay handler once it is built, and refuses them before then: the admitter
// is built first, because the handler is configured with it.
type overlayHandlerProxy struct {
	mu      sync.RWMutex
	handler overlayVTEPControl
}

func (p *overlayHandlerProxy) set(handler overlayVTEPControl) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handler = handler
}

func (p *overlayHandlerProxy) get() (overlayVTEPControl, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.handler == nil {
		return nil, &ErrServiceUnavailable{Service: ServiceOverlay, Reason: "overlay handler is not ready"}
	}
	return p.handler, nil
}

func (p *overlayHandlerProxy) RevokeVTEP(ctx context.Context, vtep netip.Addr) error {
	handler, err := p.get()
	if err != nil {
		return err
	}
	return handler.RevokeVTEP(ctx, vtep)
}

func (p *overlayHandlerProxy) ReplayVTEP(ctx context.Context, vtep netip.Addr) error {
	handler, err := p.get()
	if err != nil {
		return err
	}
	return handler.ReplayVTEP(ctx, vtep)
}

// RefusedVTEPs reports nothing before the handler is built: it has refused
// nothing yet.
func (p *overlayHandlerProxy) RefusedVTEPs() []netip.Addr {
	handler, err := p.get()
	if err != nil {
		return nil
	}
	return handler.RefusedVTEPs()
}

func (b *overlayBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handler != nil {
		return &ErrServiceAlreadyActive{Service: ServiceOverlay}
	}
	logger := b.logger
	if logger == nil {
		logger = slog.Default()
	}
	proxy := &overlayHandlerProxy{}
	admitter, err := NewVTEPAdmitter(VTEPAdmissionConfig{
		IPAM:             b.ipam,
		Devices:          b.devices,
		Verdicts:         b.verdicts,
		Revoker:          proxy,
		Replayer:         proxy,
		MaxVerdictAge:    b.config.VerdictMaxAge,
		VerdictClockSkew: b.config.VerdictClockSkew,
		Logger:           logger,
	})
	if err != nil {
		return err
	}
	modeCfg := &modes.OverlayModeConfig{
		VTEPConfig: &vxlan.VTEPConfig{
			LocalIP:       b.config.LocalVTEP,
			UnderlayIface: b.config.UnderlayInterface,
			UnderlayMTU:   b.config.UnderlayMTU,
			VXLANPort:     b.config.VXLANPort,
		},
		BridgeName: b.bridge,
		AccessPort: b.config.AccessPort,
		Admitter:   admitter,
		Logger:     logger,
	}

	speaker, evpnCfg, err := b.overlayEVPN(ctx, logger)
	if err != nil {
		return err
	}
	modeCfg.EVPNConfig = evpnCfg
	handler, err := modes.NewOverlayModeHandler(modeCfg, b.ovs, b.of)
	if err != nil {
		return errors.Join(err, stopOverlaySpeaker(ctx, speaker))
	}
	proxy.set(handler)
	if err := handler.Start(ctx); err != nil {
		return errors.Join(err, stopOverlaySpeaker(ctx, speaker))
	}

	// The loops outlive the request that started the service; Stop ends them.
	loopsCtx, stopLoops := context.WithCancel(context.WithoutCancel(ctx))
	var loops sync.WaitGroup
	ticker := time.NewTicker(b.config.admissionSweepInterval())
	loops.Add(2)
	go func() {
		defer loops.Done()
		defer ticker.Stop()
		runAdmissionSweep(loopsCtx, ticker.C, handler, admitter, logger)
	}()
	go func() {
		defer loops.Done()
		runVerdictFollower(loopsCtx, b.stream, admitter, overlayVerdictFollowRetry, logger)
	}()
	loopsDone := make(chan struct{})
	go func() {
		loops.Wait()
		close(loopsDone)
	}()

	b.handler = handler
	b.admit = admitter
	b.speaker = speaker
	b.stopLoops = stopLoops
	b.loopsDone = loopsDone
	return nil
}

func stopOverlaySpeaker(ctx context.Context, speaker *bgp.Speaker) error {
	if speaker == nil {
		return nil
	}
	return speaker.Stop(ctx)
}

func (b *overlayBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handler == nil {
		return nil
	}
	b.stopLoops()
	<-b.loopsDone
	var errs []error
	errs = append(errs, b.handler.Stop(ctx))
	if b.speaker != nil {
		errs = append(errs, b.speaker.Stop(ctx))
	}
	b.handler = nil
	b.admit = nil
	b.speaker = nil
	b.stopLoops = nil
	b.loopsDone = nil
	return errors.Join(errs...)
}

func (b *overlayBackend) Active() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.handler != nil && b.handler.GetStatus().Running
}

func (b *overlayBackend) Healthy() bool { return b.Active() }

func (b *overlayBackend) Status() *modes.OverlayModeStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handler == nil {
		return nil
	}
	return b.handler.GetStatus()
}

// ListAdmittedVTEPs reports the remote VTEPs the overlay datapath has
// installed, each with the admission that let it in.
func (b *overlayBackend) ListAdmittedVTEPs(context.Context) ([]AdmittedVTEP, error) {
	b.mu.Lock()
	handler, admitter := b.handler, b.admit
	b.mu.Unlock()
	if handler == nil {
		return nil, &ErrServiceUnavailable{Service: ServiceOverlay, Reason: "overlay admission is not running"}
	}
	return admitter.Admitted(handler.InstalledVTEPs()), nil
}

func (b *overlayBackend) overlayEVPN(ctx context.Context, logger *slog.Logger) (*bgp.Speaker, *bgp.EVPNManagerConfig, error) {
	if len(b.config.RRPeers) == 0 {
		return nil, nil, nil
	}
	if b.config.OverlayASN > 65535 {
		return nil, nil, &ErrServiceUnavailable{Service: ServiceOverlay, Reason: "overlay EVPN route targets require a 2-byte overlay ASN"}
	}
	speakerCfg := &bgp.BGPConfig{
		RouterID:        b.config.LocalVTEP,
		ASN:             b.config.OverlayASN,
		ListenAddresses: []netip.Addr{b.config.LocalVTEP},
		Capabilities:    bgp.BGPCapabilities{EVPN: true},
		EnabledFamilies: []bgp.AddressFamily{bgp.AFamilyEVPN},
		Neighbors:       append([]bgp.NeighborConfig(nil), b.config.RRPeers...),
	}
	defer zeroizeBGPSecrets(speakerCfg)
	if err := speakerCfg.ResolveSecrets(ctx, b.resolver); err != nil {
		return nil, nil, err
	}
	var opts []bgp.SpeakerOption
	if b.server != nil {
		opts = append(opts, bgp.WithBGPServer(b.server))
	}
	speaker, err := bgp.NewSpeaker(speakerCfg, logger, opts...)
	if err != nil {
		return nil, nil, err
	}
	if err := speaker.Start(ctx); err != nil {
		return nil, nil, err
	}
	for i := range speakerCfg.Neighbors {
		if err := speaker.AddPeer(ctx, &speakerCfg.Neighbors[i]); err != nil {
			if stopErr := speaker.Stop(ctx); stopErr != nil {
				logger.Warn("overlay: stopping the speaker after a peer refusal failed", slog.Any("error", stopErr))
			}
			return nil, nil, err
		}
	}
	return speaker, &bgp.EVPNManagerConfig{
		Speaker:    speaker,
		Logger:     logger,
		LocalVTEP:  b.config.LocalVTEP,
		OverlayASN: uint16(b.config.OverlayASN),
	}, nil
}

func buildOverlay(g *Gateway) (backedService, error) {
	runtime := g.config.Runtime
	if runtime == nil || runtime.OVS == nil || runtime.OverlayOpenFlow == nil || runtime.OverlayIPAM == nil || runtime.OverlayDevices == nil || runtime.OverlayVerdicts == nil || runtime.OverlayVerdictStream == nil {
		return nil, &ErrRuntimeMissing{Service: ServiceOverlay}
	}
	if g.config.Overlay == nil {
		return nil, &ErrServiceUnavailable{Service: ServiceOverlay, Reason: "the overlay service needs a gateway.overlay section"}
	}
	host := g.config.hostRuntime()
	return &overlayBackend{
		config:   g.config.Overlay,
		ovs:      runtime.OVS,
		of:       runtime.OverlayOpenFlow,
		ipam:     runtime.OverlayIPAM,
		devices:  runtime.OverlayDevices,
		verdicts: runtime.OverlayVerdicts,
		stream:   runtime.OverlayVerdictStream,
		resolver: host.SecretResolver,
		server:   host.BGPServer,
		logger:   runtime.Logger,
		bridge:   runtime.Bridge,
	}, nil
}

// transitBackend runs the BGP speaker for the transit service. The speaker
// is built at Start, after the neighbor and keychain secret references
// have been resolved through the injected resolver, so no session ever
// starts with a secret the configuration only referenced.
type transitBackend struct {
	config   *bgp.BGPConfig
	resolver bgp.SecretResolver
	server   bgp.BGPServerInterface
	logger   *slog.Logger

	mu      sync.Mutex
	speaker *bgp.Speaker
}

// cloneBGPConfig copies the configuration deeply enough that ResolveSecrets
// writes resolved material only into the copy: neighbours and every
// keychain's key slice are duplicated, so the shared configuration keeps
// references alone.
func cloneBGPConfig(src *bgp.BGPConfig) *bgp.BGPConfig {
	cfg := *src
	cfg.Neighbors = append([]bgp.NeighborConfig(nil), src.Neighbors...)
	cfg.Keychains = make([]bgp.TCPAOKeychainConfig, len(src.Keychains))
	for i, kc := range src.Keychains {
		kc.Keys = append([]bgp.TCPAOKeyConfig(nil), kc.Keys...)
		cfg.Keychains[i] = kc
	}
	return &cfg
}

func (b *transitBackend) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.speaker != nil {
		return &ErrServiceAlreadyActive{Service: ServiceTransit}
	}
	cfg := cloneBGPConfig(b.config)
	// The resolved master keys live in this private copy only until the
	// speaker has handed them to GoBGP at Start — which clones them into
	// its own keychain store (newTcpAoKey, bytes.Clone) — so whatever
	// happens next, this copy is wiped on the way out. The defer is armed
	// before resolution, not after it: a resolution that fails halfway has
	// already filled the keys it did reach, and those must be wiped too.
	// MD5 passwords are strings and travel into GoBGP's peer configuration
	// as such; a Go string cannot be wiped, so there is nothing to zeroize
	// for them.
	defer zeroizeBGPSecrets(cfg)
	if err := cfg.ResolveSecrets(ctx, b.resolver); err != nil {
		return err
	}
	var opts []bgp.SpeakerOption
	if b.server != nil {
		opts = append(opts, bgp.WithBGPServer(b.server))
	}
	speaker, err := bgp.NewSpeaker(cfg, b.logger, opts...)
	if err != nil {
		return err
	}
	if err := speaker.Start(ctx); err != nil {
		return err
	}
	// The configured neighbors are the sessions this gateway holds; adding
	// one that cannot be authenticated as configured (a TCP-AO peer while
	// GoBGP lacks the keychain binding) stops the speaker again rather
	// than leaving a partially peered session table behind.
	for i := range cfg.Neighbors {
		if err := speaker.AddPeer(ctx, &cfg.Neighbors[i]); err != nil {
			if stopErr := speaker.Stop(ctx); stopErr != nil {
				b.logger.Warn("transit: stopping the speaker after a peer refusal failed", slog.Any("error", stopErr))
			}
			return err
		}
	}
	b.speaker = speaker
	return nil
}

// zeroizeBGPSecrets overwrites every resolved TCP-AO master key in cfg.
func zeroizeBGPSecrets(cfg *bgp.BGPConfig) {
	for i := range cfg.Keychains {
		for j := range cfg.Keychains[i].Keys {
			secrets.Zeroize(cfg.Keychains[i].Keys[j].MasterKey)
		}
	}
}

func (b *transitBackend) Stop(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.speaker == nil {
		return nil
	}
	err := b.speaker.Stop(ctx)
	b.speaker = nil
	return err
}

func (b *transitBackend) Active() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.speaker != nil && b.speaker.IsStarted()
}

func (b *transitBackend) Healthy() bool { return b.Active() }

// Speaker returns the running speaker, or nil.
func (b *transitBackend) Speaker() *bgp.Speaker {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.speaker
}

// buildTransit prepares the BGP speaker for the `bgp:` section. The GoBGP
// server and the secret resolver come from HostRuntime when the daemon (or
// a test) injected them; otherwise the speaker runs its own server and a
// peer that references a secret is refused by bgp.ResolveSecrets.
func buildTransit(g *Gateway) (backedService, error) {
	if g.config.BGP == nil {
		return nil, &ErrServiceUnavailable{Service: ServiceTransit, Reason: "the transit service needs a bgp: section"}
	}
	host := g.config.hostRuntime()
	return &transitBackend{config: g.config.BGP, resolver: host.SecretResolver, server: host.BGPServer, logger: host.Logger}, nil
}

// ProxyListenerInventory derives the host filter's listener inventory from
// proxy listener addresses ("host:port"): each becomes a TCP listener on
// every interface, which is what an unpinned bind means to the kernel. A
// port of 0 (kernel-assigned) is omitted because it is unknown before the
// bind. It is the inventory gatewayd assembles for its own proxy listeners.
func ProxyListenerInventory(addresses map[string]string) (hostfw.StaticInventory, error) {
	inv := make(hostfw.StaticInventory, 0, len(addresses))
	for id, address := range addresses {
		_, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, &ErrListenerInventory{Listener: id, Address: address, Cause: err}
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return nil, &ErrListenerInventory{Listener: id, Address: address, Cause: &ErrListenerPort{Port: portText}}
		}
		if port == 0 {
			// A kernel-assigned port is unknown until the listener binds, so
			// the host filter cannot open it ahead of time. The bind still
			// succeeds; the filter simply does not admit it.
			continue
		}
		inv = append(inv, hostfw.Listener{
			Protocol: hostfw.ProtocolTCP,
			Port:     uint16(port),
			Comment:  "proxy " + id,
		})
	}
	return inv, nil
}
