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
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/firewall"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
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
	ServiceHostFW:       buildHostFW,
	ServiceTunnels:      buildTunnels,
	ServiceTransit:      buildTransit,
}

// serviceRefusals names, per unbuildable section, the blocker that stands
// between the config surface and a running service. The text is what the
// operator reads in ErrServiceUnavailable; it names the missing piece, not
// a promise.
var serviceRefusals = map[string]string{
	ServiceOverlay: "the overlay service has no runnable implementation: the overlay config carries no VTEP fields and " +
		"the overlay handler's encap flow has no output action (pkg/sdn/gateway/modes/overlay.go); " +
		"tracked under epic #553",
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
	for _, name := range g.config.enabledServices() {
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
	Close() error
}

// tunnelsBackend drives the netlink tunnel manager for the `tunnels:`
// section: every configured tunnel is ensured on Start and removed on Stop;
// the service is healthy while every tunnel interface reports up.
type tunnelsBackend struct {
	manager TunnelManager
	configs []tunnel.TunnelConfig
	logger  *slog.Logger

	mu     sync.Mutex
	active bool
}

func (b *tunnelsBackend) Start(ctx context.Context) error {
	for i := range b.configs {
		if err := b.manager.EnsureTunnel(ctx, b.configs[i]); err != nil {
			// Undo what this call created before reporting.
			for j := i - 1; j >= 0; j-- {
				if rmErr := b.manager.RemoveTunnel(ctx, b.configs[j].Name); rmErr != nil {
					b.logger.Warn("tunnel rollback failed", slog.String("tunnel", b.configs[j].Name), slog.Any("error", rmErr))
				}
			}
			return err
		}
	}
	b.mu.Lock()
	b.active = true
	b.mu.Unlock()
	return nil
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

// buildTunnels maps the gateway's `tunnels:` section onto the netlink
// tunnel manager. The manager comes from HostRuntime when the daemon (or a
// test) injected one; otherwise the real netlink manager is used.
func buildTunnels(g *Gateway) (backedService, error) {
	host := g.config.hostRuntime()
	manager := host.TunnelManager
	if manager == nil {
		manager = tunnel.NewManager(host.Logger)
	}
	configs := make([]tunnel.TunnelConfig, 0, len(g.config.Tunnels))
	for i := range g.config.Tunnels {
		configs = append(configs, g.config.Tunnels[i].tunnelConfig())
	}
	return &tunnelsBackend{manager: manager, configs: configs, logger: host.Logger}, nil
}

// tunnelConfig maps the gateway tunnel section onto the tunnel package's
// configuration.
func (t TunnelConfig) tunnelConfig() tunnel.TunnelConfig {
	return tunnel.TunnelConfig{
		Name:     t.Name,
		Type:     t.Type,
		Local:    t.Local,
		Remote:   t.Remote,
		TunnelIP: t.TunnelIP,
	}
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
