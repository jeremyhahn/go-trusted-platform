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

package tunnel

import (
	"context"
	"log/slog"
	"net"
	"sync"

	vnl "github.com/vishvananda/netlink"
)

// Uplink policy routing (#582). Each WAN uplink gets its own routing table
// holding a default route via that ISP's gateway, and ip rules steer (a)
// traffic sourced from the uplink's own addresses and (b) each tunnel's
// outer endpoint pair into that table — the platform's equivalent of the
// ASR's `tunnel route-via … mandatory` plus its return-path PBR. A tunnel
// sourced on uplink A therefore never egresses via uplink B when the main
// table's default moves.
const (
	// MinUplinkTable is the lowest routing table id an uplink may use; the
	// kernel reserves 0, 253-255 and convention leaves 1-99 to operators.
	MinUplinkTable = 100
	// MaxUplinkTable is the highest routing table id an uplink may use.
	MaxUplinkTable = 252
	// DefaultUplinkRulePriority is the ip rule priority for source rules.
	DefaultUplinkRulePriority = 1000
	// tunnelRuleOffset places tunnel endpoint rules ahead of source rules
	// so a tunnel's pin wins over a shared source address.
	tunnelRuleOffset = 100
)

// UplinkConfig describes one WAN uplink.
type UplinkConfig struct {
	// Name is the uplink's identifier, referenced by TunnelConfig.Uplink.
	Name string `yaml:"name" json:"name" mapstructure:"name"`
	// Interface is the Linux interface the uplink lives on.
	Interface string `yaml:"interface" json:"interface" mapstructure:"interface"`
	// Table is the routing table id (100-252), unique per uplink.
	Table int `yaml:"table" json:"table" mapstructure:"table"`
	// GatewayV4 / GatewayV6 are the ISP next hops; at least one is required.
	GatewayV4 string `yaml:"gateway-v4,omitempty" json:"gateway_v4,omitempty" mapstructure:"gateway-v4"`
	GatewayV6 string `yaml:"gateway-v6,omitempty" json:"gateway_v6,omitempty" mapstructure:"gateway-v6"`
	// Addresses are the uplink's own addresses (CIDR); traffic sourced from
	// them is steered into the table.
	Addresses []string `yaml:"addresses" json:"addresses" mapstructure:"addresses"`
	// Priority is the ip rule priority for the source rules (default 1000).
	Priority int `yaml:"priority,omitempty" json:"priority,omitempty" mapstructure:"priority"`
}

// Validate checks the uplink configuration.
func (c *UplinkConfig) Validate() error {
	if c.Name == "" {
		return &ErrInvalidUplinkConfig{Reason: "name is required"}
	}
	if c.Interface == "" {
		return &ErrInvalidUplinkConfig{Name: c.Name, Reason: "interface is required"}
	}
	if c.Table < MinUplinkTable || c.Table > MaxUplinkTable {
		return &ErrInvalidUplinkConfig{Name: c.Name, Reason: "table must be 100-252"}
	}
	if c.GatewayV4 == "" && c.GatewayV6 == "" {
		return &ErrInvalidUplinkConfig{Name: c.Name, Reason: "gateway-v4 or gateway-v6 is required"}
	}
	if c.GatewayV4 != "" {
		gw := net.ParseIP(c.GatewayV4)
		if gw == nil || gw.To4() == nil {
			return &ErrInvalidUplinkConfig{Name: c.Name, Reason: "gateway-v4 is not an IPv4 address"}
		}
	}
	if c.GatewayV6 != "" {
		gw := net.ParseIP(c.GatewayV6)
		if gw == nil || gw.To4() != nil {
			return &ErrInvalidUplinkConfig{Name: c.Name, Reason: "gateway-v6 is not an IPv6 address"}
		}
	}
	if len(c.Addresses) == 0 {
		return &ErrInvalidUplinkConfig{Name: c.Name, Reason: "at least one address is required"}
	}
	for _, a := range c.Addresses {
		if _, _, err := net.ParseCIDR(a); err != nil {
			return &ErrInvalidUplinkConfig{Name: c.Name, Reason: "address " + a + " is not valid CIDR"}
		}
	}
	if c.Priority < 0 {
		return &ErrInvalidUplinkConfig{Name: c.Name, Reason: "priority must not be negative"}
	}
	return nil
}

func (c *UplinkConfig) effectivePriority() int {
	if c.Priority > 0 {
		return c.Priority
	}
	return DefaultUplinkRulePriority
}

// tunnelBinding is one tunnel's outer endpoint pair pinned to an uplink.
type tunnelBinding struct {
	tunnel string
	rules  []*vnl.Rule
}

type managedUplink struct {
	config   UplinkConfig
	ifindex  int
	rules    []*vnl.Rule
	bindings map[string]*tunnelBinding
}

// UplinkManager owns the per-uplink routing tables and rules.
type UplinkManager struct {
	uplinks map[string]*managedUplink
	mu      sync.RWMutex
	logger  *slog.Logger
	nl      netlinkOps
}

// NewUplinkManager creates an UplinkManager over the real netlink.
func NewUplinkManager(logger *slog.Logger) *UplinkManager {
	return newUplinkManagerWithOps(logger, &realNetlinkOps{})
}

func newUplinkManagerWithOps(logger *slog.Logger, nl netlinkOps) *UplinkManager {
	return &UplinkManager{uplinks: make(map[string]*managedUplink), logger: logger, nl: nl}
}

// EnsureUplink installs (idempotently) the uplink's table default route(s)
// and source rules. A changed configuration is torn down and re-installed.
func (u *UplinkManager) EnsureUplink(ctx context.Context, config UplinkConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	if existing, ok := u.uplinks[config.Name]; ok {
		if uplinkConfigEqual(existing.config, config) {
			return nil
		}
		if err := u.removeUplinkLocked(existing); err != nil {
			return err
		}
	}
	link, err := u.nl.LinkByName(config.Interface)
	if err != nil {
		return &ErrUplinkOperationFailed{Name: config.Name, Operation: "resolve interface " + config.Interface, Cause: err}
	}
	mu := &managedUplink{config: config, ifindex: link.Attrs().Index, bindings: make(map[string]*tunnelBinding)}
	if err := u.installRoutes(mu); err != nil {
		return err
	}
	if err := u.installSourceRules(mu); err != nil {
		// Roll back everything this call programmed: the partial rules and
		// the default routes installed just before them. The uplink is not
		// registered, so nothing else would ever remove those routes.
		u.removeRules(mu.rules)
		if rmErr := u.removeRoutes(mu); rmErr != nil {
			// The rule failure is what the caller acts on; a route the
			// rollback could not delete is reported beside it.
			u.logger.Warn("uplink route rollback incomplete", slog.String("name", config.Name), slog.Any("error", rmErr))
		}
		return err
	}
	u.uplinks[config.Name] = mu
	u.logger.Info("uplink programmed", slog.String("name", config.Name), slog.Int("table", config.Table), slog.String("interface", config.Interface))
	return nil
}

func (u *UplinkManager) installRoutes(mu *managedUplink) error {
	for _, gw := range u.defaultRoutes(mu) {
		if err := u.nl.RouteReplace(gw); err != nil {
			return &ErrUplinkOperationFailed{Name: mu.config.Name, Operation: "install default route", Cause: err}
		}
	}
	return nil
}

func (u *UplinkManager) defaultRoutes(mu *managedUplink) []*vnl.Route {
	var routes []*vnl.Route
	if mu.config.GatewayV4 != "" {
		routes = append(routes, &vnl.Route{
			LinkIndex: mu.ifindex, Table: mu.config.Table, Gw: net.ParseIP(mu.config.GatewayV4),
			Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Scope: vnl.SCOPE_UNIVERSE,
		})
	}
	if mu.config.GatewayV6 != "" {
		routes = append(routes, &vnl.Route{
			LinkIndex: mu.ifindex, Table: mu.config.Table, Gw: net.ParseIP(mu.config.GatewayV6),
			Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Scope: vnl.SCOPE_UNIVERSE,
		})
	}
	return routes
}

func (u *UplinkManager) installSourceRules(mu *managedUplink) error {
	existing, err := u.existingRules()
	if err != nil {
		return &ErrUplinkOperationFailed{Name: mu.config.Name, Operation: "list rules", Cause: err}
	}
	for _, a := range mu.config.Addresses {
		ip, ipnet, _ := net.ParseCIDR(a)
		rule := vnl.NewRule()
		rule.Priority = mu.config.effectivePriority()
		rule.Table = mu.config.Table
		rule.Src = hostNet(ip)
		rule.Family = family(ipnet.IP)
		if !ruleInstalled(existing, rule) {
			if err := u.nl.RuleAdd(rule); err != nil {
				return &ErrUplinkOperationFailed{Name: mu.config.Name, Operation: "install source rule " + a, Cause: err}
			}
		}
		mu.rules = append(mu.rules, rule)
	}
	return nil
}

// BindTunnel pins a tunnel's outer endpoints (local → remote) to the
// uplink's table with a higher-priority rule than the source rules.
func (u *UplinkManager) BindTunnel(ctx context.Context, uplink, tunnel, local, remote string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	mu, ok := u.uplinks[uplink]
	if !ok {
		return &ErrUplinkNotFound{Name: uplink}
	}
	if _, bound := mu.bindings[tunnel]; bound {
		return nil
	}
	localIP, remoteIP := net.ParseIP(local), net.ParseIP(remote)
	if localIP == nil || remoteIP == nil {
		return &ErrInvalidUplinkConfig{Name: uplink, Reason: "tunnel " + tunnel + " endpoints are not IP addresses"}
	}
	existing, err := u.existingRules()
	if err != nil {
		return &ErrUplinkOperationFailed{Name: uplink, Operation: "list rules", Cause: err}
	}
	rule := vnl.NewRule()
	rule.Priority = mu.config.effectivePriority() - tunnelRuleOffset
	if rule.Priority < 1 {
		rule.Priority = 1
	}
	rule.Table = mu.config.Table
	rule.Src = hostNet(localIP)
	rule.Dst = hostNet(remoteIP)
	rule.Family = family(localIP)
	if !ruleInstalled(existing, rule) {
		if err := u.nl.RuleAdd(rule); err != nil {
			return &ErrUplinkOperationFailed{Name: uplink, Operation: "bind tunnel " + tunnel, Cause: err}
		}
	}
	mu.bindings[tunnel] = &tunnelBinding{tunnel: tunnel, rules: []*vnl.Rule{rule}}
	return nil
}

// UnbindTunnel removes a tunnel's endpoint rule from its uplink. It is
// idempotent: an uplink that has already been removed (taking the rule with
// it) or a tunnel that was never bound both return nil.
func (u *UplinkManager) UnbindTunnel(ctx context.Context, uplink, tunnel string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	mu, ok := u.uplinks[uplink]
	if !ok {
		// The uplink is gone, and removeUplinkLocked took every binding's
		// rules with it: from the kernel's point of view the tunnel is
		// already unbound, so there is nothing left to undo here.
		return nil
	}
	b, bound := mu.bindings[tunnel]
	if !bound {
		return nil
	}
	for _, r := range b.rules {
		if err := u.nl.RuleDel(r); err != nil {
			return &ErrUplinkOperationFailed{Name: uplink, Operation: "unbind tunnel " + tunnel, Cause: err}
		}
	}
	delete(mu.bindings, tunnel)
	return nil
}

// RemoveUplink tears down the uplink's rules, bindings and table routes.
func (u *UplinkManager) RemoveUplink(ctx context.Context, name string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	mu, ok := u.uplinks[name]
	if !ok {
		return &ErrUplinkNotFound{Name: name}
	}
	return u.removeUplinkLocked(mu)
}

func (u *UplinkManager) removeUplinkLocked(mu *managedUplink) error {
	for _, b := range mu.bindings {
		u.removeRules(b.rules)
	}
	u.removeRules(mu.rules)
	firstErr := u.removeRoutes(mu)
	delete(u.uplinks, mu.config.Name)
	return firstErr
}

// removeRoutes deletes the uplink's default routes, reporting the first
// failure after attempting every route.
func (u *UplinkManager) removeRoutes(mu *managedUplink) error {
	var firstErr error
	for _, r := range u.defaultRoutes(mu) {
		if err := u.nl.RouteDel(r); err != nil && firstErr == nil {
			firstErr = &ErrUplinkOperationFailed{Name: mu.config.Name, Operation: "remove default route", Cause: err}
		}
	}
	return firstErr
}

func (u *UplinkManager) removeRules(rules []*vnl.Rule) {
	for _, r := range rules {
		if err := u.nl.RuleDel(r); err != nil {
			u.logger.Warn("uplink rule removal failed", slog.Any("error", err))
		}
	}
}

// Has reports whether name is a managed uplink.
func (u *UplinkManager) Has(name string) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	_, ok := u.uplinks[name]
	return ok
}

// Close removes every managed uplink.
func (u *UplinkManager) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	var lastErr error
	for _, mu := range u.uplinks {
		if err := u.removeUplinkLocked(mu); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (u *UplinkManager) existingRules() ([]vnl.Rule, error) {
	v4, err := u.nl.RuleList(vnl.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	v6, err := u.nl.RuleList(vnl.FAMILY_V6)
	if err != nil {
		return nil, err
	}
	return append(v4, v6...), nil
}

func ruleInstalled(existing []vnl.Rule, want *vnl.Rule) bool {
	for i := range existing {
		if rulesEqual(&existing[i], want) {
			return true
		}
	}
	return false
}

func rulesEqual(a, b *vnl.Rule) bool {
	return a.Priority == b.Priority && a.Table == b.Table && a.Family == b.Family &&
		ipnetEqual(a.Src, b.Src) && ipnetEqual(a.Dst, b.Dst)
}

func ipnetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.String() == b.String()
}

func family(ip net.IP) int {
	if ip.To4() != nil {
		return vnl.FAMILY_V4
	}
	return vnl.FAMILY_V6
}

func uplinkConfigEqual(a, b UplinkConfig) bool {
	if a.Name != b.Name || a.Interface != b.Interface || a.Table != b.Table ||
		a.GatewayV4 != b.GatewayV4 || a.GatewayV6 != b.GatewayV6 ||
		a.effectivePriority() != b.effectivePriority() || len(a.Addresses) != len(b.Addresses) {
		return false
	}
	for i := range a.Addresses {
		if a.Addresses[i] != b.Addresses[i] {
			return false
		}
	}
	return true
}
