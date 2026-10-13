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
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/firewall"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// desiredState is the gateway's record of desired-config reconciliation
// (#555). now is the clock; nil means time.Now.
type desiredState struct {
	mu    sync.Mutex
	state gwstate.DesiredConfigState
	now   func() time.Time
}

func (d *desiredState) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

// DesiredConfigState reports the last reconciliation for the snapshot.
func (g *Gateway) DesiredConfigState() gwstate.DesiredConfigState {
	g.desired.mu.Lock()
	defer g.desired.mu.Unlock()
	return g.desired.state
}

// Apply reconciles the gateway's live services with the control plane's
// desired configuration. It is declarative and idempotent: a document
// whose effective version was already applied is a no-op; otherwise every
// section present is brought to the desired state through the running
// service, and every section the gateway cannot apply — because the
// service is not enabled on this node — is a typed error. Sections are
// applied independently so one failing section does not stop the others;
// the returned error names every section that failed, and the version is
// recorded as applied only when all of them succeeded.
func (g *Gateway) Apply(ctx context.Context, desired *gwstate.DesiredConfig) error {
	d := &g.desired
	d.mu.Lock()
	defer d.mu.Unlock()

	d.state.AttemptedAt = d.clock()
	if err := desired.Validate(); err != nil {
		d.state.LastError = err.Error()
		return err
	}
	version := desired.EffectiveVersion()
	if version != "" && version == d.state.Version {
		d.state.LastError = ""
		return nil
	}

	// Once the datapath services are supervised they live in the datapath
	// child; the document goes to it whole and its reconciliation state is
	// the truth this gateway reports (#557). Until then they are in this
	// process and the document is applied here.
	// The VPN runs in this process whichever way the datapath runs, so its
	// section is applied here in both cases.
	var failures []error
	if err := g.applyVPN(ctx, desired.VPN); err != nil {
		failures = append(failures, &ErrDesiredApplyFailed{Section: gwstate.SectionVPN, Cause: err})
	}
	if g.supervises(ServiceLoadBalancer) || g.supervises(ServiceNAT) {
		previous := d.state.Version
		state, err := g.config.Supervisor.Apply(ctx, desired)
		d.state = state
		d.state.AttemptedAt = d.clock()
		if err != nil {
			// The child's state already names the version it last applied.
			failures = append(failures, err)
		} else if len(failures) > 0 {
			// The child applied the document but the VPN did not, so the
			// document as a whole is not applied.
			d.state.Version = previous
		}
		if len(failures) > 0 {
			err := errors.Join(failures...)
			d.state.LastError = err.Error()
			return err
		}
		return nil
	}

	if desired.LoadBalancer != nil {
		if err := g.applyLoadBalancer(ctx, desired.LoadBalancer); err != nil {
			failures = append(failures, &ErrDesiredApplyFailed{Section: gwstate.SectionLoadBalancer, Cause: err})
		}
	}
	if desired.NAT != nil {
		if err := g.applyNAT(ctx, desired.NAT); err != nil {
			failures = append(failures, &ErrDesiredApplyFailed{Section: gwstate.SectionNAT, Cause: err})
		}
	}
	if len(failures) > 0 {
		err := errors.Join(failures...)
		d.state.LastError = err.Error()
		return err
	}
	d.state.Version = version
	d.state.AppliedAt = d.state.AttemptedAt
	d.state.LastError = ""
	return nil
}

// applyLoadBalancer makes the live VIP set equal the desired set.
func (g *Gateway) applyLoadBalancer(ctx context.Context, desired *gwstate.DesiredLoadBalancer) error {
	svc, err := g.lbService()
	if err != nil {
		return err
	}
	want := make(map[string]loadbalancer.VIP, len(desired.VIPs))
	order := make([]string, 0, len(desired.VIPs))
	for _, v := range desired.VIPs {
		vip, err := desiredVIP(v)
		if err != nil {
			return err
		}
		want[v.Key()] = vip
		order = append(order, v.Key())
	}
	have := make(map[string]loadbalancer.VIPStatus)
	for _, status := range svc.ListVIPs() {
		have[vipKeyOf(status.VIP)] = status
	}
	for key, status := range have {
		if _, keep := want[key]; keep {
			continue
		}
		if err := svc.RemoveVIP(ctx, status.VIP.Protocol, netip.AddrPortFrom(status.VIP.Address, status.VIP.Port)); err != nil {
			return err
		}
	}
	for _, key := range order {
		vip := want[key]
		current, exists := have[key]
		switch {
		case !exists:
			if err := svc.AddVIP(ctx, vip); err != nil {
				return err
			}
		case !strings.EqualFold(current.VIP.Algorithm, vip.Algorithm):
			// The algorithm is part of the group definition; replace the VIP.
			if err := svc.RemoveVIP(ctx, vip.Protocol, netip.AddrPortFrom(vip.Address, vip.Port)); err != nil {
				return err
			}
			if err := svc.AddVIP(ctx, vip); err != nil {
				return err
			}
		case !sameBackends(current, vip.Backends):
			if err := svc.SetBackends(ctx, vip.Protocol, netip.AddrPortFrom(vip.Address, vip.Port), vip.Backends); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyNAT makes the live SNAT prefix and DNAT set equal the desired ones.
func (g *Gateway) applyNAT(ctx context.Context, desired *gwstate.DesiredNAT) error {
	svc, ok := g.NATService()
	if !ok {
		return &ErrServiceNotActive{Service: ServiceNAT}
	}
	current, enabled := svc.SNATPrefix()
	switch {
	case desired.SNATInternalCIDR == "" && enabled:
		if err := svc.DisableSNAT(ctx); err != nil {
			return err
		}
	case desired.SNATInternalCIDR != "":
		prefix, err := netip.ParsePrefix(desired.SNATInternalCIDR)
		if err != nil {
			return &gwstate.ErrDesiredConfigInvalid{Field: "nat.snat_internal_cidr", Reason: err.Error()}
		}
		if !enabled || current != prefix {
			if enabled {
				if err := svc.DisableSNAT(ctx); err != nil {
					return err
				}
			}
			if err := svc.EnableSNAT(ctx, prefix); err != nil {
				return err
			}
		}
	}

	want := make(map[string]gwstate.DesiredDNAT, len(desired.DNAT))
	for _, rule := range desired.DNAT {
		want[dnatKeyOf(rule.Protocol, rule.External)] = rule
	}
	have := make(map[string]firewall.DNATRule)
	for _, rule := range svc.DNATRules() {
		have[dnatKeyOf(rule.Protocol, rule.External.String())] = rule
	}
	for key, rule := range have {
		wanted, keep := want[key]
		if keep && wanted.Internal == rule.Internal.String() {
			continue
		}
		if err := svc.RemoveDNAT(ctx, rule.Protocol, rule.External); err != nil {
			return err
		}
		delete(have, key)
	}
	for _, rule := range desired.DNAT {
		if _, exists := have[dnatKeyOf(rule.Protocol, rule.External)]; exists {
			continue
		}
		external, err := netip.ParseAddrPort(rule.External)
		if err != nil {
			return &gwstate.ErrDesiredConfigInvalid{Field: "nat.dnat.external", Reason: err.Error()}
		}
		internal, err := netip.ParseAddrPort(rule.Internal)
		if err != nil {
			return &gwstate.ErrDesiredConfigInvalid{Field: "nat.dnat.internal", Reason: err.Error()}
		}
		if err := svc.AddDNAT(ctx, strings.ToLower(rule.Protocol), external, internal); err != nil {
			return err
		}
	}
	return nil
}

// desiredVIP converts the wire VIP into the load balancer's definition.
func desiredVIP(v gwstate.DesiredVIP) (loadbalancer.VIP, error) {
	cfg := VIPConfig{
		Address:   v.Address,
		Port:      v.Port,
		Protocol:  strings.ToLower(v.Protocol),
		Algorithm: v.Algorithm,
		Backends:  make([]BackendConfig, 0, len(v.Backends)),
	}
	for _, b := range v.Backends {
		cfg.Backends = append(cfg.Backends, BackendConfig{Address: b.Address, Port: b.Port, Weight: b.Weight})
	}
	return cfg.ServiceVIP()
}

func vipKeyOf(v loadbalancer.VIP) string {
	return strings.ToLower(v.Protocol) + "/" + netip.AddrPortFrom(v.Address, v.Port).String()
}

func dnatKeyOf(proto, external string) string {
	return strings.ToLower(proto) + "/" + external
}

// sameBackends reports whether the live VIP already serves exactly the
// desired backends (address, port and weight), in any order.
func sameBackends(current loadbalancer.VIPStatus, want []loadbalancer.Backend) bool {
	if len(current.VIP.Backends) != len(want) {
		return false
	}
	have := make(map[string]loadbalancer.Backend, len(current.VIP.Backends))
	for _, b := range current.VIP.Backends {
		have[netip.AddrPortFrom(b.Address, b.Port).String()] = b
	}
	for _, b := range want {
		existing, ok := have[netip.AddrPortFrom(b.Address, b.Port).String()]
		if !ok || existing.Weight != b.Weight {
			return false
		}
	}
	return true
}

// ErrDesiredApplyFailed reports one desired-config section that could not
// be brought to its desired state.
type ErrDesiredApplyFailed struct {
	Section string
	Cause   error
}

// Error implements the error interface.
func (e *ErrDesiredApplyFailed) Error() string {
	return "desired config: section " + e.Section + ": " + e.Cause.Error()
}

// Unwrap returns the section's failure.
func (e *ErrDesiredApplyFailed) Unwrap() error { return e.Cause }
