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

package ntp

import (
	"context"
	"net"
	"net/netip"
	"strings"
)

// A serving node advertises an identity (serve.nts.server-names) and, quite
// separately, decides who it will answer (serve.listen-networks). Nothing
// ties the two together: a control plane can hold a valid certificate for
// `cp.example.internal`, complete the NTS-KE handshake with a node that dials
// that name, and then refuse the node's NTP packets because the name resolved
// to an address no `allow` directive covers.
//
// That is not hypothetical. On the measured fleet the internal zone publishes
// `cp` at the control plane's MANAGEMENT address while the rendered
// chrony.conf allows only the trusted and provisioning /24s, so fixing the
// certificate alone would have moved the failure one step later and made it
// harder to see, not easier.
//
// This file is the check that closes the gap. It runs where the identity is
// established — provisioning and renewal — resolves each advertised name, and
// records the ones the node's own allow list refuses. The finding drives the
// `ntp` health component to degraded and names the name, the address and the
// allow list, so the operator is told what to reconcile rather than left with
// a node whose handshake succeeds and whose time never arrives.
//
// It never decides WHICH side is wrong. Widening the allow list to the
// segment the name resolves on, and republishing the name on a segment the
// allow list already covers, are both valid fixes and the choice belongs to
// whoever owns the fleet's addressing.

// ServeNameFindingKind names WHY an advertised NTS-KE name is a problem.
// The two cases are different claims about different things and a consumer
// must be able to tell them apart, so each carries its own stable marker
// that monitoring keys on, alongside TimeUnsyncedMessage.
type ServeNameFindingKind string

const (
	// ServeNameUnreachable: the name resolved, and this node's own allow
	// list refuses the address. A client completes the NTS-KE handshake
	// and is then refused time.
	ServeNameUnreachable ServeNameFindingKind = "nts-name-unreachable"

	// ServeNameUnresolvable: the name did not resolve on this node at all.
	//
	// This is a claim about RESOLUTION, never about the allow list — a
	// name that did not resolve has no address to judge, and reporting one
	// as the other would be the conflation the two kinds exist to prevent.
	// It is still a finding because of how the fleet resolves: nodes
	// forward the internal zone to the control plane, so a name the
	// control plane cannot resolve is one no node can reach either. Same
	// silent failure, different coat.
	ServeNameUnresolvable ServeNameFindingKind = "nts-name-unresolvable"
)

// ServeNameFinding is one advertised NTS-KE server name that clients cannot
// usefully dial, and why.
type ServeNameFinding struct {
	// Kind distinguishes "resolved somewhere I refuse" from "did not
	// resolve here at all".
	Kind ServeNameFindingKind `json:"kind"`

	// Name is the configured serve.nts.server-names entry.
	Name string `json:"name"`

	// Address is where the name resolved, for ServeNameUnreachable. When a
	// name resolves to several addresses and none is allowed, this is the
	// first of them — naming one concrete address an operator can check
	// beats listing all of them. Empty for ServeNameUnresolvable.
	Address string `json:"address,omitempty"`

	// ListenNetworks is the allow list as rendered, so an unreachable
	// finding carries both halves of the mismatch and needs no second
	// lookup. Empty for ServeNameUnresolvable, which is not about the
	// allow list.
	ListenNetworks []string `json:"listen_networks,omitempty"`

	// Error is the resolver's own words, for ServeNameUnresolvable. It is
	// what tells an operator whether the zone lacks the record or the
	// resolver itself is down.
	Error string `json:"error,omitempty"`
}

// String renders the finding as the operator-readable sentence the health
// component, the wire and the log line all share. It does NOT repeat the
// kind: callers prefix that, so the marker appears exactly once.
func (f ServeNameFinding) String() string {
	if f.Kind == ServeNameUnresolvable {
		msg := f.Name + " does not resolve on this node"
		if f.Error != "" {
			msg += " (" + f.Error + ")"
		}
		return msg + "; nodes resolve the internal zone through this one, so no client can reach it either"
	}
	networks := strings.Join(f.ListenNetworks, ", ")
	if networks == "" {
		networks = "none"
	}
	return f.Name + " resolves to " + f.Address +
		", which no serve.listen-networks entry covers (" + networks +
		"); clients will complete the NTS-KE handshake and then be refused time"
}

// ServeNameResolution is one advertised name's lookup outcome, as the pure
// evaluator consumes it. Err and Addrs are the two halves the two finding
// kinds are built from.
type ServeNameResolution struct {
	// Addrs is what the name resolved to.
	Addrs []netip.Addr

	// Err is the resolver's failure, if any.
	Err error
}

// NameResolver resolves a host name to IP addresses.
//
// It is an interface so the check is testable without DNS and so a caller
// can supply the platform's own resolver rather than the host's. The
// signature is *net.Resolver's, which therefore satisfies it directly.
type NameResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DefaultNameResolver returns the host resolver, which on a platform node is
// the local forwarder the `dns:` section configures.
func DefaultNameResolver() NameResolver { return net.DefaultResolver }

// EvaluateServeNames reports every advertised NTS-KE server name a client
// cannot usefully dial, and which of the two ways it fails.
//
// resolved maps a configured name to its lookup outcome. A name ABSENT from
// the map yields nothing — nothing was attempted for it, and inventing a
// verdict from a lookup that never ran would be a fabricated finding. A name
// that WAS looked up and failed, or answered with no addresses, is
// ServeNameUnresolvable carrying the resolver's own words. A name that
// resolved entirely outside the allow list is ServeNameUnreachable.
//
// The two kinds are kept apart deliberately: an unresolvable name has no
// address, so saying the allow list refuses it would be a claim the data
// does not support.
//
// An unparseable allow-list entry is skipped rather than treated as a
// non-match. Validation already rejects those (ErrInvalidListenNetwork), so
// reaching one here means the config was bypassed, and inventing a mismatch
// from it would be a fabricated finding too.
func (c *Config) EvaluateServeNames(resolved map[string]ServeNameResolution) []ServeNameFinding {
	names := c.NTSServerNames()
	if len(names) == 0 {
		return nil
	}

	networks := c.Serve.ListenNetworks
	prefixes := make([]netip.Prefix, 0, len(networks))
	for _, network := range networks {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(network))
		if err != nil {
			continue
		}
		prefixes = append(prefixes, prefix)
	}

	var findings []ServeNameFinding
	for _, name := range names {
		resolution, attempted := resolved[name]
		if !attempted {
			continue
		}
		if resolution.Err != nil || len(resolution.Addrs) == 0 {
			findings = append(findings, ServeNameFinding{
				Kind:  ServeNameUnresolvable,
				Name:  name,
				Error: resolutionError(resolution),
			})
			continue
		}
		if anyAllowed(resolution.Addrs, prefixes) {
			continue
		}
		findings = append(findings, ServeNameFinding{
			Kind:           ServeNameUnreachable,
			Name:           name,
			Address:        resolution.Addrs[0].String(),
			ListenNetworks: append([]string(nil), networks...),
		})
	}
	return findings
}

// resolutionError renders the resolver's failure. A lookup that succeeded
// with no addresses has no error of its own, so it gets a description rather
// than an empty string an operator cannot act on.
func resolutionError(resolution ServeNameResolution) string {
	if resolution.Err != nil {
		return resolution.Err.Error()
	}
	return "the resolver returned no addresses"
}

// anyAllowed reports whether at least one address falls inside one prefix.
// One allowed address is enough: chronyd answers that address, so a client
// resolving the name to it is served.
func anyAllowed(addrs []netip.Addr, prefixes []netip.Prefix) bool {
	for _, addr := range addrs {
		// A v4-mapped v6 address and its v4 form are the same host, and a
		// resolver may hand back either. Compare in the prefix's family.
		candidate := addr.Unmap()
		for _, prefix := range prefixes {
			if prefix.Contains(candidate) {
				return true
			}
			if prefix.Addr().Is6() && prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// CheckServeNames resolves every advertised NTS-KE server name and latches
// the findings so the `ntp` health component reports them.
//
// It is called where the served identity is established or replaced —
// provisioning and certificate renewal — rather than on every status poll: a
// DNS lookup per health probe would put the resolver in the health path, and
// the answer only changes when the configuration or the zone does.
//
// A resolution failure is reported as ServeNameUnresolvable rather than
// swallowed. It is NOT reported as an allow-list refusal: the name has no
// address, so that claim has nothing behind it. Both kinds are findings
// because both leave clients unable to dial the name — on this fleet nodes
// forward the internal zone to the control plane, so a name the control
// plane cannot resolve is one no node can reach.
//
// Findings replace the previous set wholesale, so a reconciled zone or a
// recovered resolver clears the health component at the next provisioning or
// renewal.
func (s *Service) CheckServeNames(ctx context.Context, resolver NameResolver) []ServeNameFinding {
	names := s.config.NTSServerNames()
	if len(names) == 0 {
		s.serveNames.Store(&serveNameState{})
		return nil
	}
	if resolver == nil {
		resolver = DefaultNameResolver()
	}

	resolved := make(map[string]ServeNameResolution, len(names))
	for _, name := range names {
		addrs, err := resolver.LookupNetIP(ctx, "ip", name)
		resolved[name] = ServeNameResolution{Addrs: addrs, Err: err}
	}

	findings := s.config.EvaluateServeNames(resolved)
	for _, finding := range findings {
		s.logger.Warn("ntp: "+string(finding.Kind)+": "+finding.String(),
			"kind", string(finding.Kind), "name", finding.Name,
			"address", finding.Address, "resolver_error", finding.Error,
			"listen_networks", strings.Join(finding.ListenNetworks, ","))
	}
	s.serveNames.Store(&serveNameState{findings: findings})
	return findings
}

// serveNameState is the latched result of the last CheckServeNames run. It
// is stored behind an atomic pointer, like the anomaly state, so Status can
// read it without taking the service lock.
type serveNameState struct {
	findings []ServeNameFinding
}

// ServeNameFindings returns the latched findings, or nil when the check has
// not run or found nothing.
func (s *Service) ServeNameFindings() []ServeNameFinding {
	state := s.serveNames.Load()
	if state == nil || len(state.findings) == 0 {
		return nil
	}
	return append([]ServeNameFinding(nil), state.findings...)
}
