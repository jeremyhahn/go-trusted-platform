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

// Package calleradmission decides which authenticated machine peers may ask
// this node for a TPM quote (#226, owner-ruled 2026-09-03 and 2026-09-04).
//
// # Two claims, kept separate
//
// A peer makes two claims: WHO it is (identity, proven by a client
// certificate chaining to the configured anchors) and WHAT STATE it is in
// (attestation, proven by evidence about the peer itself). This package
// evaluates the first and the configured strategy; the state gate is the
// upstream attested-caller middleware (go-qrdb#278 over go-xkms#273) and
// composes in front of this policy when it lands. Until then the
// any-attested strategy is honoured only where attested-peer evidence exists
// locally, and refuses everyone elsewhere — it never degrades to "any valid
// certificate", because that would widen trust silently.
//
// # Fail closed
//
// Every path that cannot prove admission refuses: no anchors configured, a
// certificate that does not chain, a certificate with no name, a name not on
// the list, an empty or unparseable list, or an attestation gate that cannot
// answer. Refusals carry a Reason so the audit trail distinguishes "not on
// the list" from "measured state unacceptable" — one of those is a security
// incident and the other is a configuration error.
//
// Nothing in this package reads a request body or trusts a header; identity
// comes from the TLS layer only.
package calleradmission

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"
)

// Strategy names the admission strategy. The string values are the
// configuration vocabulary (pkg/config).
type Strategy string

const (
	// StrategyReportingServers admits only the configured reporting-server
	// identities. Default.
	StrategyReportingServers Strategy = "reporting-servers"
	// StrategyAnyAttested admits any peer whose own attestation is verified
	// and fresh, as reported by an AttestedPeers source.
	StrategyAnyAttested Strategy = "any-attested"
	// StrategyAllowlist admits an explicit list of peer identities.
	StrategyAllowlist Strategy = "allowlist"
)

// Reason explains a decision. The values are stable audit vocabulary.
type Reason string

const (
	ReasonAdmitted        Reason = "admitted"
	ReasonNoAnchors       Reason = "no-trust-anchors"
	ReasonUntrustedIssuer Reason = "untrusted-issuer"
	ReasonNoIdentity      Reason = "no-identity"
	ReasonNotListed       Reason = "not-listed"
	ReasonListEmpty       Reason = "list-empty"
	ReasonListInvalid     Reason = "list-invalid"
	ReasonNotAttested     Reason = "not-attested"
	ReasonStale           Reason = "attestation-stale"
	ReasonGateUnavailable Reason = "attestation-gate-unavailable"
)

// SecurityRelevant reports whether a refusal for this reason describes a
// peer that proved its identity and was refused on state — the refusals an
// operator must treat as a possible incident rather than a misconfiguration.
func (r Reason) SecurityRelevant() bool {
	switch r {
	case ReasonNotAttested, ReasonStale:
		return true
	default:
		return false
	}
}

// Peer is what the TLS layer presented: the leaf certificate, any
// intermediates sent with it, and the transport address.
type Peer struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
	RemoteAddr    string
}

// PeerFromTLS extracts the presented certificate chain from a connection
// state. It returns false when no certificate was presented at all, which is
// the "no machine identity, let the operator path decide" case rather than a
// refusal.
func PeerFromTLS(cs *tls.ConnectionState, remoteAddr string) (*Peer, bool) {
	if cs == nil || len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0] == nil {
		return nil, false
	}
	return &Peer{
		Leaf:          cs.PeerCertificates[0],
		Intermediates: cs.PeerCertificates[1:],
		RemoteAddr:    remoteAddr,
	}, true
}

// Names returns the identities a certificate carries for matching: its DNS
// SANs, lower-cased, trimmed, de-duplicated and sorted. The Common Name is
// used ONLY when the certificate carries no DNS SAN at all (owner ruling
// 2026-09-05): a modern certificate's identity is its SANs, and a CN that
// disagrees with them must not become a second way to match.
func Names(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	seen := make(map[string]struct{}, 1+len(cert.DNSNames))
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			return
		}
		seen[n] = struct{}{}
	}
	for _, n := range cert.DNSNames {
		add(n)
	}
	if len(seen) == 0 {
		add(cert.Subject.CommonName)
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// PeerAttestation is what an AttestedPeers source knows about a peer.
type PeerAttestation struct {
	// Verified is the peer's most recent verdict.
	Verified bool
	// Fresh reports whether that verdict is inside its freshness window.
	Fresh bool
}

// AttestedPeers answers whether a peer identity is currently attested. The
// reporting cache on a control plane provides one; a worker node has none.
type AttestedPeers interface {
	// PeerAttestation looks a peer up by any of its certificate names. ok is
	// false when the source holds nothing about that peer.
	PeerAttestation(names []string) (att PeerAttestation, ok bool)
}

// Decision is the outcome of one admission evaluation.
type Decision struct {
	Admitted bool
	// Identity is the peer's primary name (Common Name, else first SAN).
	Identity string
	// Names are all identities the certificate carried.
	Names      []string
	Strategy   Strategy
	Reason     Reason
	Detail     string
	RemoteAddr string
	At         time.Time
}

// Auditor records every decision. Refusals are never silent.
type Auditor interface {
	RecordAdmission(ctx context.Context, d Decision) error
}

// Config configures a Policy.
type Config struct {
	// Strategy selects the admission strategy. Required to be one of the
	// three; the config layer applies the default.
	Strategy Strategy
	// ReportingServers is the identity set for StrategyReportingServers.
	ReportingServers []string
	// ReportingServersSource says where that set came from, for Describe.
	ReportingServersSource string
	// Allowlist is the identity set for StrategyAllowlist.
	Allowlist []string
	// Anchors are the CA certificates a caller must chain to. Empty refuses
	// every machine caller.
	Anchors []*x509.Certificate
	// AnchorSource says where the anchors came from, for Describe.
	AnchorSource string
	// AttestedPeers backs StrategyAnyAttested. nil makes that strategy
	// refuse everyone.
	AttestedPeers AttestedPeers
	// Auditor receives every decision. Optional.
	Auditor Auditor
	// Logger is optional.
	Logger *slog.Logger
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// Policy is a compiled admission policy.
type Policy struct {
	strategy      Strategy
	reporting     identitySet
	reportingSrc  string
	allowlist     identitySet
	anchors       []*x509.Certificate
	pool          *x509.CertPool
	anchorSource  string
	attestedPeers AttestedPeers
	auditor       Auditor
	logger        *slog.Logger
	now           func() time.Time
}

// New compiles a policy. The only construction failure is an unknown
// strategy: every other misconfiguration compiles to a policy that refuses,
// so the node still starts and still answers operators.
func New(cfg Config) (*Policy, error) {
	switch cfg.Strategy {
	case StrategyReportingServers, StrategyAnyAttested, StrategyAllowlist:
	default:
		return nil, ErrUnknownStrategy{Strategy: string(cfg.Strategy)}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	var anchors []*x509.Certificate
	var pool *x509.CertPool
	for _, c := range cfg.Anchors {
		if c == nil {
			continue
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AddCert(c)
		anchors = append(anchors, c)
	}
	p := &Policy{
		strategy:      cfg.Strategy,
		reporting:     compileIdentitySet(cfg.ReportingServers),
		reportingSrc:  cfg.ReportingServersSource,
		allowlist:     compileIdentitySet(cfg.Allowlist),
		anchors:       anchors,
		pool:          pool,
		anchorSource:  cfg.AnchorSource,
		attestedPeers: cfg.AttestedPeers,
		auditor:       cfg.Auditor,
		logger:        logger,
		now:           now,
	}
	if pool == nil {
		logger.Warn("attestation caller admission: no trust anchors; every machine caller will be refused",
			"strategy", string(cfg.Strategy))
	}
	if !p.activeSet().valid {
		logger.Error("attestation caller admission: identity list is unparseable; every machine caller will be refused",
			"strategy", string(cfg.Strategy), "invalid", p.activeSet().invalid)
	} else if p.strategy != StrategyAnyAttested && len(p.activeSet().names) == 0 {
		logger.Warn("attestation caller admission: identity list is empty; every machine caller will be refused",
			"strategy", string(cfg.Strategy))
	}
	return p, nil
}

// Strategy returns the compiled strategy.
func (p *Policy) Strategy() Strategy { return p.strategy }

// Anchors returns the trust anchors a caller must chain to, for a listener
// that needs to request certificates from them. Empty when none are set.
func (p *Policy) Anchors() []*x509.Certificate {
	return append([]*x509.Certificate(nil), p.anchors...)
}

// Evaluate decides whether a peer is admitted and audits the decision.
func (p *Policy) Evaluate(ctx context.Context, peer *Peer) Decision {
	d := p.decide(peer)
	d.Strategy = p.strategy
	d.At = p.now()
	if peer != nil {
		d.RemoteAddr = peer.RemoteAddr
	}
	p.audit(ctx, d)
	return d
}

func (p *Policy) decide(peer *Peer) Decision {
	if peer == nil || peer.Leaf == nil {
		return Decision{Reason: ReasonNoIdentity, Detail: "no client certificate was presented"}
	}
	names := Names(peer.Leaf)
	d := Decision{Names: names, Identity: primaryName(peer.Leaf, names)}

	if p.pool == nil {
		d.Reason = ReasonNoAnchors
		d.Detail = "no caller trust anchors are configured on this node"
		return d
	}
	if err := verifyChain(peer, p.pool, p.now()); err != nil {
		d.Reason = ReasonUntrustedIssuer
		d.Detail = err.Error()
		return d
	}
	if len(names) == 0 {
		d.Reason = ReasonNoIdentity
		d.Detail = "client certificate carries neither a Common Name nor a DNS SAN"
		return d
	}

	switch p.strategy {
	case StrategyReportingServers:
		return p.decideByList(d, p.reporting, "reporting server")
	case StrategyAllowlist:
		return p.decideByList(d, p.allowlist, "allowlisted host")
	case StrategyAnyAttested:
		return p.decideByAttestation(d)
	}
	d.Reason = ReasonGateUnavailable
	d.Detail = "no strategy compiled"
	return d
}

func (p *Policy) decideByList(d Decision, set identitySet, role string) Decision {
	if !set.valid {
		d.Reason = ReasonListInvalid
		d.Detail = "identity list contains an unparseable entry: " + strings.Join(set.invalid, ", ")
		return d
	}
	if len(set.names) == 0 {
		d.Reason = ReasonListEmpty
		d.Detail = "identity list is empty; nobody is a " + role
		return d
	}
	for _, n := range d.Names {
		if _, ok := set.names[n]; ok {
			d.Admitted = true
			d.Reason = ReasonAdmitted
			d.Detail = n + " is a configured " + role
			return d
		}
	}
	d.Reason = ReasonNotListed
	d.Detail = "none of " + strings.Join(d.Names, ", ") + " is a configured " + role
	return d
}

func (p *Policy) decideByAttestation(d Decision) Decision {
	if p.attestedPeers == nil {
		d.Reason = ReasonGateUnavailable
		d.Detail = "this node holds no attested-peer evidence; any-attested cannot be honoured here (go-qrdb#278)"
		return d
	}
	att, ok := p.attestedPeers.PeerAttestation(d.Names)
	if !ok {
		d.Reason = ReasonNotAttested
		d.Detail = "no attestation report exists for " + d.Identity
		return d
	}
	if !att.Verified {
		d.Reason = ReasonNotAttested
		d.Detail = "the most recent attestation of " + d.Identity + " failed"
		return d
	}
	if !att.Fresh {
		d.Reason = ReasonStale
		d.Detail = "the most recent attestation of " + d.Identity + " is past its freshness window"
		return d
	}
	d.Admitted = true
	d.Reason = ReasonAdmitted
	d.Detail = d.Identity + " is currently attested"
	return d
}

func (p *Policy) audit(ctx context.Context, d Decision) {
	if p.auditor == nil {
		return
	}
	if err := p.auditor.RecordAdmission(ctx, d); err != nil {
		p.logger.Error("attestation caller admission: decision could not be audited",
			"identity", d.Identity, "admitted", d.Admitted, "reason", string(d.Reason), "error", err)
	}
}

func (p *Policy) activeSet() identitySet {
	if p.strategy == StrategyAllowlist {
		return p.allowlist
	}
	return p.reporting
}

// Description is the policy as an operator sees it: what is enforced, not
// what was intended.
type Description struct {
	Strategy Strategy `json:"strategy"`
	// Identities is the effective identity list for the list strategies.
	Identities []string `json:"identities"`
	// IdentitiesSource says where the list came from.
	IdentitiesSource string `json:"identities_source,omitempty"`
	// ListValid is false when an entry could not be parsed, in which case
	// every caller is refused.
	ListValid bool `json:"list_valid"`
	// InvalidEntries lists the entries that failed to parse.
	InvalidEntries []string `json:"invalid_entries,omitempty"`
	// AnchorsConfigured reports whether any trust anchor is set.
	AnchorsConfigured bool   `json:"anchors_configured"`
	AnchorSource      string `json:"anchor_source,omitempty"`
	// AttestedPeersAvailable reports whether any-attested can be honoured.
	AttestedPeersAvailable bool `json:"attested_peers_available"`
	// AdmitsNobody is true when the compiled policy cannot admit any
	// caller, whatever it presents.
	AdmitsNobody bool `json:"admits_nobody"`
}

// Describe reports the effective policy.
func (p *Policy) Describe() Description {
	set := p.activeSet()
	desc := Description{
		Strategy:               p.strategy,
		Identities:             set.sorted(),
		ListValid:              set.valid,
		InvalidEntries:         set.invalid,
		AnchorsConfigured:      p.pool != nil,
		AnchorSource:           p.anchorSource,
		AttestedPeersAvailable: p.attestedPeers != nil,
	}
	switch p.strategy {
	case StrategyAllowlist:
		desc.IdentitiesSource = "configured"
	case StrategyReportingServers:
		desc.IdentitiesSource = p.reportingSrc
	case StrategyAnyAttested:
		desc.Identities = nil
		desc.ListValid = true
		desc.InvalidEntries = nil
	}
	switch {
	case p.pool == nil:
		desc.AdmitsNobody = true
	case p.strategy == StrategyAnyAttested:
		desc.AdmitsNobody = p.attestedPeers == nil
	default:
		desc.AdmitsNobody = !set.valid || len(set.names) == 0
	}
	return desc
}

// identitySet is a compiled name list.
type identitySet struct {
	names   map[string]struct{}
	invalid []string
	valid   bool
}

func compileIdentitySet(entries []string) identitySet {
	set := identitySet{names: make(map[string]struct{}, len(entries)), valid: true}
	for _, raw := range entries {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" || !validHostIdentity(name) {
			set.invalid = append(set.invalid, strings.TrimSpace(raw))
			set.valid = false
			continue
		}
		set.names[name] = struct{}{}
	}
	return set
}

func (s identitySet) sorted() []string {
	out := make([]string, 0, len(s.names))
	for n := range s.names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// validHostIdentity accepts a DNS host name or an IP literal — the forms a
// certificate Common Name or SAN takes. Anything else is unparseable.
func validHostIdentity(name string) bool {
	if net.ParseIP(name) != nil {
		return true
	}
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			case r == '-' && i != 0 && i != len(label)-1:
			default:
				return false
			}
		}
	}
	return true
}

// primaryName is the identity a decision is recorded under: the first DNS
// SAN in certificate order, else the Common Name.
func primaryName(cert *x509.Certificate, names []string) string {
	for _, n := range cert.DNSNames {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			return n
		}
	}
	if cn := strings.ToLower(strings.TrimSpace(cert.Subject.CommonName)); cn != "" {
		return cn
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

// verifyChain proves the leaf chains to the anchors with the client-auth
// key usage, independently of what the listener's own ClientCAs accepted:
// the listener pool is a union that also admits the node's own CA, and a
// certificate the node issued to itself is not a reporting server.
func verifyChain(peer *Peer, anchors *x509.CertPool, now time.Time) error {
	opts := x509.VerifyOptions{
		Roots:         anchors,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   now,
	}
	for _, c := range peer.Intermediates {
		if c != nil {
			opts.Intermediates.AddCert(c)
		}
	}
	if _, err := peer.Leaf.Verify(opts); err != nil {
		return ErrChainVerification{Cause: err}
	}
	return nil
}
