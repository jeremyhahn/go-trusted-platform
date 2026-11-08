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
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The measured #509 follow-up: a control plane can hold a valid certificate
// for `cp.example.internal`, complete the NTS-KE handshake, and then refuse
// the client's NTP packets because the name resolves to an address no
// `allow` directive covers. On the fleet the internal zone published `cp` at
// the MANAGEMENT address while chrony.conf allowed only the trusted and
// provisioning /24s.

func addrs(t *testing.T, values ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			t.Fatalf("parse %q: %v", v, err)
		}
		out = append(out, addr)
	}
	return out
}

// servingConfig is the control-plane shape: serves the trusted and
// provisioning segments, advertises one NTS-KE name.
func servingConfig(names ...string) *Config {
	cfg := controlPlaneConfig()
	cfg.Serve.NTS.ServerNames = names
	return cfg
}

// TestEvaluateServeNamesFlagsAnAddressTheAllowListRefuses is the fleet case.
func TestEvaluateServeNamesFlagsAnAddressTheAllowListRefuses(t *testing.T) {
	cfg := servingConfig("cp.example.internal")

	findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		"cp.example.internal": {Addrs: addrs(t, "198.51.100.140")},
	})

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}
	f := findings[0]
	if f.Name != "cp.example.internal" {
		t.Errorf("Name = %q", f.Name)
	}
	if f.Address != "198.51.100.140" {
		t.Errorf("Address = %q, want the address that was refused", f.Address)
	}
	if len(f.ListenNetworks) != 2 {
		t.Errorf("ListenNetworks = %v, want the rendered allow list", f.ListenNetworks)
	}

	// The message must carry all three facts an operator needs to
	// reconcile: which name, which address, and what is allowed.
	msg := f.String()
	for _, want := range []string{"cp.example.internal", "198.51.100.140", "10.4.200.0/24", "192.0.2.0/24"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not name %q", msg, want)
		}
	}
}

// TestEvaluateServeNamesAcceptsAnAllowedAddress covers the healthy case and
// the "one allowed address is enough" rule: chronyd answers that address, so
// a client resolving the name to it is served.
func TestEvaluateServeNamesAcceptsAnAllowedAddress(t *testing.T) {
	cfg := servingConfig("cp.example.internal")

	if findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		"cp.example.internal": {Addrs: addrs(t, "10.4.200.2")},
	}); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for an allowed address", findings)
	}

	if findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		"cp.example.internal": {Addrs: addrs(t, "198.51.100.140", "10.4.200.2")},
	}); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none when one address is allowed", findings)
	}
}

// TestEvaluateServeNamesSeparatesUnresolvedFromRefused asserts the rule that
// keeps this check honest: a name that did not resolve is reported as
// UNRESOLVABLE, never as one the allow list refuses. It has no address, so
// the refusal claim would have nothing behind it. A name that was never
// looked up at all yields nothing.
func TestEvaluateServeNamesSeparatesUnresolvedFromRefused(t *testing.T) {
	cfg := servingConfig("cp.example.internal", "time.example.internal")

	findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		// cp resolved and is allowed; time was never looked up.
		"cp.example.internal": {Addrs: addrs(t, "10.4.200.2")},
	})
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none: an unresolved name is not a refused name", findings)
	}

	if findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		"cp.example.internal": {},
	}); len(findings) != 1 || findings[0].Kind != ServeNameUnresolvable {
		t.Fatalf("findings = %+v, want one unresolvable finding for a name with no addresses", findings)
	}

	if findings := cfg.EvaluateServeNames(nil); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none when nothing resolved", findings)
	}
}

// TestEvaluateServeNamesNotApplicable asserts the check is inert wherever
// there is nothing to reconcile.
func TestEvaluateServeNamesNotApplicable(t *testing.T) {
	resolved := map[string]ServeNameResolution{"cp.example.internal": {Addrs: addrs(t, "198.51.100.140")}}

	var nilCfg *Config
	if findings := nilCfg.EvaluateServeNames(resolved); findings != nil {
		t.Errorf("nil config yielded %+v", findings)
	}

	if findings := servingConfig().EvaluateServeNames(resolved); findings != nil {
		t.Errorf("no configured names yielded %+v", findings)
	}

	consumer := consumerConfig()
	if findings := consumer.EvaluateServeNames(resolved); findings != nil {
		t.Errorf("consume-only node yielded %+v", findings)
	}
}

// TestEvaluateServeNamesSkipsUnparseableAllowEntries asserts a malformed
// allow-list entry is skipped rather than counted as a non-match.
// Validation rejects those already, so reaching one means the config was
// bypassed — and inventing a mismatch from it would be a fabricated finding
// on top of a real configuration bug.
func TestEvaluateServeNamesSkipsUnparseableAllowEntries(t *testing.T) {
	cfg := servingConfig("cp.example.internal")
	cfg.Serve.ListenNetworks = []string{"not-a-cidr", "10.4.200.0/24"}

	if findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		"cp.example.internal": {Addrs: addrs(t, "10.4.200.2")},
	}); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none: the parseable entry still covers the address", findings)
	}

	findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		"cp.example.internal": {Addrs: addrs(t, "198.51.100.140")},
	})
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want the mismatch reported from the parseable entries", findings)
	}
}

// TestEvaluateServeNamesIPv6 covers the v6 allow list and the v4-mapped form
// a resolver may return.
func TestEvaluateServeNamesIPv6(t *testing.T) {
	cfg := servingConfig("cp.example.internal")
	cfg.Serve.ListenNetworks = []string{"fd00:200::/64"}

	if findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		"cp.example.internal": {Addrs: addrs(t, "fd00:200::2")},
	}); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for an allowed v6 address", findings)
	}

	findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		"cp.example.internal": {Addrs: addrs(t, "fd00:999::2")},
	})
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one for a v6 address outside the prefix", findings)
	}

	// A v4-mapped v6 answer for an allowed v4 address is the same host.
	cfg.Serve.ListenNetworks = []string{"10.4.200.0/24"}
	if findings := cfg.EvaluateServeNames(map[string]ServeNameResolution{
		"cp.example.internal": {Addrs: addrs(t, "::ffff:10.4.200.2")},
	}); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none: a v4-mapped answer is the same host", findings)
	}
}

// TestServeNameFindingStringWithNoAllowList asserts the message stays
// readable when the allow list is empty rather than rendering an empty
// parenthesis an operator cannot interpret.
func TestServeNameFindingStringWithNoAllowList(t *testing.T) {
	msg := ServeNameFinding{Name: "cp", Address: "10.0.0.1"}.String()
	if !strings.Contains(msg, "none") {
		t.Errorf("message %q does not say the allow list is empty", msg)
	}
}

// stubResolver answers from a fixed map; a name absent from it fails.
type stubResolver struct {
	answers map[string][]netip.Addr
	calls   []string
	err     error
}

func (r *stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.calls = append(r.calls, host)
	if r.err != nil {
		return nil, r.err
	}
	answer, ok := r.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return answer, nil
}

// serveNameService builds a Service with the given serving config and a
// controller that reports a healthy clock, so a serve-name finding is
// clearly attributable to the name check rather than to the clock.
func serveNameService(t *testing.T, cfg *Config) *Service {
	t.Helper()
	controller := &fakeController{tracking: []*Tracking{{
		Stratum:    3,
		LeapStatus: "Normal",
		RefTime:    time.Unix(1_700_000_000, 0).UTC(),
	}}}
	return newTestService(t, cfg, controller, nil, newMemFS())
}

// TestCheckServeNamesLatchesTheFinding asserts the resolved mismatch is
// latched where the health component reads it, and that the reported status
// carries it.
func TestCheckServeNamesLatchesTheFinding(t *testing.T) {
	service := serveNameService(t, servingConfig("cp.example.internal"))
	resolver := &stubResolver{answers: map[string][]netip.Addr{
		"cp.example.internal": addrs(t, "198.51.100.140"),
	}}

	findings := service.CheckServeNames(context.Background(), resolver)
	if len(findings) != 1 {
		t.Fatalf("CheckServeNames = %+v, want one finding", findings)
	}
	if got := service.ServeNameFindings(); len(got) != 1 || got[0].Name != "cp.example.internal" {
		t.Fatalf("latched findings = %+v", got)
	}

	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(status.ServeNameFindings) != 1 {
		t.Fatalf("status carries %+v, want the latched finding", status.ServeNameFindings)
	}
	// The clock itself is fine; this is a serving-side misconfiguration
	// and must not be reported as an unhealthy clock.
	if !status.Healthy() {
		t.Error("a serve-name mismatch must not make the CLOCK unhealthy")
	}
}

// TestCheckServeNamesClearsAReconciledZone asserts a later run with an
// allowed address clears the finding, so fixing the zone or widening the
// allow list actually clears the health component.
func TestCheckServeNamesClearsAReconciledZone(t *testing.T) {
	service := serveNameService(t, servingConfig("cp.example.internal"))
	bad := &stubResolver{answers: map[string][]netip.Addr{
		"cp.example.internal": addrs(t, "198.51.100.140"),
	}}
	if findings := service.CheckServeNames(context.Background(), bad); len(findings) != 1 {
		t.Fatalf("setup: findings = %+v", findings)
	}

	good := &stubResolver{answers: map[string][]netip.Addr{
		"cp.example.internal": addrs(t, "10.4.200.2"),
	}}
	if findings := service.CheckServeNames(context.Background(), good); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none after reconciliation", findings)
	}
	if got := service.ServeNameFindings(); got != nil {
		t.Fatalf("latched findings = %+v, want cleared", got)
	}
}

// TestCheckServeNamesResolutionFailureIsItsOwnKind asserts a name that does
// not resolve is reported as UNRESOLVABLE with the resolver's own words, and
// never as an allow-list refusal. Nodes forward the internal zone through the
// serving node, so a name it cannot resolve is one no client can reach —
// the same silent failure in a different coat — but it is a different claim
// and carries a different marker.
func TestCheckServeNamesResolutionFailureIsItsOwnKind(t *testing.T) {
	service := serveNameService(t, servingConfig("cp.example.internal"))

	findings := service.CheckServeNames(context.Background(),
		&stubResolver{err: errors.New("resolver unavailable")})
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	f := findings[0]
	if f.Kind != ServeNameUnresolvable {
		t.Fatalf("Kind = %q, want %q", f.Kind, ServeNameUnresolvable)
	}
	if f.Name != "cp.example.internal" {
		t.Errorf("Name = %q", f.Name)
	}
	if !strings.Contains(f.Error, "resolver unavailable") {
		t.Errorf("Error = %q, want the resolver's own words", f.Error)
	}
	// An unresolvable name has no address, so asserting one — or an allow
	// list it was measured against — would be a claim with nothing behind it.
	if f.Address != "" {
		t.Errorf("Address = %q, want empty: an unresolvable name has no address", f.Address)
	}
	if len(f.ListenNetworks) != 0 {
		t.Errorf("ListenNetworks = %v, want empty: this is not an allow-list verdict", f.ListenNetworks)
	}
	if !strings.Contains(f.String(), "does not resolve") {
		t.Errorf("message %q does not say the name did not resolve", f.String())
	}

	if got := service.ServeNameFindings(); len(got) != 1 || got[0].Kind != ServeNameUnresolvable {
		t.Fatalf("latched findings = %+v", got)
	}

	// A name simply missing from the zone is the same kind, with the
	// resolver's message rather than an invented one.
	missing := service.CheckServeNames(context.Background(),
		&stubResolver{answers: map[string][]netip.Addr{}})
	if len(missing) != 1 || missing[0].Kind != ServeNameUnresolvable {
		t.Fatalf("findings = %+v, want one unresolvable finding", missing)
	}
	if missing[0].Error == "" {
		t.Error("an unresolvable finding must carry a reason an operator can act on")
	}
}

// TestCheckServeNamesUnresolvableClears asserts the finding is not sticky: a
// recovered resolver clears it at the next provisioning or renewal, so a
// transient outage does not leave a control plane permanently degraded.
func TestCheckServeNamesUnresolvableClears(t *testing.T) {
	service := serveNameService(t, servingConfig("cp.example.internal"))

	if findings := service.CheckServeNames(context.Background(),
		&stubResolver{err: errors.New("resolver unavailable")}); len(findings) != 1 {
		t.Fatalf("setup: findings = %+v", findings)
	}

	if findings := service.CheckServeNames(context.Background(), &stubResolver{
		answers: map[string][]netip.Addr{"cp.example.internal": addrs(t, "10.4.200.2")},
	}); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none once the resolver recovers", findings)
	}
	if got := service.ServeNameFindings(); got != nil {
		t.Fatalf("latched findings = %+v, want cleared", got)
	}
}

// TestCheckServeNamesReportsBothKindsTogether asserts a node advertising one
// name it refuses and one it cannot resolve reports both, each with its own
// kind. Collapsing them would send an operator to the wrong file.
func TestCheckServeNamesReportsBothKindsTogether(t *testing.T) {
	service := serveNameService(t, servingConfig("cp.example.internal", "time.example.internal"))

	findings := service.CheckServeNames(context.Background(), &stubResolver{
		answers: map[string][]netip.Addr{
			// cp resolves onto a segment the allow list refuses;
			// time.example.internal is absent from the stub, so it fails.
			"cp.example.internal": addrs(t, "198.51.100.140"),
		},
	})
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want both", findings)
	}
	byName := map[string]ServeNameFinding{}
	for _, f := range findings {
		byName[f.Name] = f
	}
	if got := byName["cp.example.internal"].Kind; got != ServeNameUnreachable {
		t.Errorf("cp kind = %q, want %q", got, ServeNameUnreachable)
	}
	if got := byName["time.example.internal"].Kind; got != ServeNameUnresolvable {
		t.Errorf("time kind = %q, want %q", got, ServeNameUnresolvable)
	}
}

// TestCheckServeNamesNotServingIsInert asserts a node with no advertised
// names resolves nothing and latches nothing.
func TestCheckServeNamesNotServingIsInert(t *testing.T) {
	service := serveNameService(t, servingConfig())
	resolver := &stubResolver{}

	if findings := service.CheckServeNames(context.Background(), resolver); findings != nil {
		t.Fatalf("findings = %+v, want none", findings)
	}
	if len(resolver.calls) != 0 {
		t.Errorf("resolver was called %v times with no configured names", resolver.calls)
	}
	if got := service.ServeNameFindings(); got != nil {
		t.Fatalf("latched findings = %+v", got)
	}
}

// TestDefaultNameResolverIsUsable asserts the production default is a real
// resolver rather than a nil interface a caller would panic on.
func TestDefaultNameResolverIsUsable(t *testing.T) {
	if DefaultNameResolver() == nil {
		t.Fatal("DefaultNameResolver returned nil")
	}
}
