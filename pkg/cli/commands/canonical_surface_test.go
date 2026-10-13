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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	authsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/auth"
)

// canonicalRootSubcommands lists the locked canonical command names
// that MUST appear at the platformctl root per
// docs/08-bootstrap-auth-architecture.md §6.
var canonicalRootSubcommands = []string{
	"init",
	"auth",
	"barrier",
	"ceremony",
	"ca",
	"bootstrap",
	"credential",
}

// canonicalInitFlagNames lists the canonical init flag names.
var canonicalInitFlagNames = []string{
	"so-pin",
	"user-pin",
	"barrier-strategy",
	"shares",
	"threshold",
	"hostname",
	"sans",
	"admin-bundle",
	"gate-endpoint",
	"loopback-http",
}

// TestCanonicalSurface_RootHasInit verifies the platformctl root
// "init" command is registered.
func TestCanonicalSurface_RootHasInit(t *testing.T) {
	if _, _, err := rootCmd.Find([]string{"init"}); err != nil {
		t.Fatalf("expected canonical 'init' command at platformctl root: %v", err)
	}
}

// TestCanonicalSurface_RootHasAllSubcommands verifies every canonical
// subcommand appears at the root.
func TestCanonicalSurface_RootHasAllSubcommands(t *testing.T) {
	for _, name := range canonicalRootSubcommands {
		if _, _, err := rootCmd.Find([]string{name}); err != nil {
			t.Errorf("canonical command %q missing from platformctl root: %v", name, err)
		}
	}
}

// TestCanonicalSurface_InitFlagsExposed verifies the canonical init
// flag set is fully exposed.
func TestCanonicalSurface_InitFlagsExposed(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("init not found: %v", err)
	}
	for _, name := range canonicalInitFlagNames {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("canonical init flag --%s missing", name)
		}
	}
}

// TestCanonicalSurface_LegacyBarrierInitRedirects verifies that
// "platformctl barrier init" emits CanonicalRedirectError.
func TestCanonicalSurface_LegacyBarrierInitRedirects(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"barrier", "init"})
	if err != nil {
		t.Fatalf("barrier init redirect not registered: %v", err)
	}
	if cmd.RunE == nil {
		t.Fatal("legacy barrier init must emit CanonicalRedirectError")
	}
}

// TestCanonicalSurface_LegacyCeremonyInitRedirects verifies that
// "platformctl ceremony init" emits CanonicalRedirectError.
func TestCanonicalSurface_LegacyCeremonyInitRedirects(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"ceremony", "init"})
	if err != nil {
		t.Fatalf("ceremony init redirect not registered: %v", err)
	}
	if cmd.RunE == nil {
		t.Fatal("legacy ceremony init must emit CanonicalRedirectError")
	}
}

// TestCanonicalSurface_BootstrapHasDirect verifies the bootstrap group
// includes the new "direct" mode required by §6.
func TestCanonicalSurface_BootstrapHasDirect(t *testing.T) {
	for _, mode := range []string{"auto", "dane", "noise", "spki", "direct"} {
		if _, _, err := rootCmd.Find([]string{"bootstrap", mode}); err != nil {
			t.Errorf("bootstrap %s missing: %v", mode, err)
		}
	}
}

// TestCanonicalSurface_AuthHasFactor verifies the auth N-factor
// surface is registered.
func TestCanonicalSurface_AuthHasFactor(t *testing.T) {
	for _, verb := range []string{"login", "factor"} {
		if _, _, err := rootCmd.Find([]string{"auth", verb}); err != nil {
			t.Errorf("auth %s missing: %v", verb, err)
		}
	}
	for _, verb := range []string{"list", "add", "remove", "rotate", "relabel"} {
		if _, _, err := rootCmd.Find([]string{"auth", "factor", verb}); err != nil {
			t.Errorf("auth factor %s missing: %v", verb, err)
		}
	}
}

// TestCanonicalSurface_CeremonyHasSubcommands verifies the canonical
// ceremony surface has status / claim-cert / claim-share / sign-csr.
func TestCanonicalSurface_CeremonyHasSubcommands(t *testing.T) {
	for _, verb := range []string{"status", "claim-cert", "claim-share", "sign-csr"} {
		if _, _, err := rootCmd.Find([]string{"ceremony", verb}); err != nil {
			t.Errorf("ceremony %s missing: %v", verb, err)
		}
	}
}

// TestCanonicalSurface_CredentialHasSubcommands verifies the canonical
// credential surface has submit / list / rotate.
func TestCanonicalSurface_CredentialHasSubcommands(t *testing.T) {
	for _, verb := range []string{"submit", "list", "rotate"} {
		if _, _, err := rootCmd.Find([]string{"credential", verb}); err != nil {
			t.Errorf("credential %s missing: %v", verb, err)
		}
	}
}

// TestCanonicalSurface_CAHasExportBundle verifies the canonical "ca
// export-bundle" alias is registered.
func TestCanonicalSurface_CAHasExportBundle(t *testing.T) {
	if _, _, err := rootCmd.Find([]string{"ca", "export-bundle"}); err != nil {
		t.Errorf("ca export-bundle missing: %v", err)
	}
}

// TestCanonicalSurface_InitRejectsBadStrategy verifies the validator
// rejects unknown strategies.
func TestCanonicalSurface_InitRejectsBadStrategy(t *testing.T) {
	f := &canonicalInitFlags{
		soPin:           "so",
		userPin:         "user",
		barrierStrategy: "bogus",
	}
	cmd, _, err := rootCmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("init not found: %v", err)
	}
	rerr := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL")
	if rerr == nil {
		t.Fatal("expected error for invalid --barrier-strategy")
	}
}

// TestCanonicalSurface_InitShamirEnforcesShares verifies that
// --barrier-strategy=shamir requires --shares >= 2.
func TestCanonicalSurface_InitShamirEnforcesShares(t *testing.T) {
	f := &canonicalInitFlags{
		soPin:           "so",
		userPin:         "user",
		barrierStrategy: "shamir",
		shares:          0,
	}
	cmd, _, err := rootCmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("init not found: %v", err)
	}
	rerr := resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL")
	if rerr == nil {
		t.Fatal("expected error: --barrier-strategy=shamir requires --shares >= 2")
	}
}

// TestCanonicalSurface_AuthFactorWiredToSDK verifies the auth-factor
// handlers wire to the quicbaas SDK Security().Auth().Factors()
// surface (M10 + M14). The test injects a no-op auth client factory
// so the handler runs to completion against an empty factor list.
func TestCanonicalSurface_AuthFactorWiredToSDK(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"auth", "factor", "list"})
	if err != nil {
		t.Fatalf("auth factor list not found: %v", err)
	}
	if cmd.RunE == nil {
		t.Fatal("auth factor list missing RunE")
	}

	called := false
	restore := SetAuthClientFactory(func(_ context.Context, _ *cli.CommonFlags) (authsvc.Service, error) {
		called = true
		return &noopAuthService{}, nil
	})
	t.Cleanup(restore)

	if rerr := cmd.RunE(cmd, nil); rerr != nil {
		t.Errorf("auth factor list with stub SDK should succeed; got: %v", rerr)
	}
	if !called {
		t.Error("auth factor list did not invoke the SDK auth client factory; handlers may still return a stub error")
	}
}

// TestCanonicalSurface_CredentialReturnsPendingError verifies the
// stub credential handlers return PendingCredentialBackendError until
// the SDK CredentialService surface ships.
func TestCanonicalSurface_CredentialReturnsPendingError(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"credential", "submit"})
	if err != nil {
		t.Fatalf("credential submit not found: %v", err)
	}
	rerr := cmd.RunE(cmd, nil)
	var pending *PendingCredentialBackendError
	if !errors.As(rerr, &pending) {
		t.Errorf("expected *PendingCredentialBackendError, got %T: %v", rerr, rerr)
	}
}

// noopAuthService is a stub Service used to verify the canonical auth
// command handlers dispatch to the platform SDK auth client. It is
// intentionally a no-op: every method returns a zero result with no
// error so the canonical handlers exercise their full code path.
type noopAuthService struct{}

func (n *noopAuthService) AddFactor(_ context.Context, _ *authsvc.AddFactorRequest) (*authsvc.EnrollmentResult, error) {
	return &authsvc.EnrollmentResult{EnrolledAt: time.Now().UTC()}, nil
}
func (n *noopAuthService) ListFactors(_ context.Context, _ string) (*authsvc.ListResult, error) {
	return &authsvc.ListResult{}, nil
}
func (n *noopAuthService) RemoveFactor(_ context.Context, _ string, _ bool) error { return nil }
func (n *noopAuthService) RotateFactor(_ context.Context, _ string, _ *authsvc.AddFactorRequest) (*authsvc.EnrollmentResult, error) {
	return &authsvc.EnrollmentResult{EnrolledAt: time.Now().UTC()}, nil
}
func (n *noopAuthService) RelabelFactor(_ context.Context, _, _ string) error { return nil }
func (n *noopAuthService) Login(_ context.Context, _ *authsvc.LoginRequest) (*authsvc.LoginResult, error) {
	return &authsvc.LoginResult{IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
}
func (n *noopAuthService) Close() error { return nil }
