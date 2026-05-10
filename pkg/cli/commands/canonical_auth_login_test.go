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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	authsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/auth"
)

// recordingAuthService is a stub Service that records the LoginRequest
// the canonical handler dispatches for assertion.
type recordingAuthService struct {
	gotLogin *authsvc.LoginRequest
	resp     *authsvc.LoginResult
	err      error
}

func (r *recordingAuthService) AddFactor(_ context.Context, _ *authsvc.AddFactorRequest) (*authsvc.EnrollmentResult, error) {
	return nil, nil
}
func (r *recordingAuthService) ListFactors(_ context.Context, _ string) (*authsvc.ListResult, error) {
	return &authsvc.ListResult{}, nil
}
func (r *recordingAuthService) RemoveFactor(_ context.Context, _ string, _ bool) error { return nil }
func (r *recordingAuthService) RotateFactor(_ context.Context, _ string, _ *authsvc.AddFactorRequest) (*authsvc.EnrollmentResult, error) {
	return nil, nil
}
func (r *recordingAuthService) RelabelFactor(_ context.Context, _, _ string) error { return nil }
func (r *recordingAuthService) Login(_ context.Context, req *authsvc.LoginRequest) (*authsvc.LoginResult, error) {
	r.gotLogin = req
	if r.err != nil {
		return nil, r.err
	}
	if r.resp != nil {
		return r.resp, nil
	}
	return &authsvc.LoginResult{
		UserID:    "u1",
		Username:  "alice",
		Token:     "tok",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}
func (r *recordingAuthService) Close() error { return nil }

// TestCanonicalAuthLogin_ForwardsAllFlags asserts the cobra wiring
// forwards every per-method flag into the SDK LoginRequest. The test
// builds a fresh auth-login command via newAuthLoginCommand so the
// shared rootCmd doesn't leak flag state across tests.
func TestCanonicalAuthLogin_ForwardsAllFlags(t *testing.T) {
	rec := &recordingAuthService{}
	restore := SetAuthClientFactory(func(_ context.Context, _ *cli.CommonFlags) (authsvc.Service, error) {
		return rec, nil
	})
	t.Cleanup(restore)
	t.Setenv("PLATFORMCTL_USER_PIN", "")
	t.Setenv("PLATFORMCTL_CLIENT_CERT", "")
	t.Setenv("PLATFORMCTL_TOKEN_PATH", "")

	cmd := newAuthLoginCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	cmd.SetArgs([]string{
		"--method", "fido2",
		"--factor", "f-uuid",
		"--username", "alice",
		"--device", "yubikey-1",
		"--rp-id", "platform.example.internal",
		"--reader", "Reader 0",
		"--slot", "9c",
		"--pin", "123456",
	})
	if rerr := cmd.Execute(); rerr != nil {
		t.Fatalf("auth login execute error: %v", rerr)
	}
	if rec.gotLogin == nil {
		t.Fatal("Login() was not invoked")
	}
	if rec.gotLogin.Method != "fido2" {
		t.Errorf("Method=%q want fido2", rec.gotLogin.Method)
	}
	if rec.gotLogin.FactorID != "f-uuid" {
		t.Errorf("FactorID=%q want f-uuid", rec.gotLogin.FactorID)
	}
	if rec.gotLogin.Username != "alice" {
		t.Errorf("Username=%q want alice", rec.gotLogin.Username)
	}
	if rec.gotLogin.Device != "yubikey-1" {
		t.Errorf("Device=%q want yubikey-1", rec.gotLogin.Device)
	}
	if rec.gotLogin.RPID != "platform.example.internal" {
		t.Errorf("RPID=%q want platform.example.internal", rec.gotLogin.RPID)
	}
	if rec.gotLogin.Reader != "Reader 0" {
		t.Errorf("Reader=%q want Reader 0", rec.gotLogin.Reader)
	}
	if rec.gotLogin.Slot != "9c" {
		t.Errorf("Slot=%q want 9c", rec.gotLogin.Slot)
	}
	if rec.gotLogin.PIN != "123456" {
		t.Errorf("PIN=%q want 123456", rec.gotLogin.PIN)
	}
}

// TestCanonicalAuthLogin_PropagatesError ensures errors bubble up.
func TestCanonicalAuthLogin_PropagatesError(t *testing.T) {
	cause := errors.New("server rejected proof")
	rec := &recordingAuthService{err: cause}
	restore := SetAuthClientFactory(func(_ context.Context, _ *cli.CommonFlags) (authsvc.Service, error) {
		return rec, nil
	})
	t.Cleanup(restore)

	cmd, _, err := rootCmd.Find([]string{"auth", "login"})
	if err != nil {
		t.Fatalf("auth login not found: %v", err)
	}
	cmd.ResetFlags()
	// Re-register flags via a fresh builder so prior tests don't bleed.
	freshCmd := newAuthLoginCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	freshCmd.SetArgs([]string{"--method", "mtls", "--client-cert", "/no/such/file.pem"})
	if rerr := freshCmd.Execute(); rerr == nil {
		t.Fatal("expected error for missing cert path")
	}
}

// TestResolveAuthLoginEnv_FillsBlankFlags verifies the env-var
// fallbacks fill blank flags.
func TestResolveAuthLoginEnv_FillsBlankFlags(t *testing.T) {
	t.Setenv("PLATFORMCTL_USER_PIN", "envpin")
	t.Setenv("PLATFORMCTL_CLIENT_CERT", "/env/cert.pem")
	t.Setenv("PLATFORMCTL_TOKEN_PATH", "/env/token")
	opts := &authLoginOptions{}
	resolveAuthLoginEnv(opts)
	if opts.PIN != "envpin" {
		t.Errorf("PIN = %q, want envpin", opts.PIN)
	}
	if opts.ClientCertPath != "/env/cert.pem" {
		t.Errorf("ClientCertPath = %q, want /env/cert.pem", opts.ClientCertPath)
	}
	if opts.TokenPath != "/env/token" {
		t.Errorf("TokenPath = %q, want /env/token", opts.TokenPath)
	}
}

// TestResolveAuthLoginEnv_DoesNotOverrideExplicit verifies env-vars
// don't override values already set on the struct.
func TestResolveAuthLoginEnv_DoesNotOverrideExplicit(t *testing.T) {
	t.Setenv("PLATFORMCTL_USER_PIN", "envpin")
	opts := &authLoginOptions{PIN: "flagpin"}
	resolveAuthLoginEnv(opts)
	if opts.PIN != "flagpin" {
		t.Errorf("PIN = %q, want flagpin (env should not override)", opts.PIN)
	}
}

// TestWriteSessionToken persists the issued JWT.
func TestWriteSessionToken(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "session.token")
	got, err := writeSessionToken(path, "JWT.HEAD.SIG")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Errorf("expected %q, got %q", path, got)
	}
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(data) != "JWT.HEAD.SIG\n" {
		t.Errorf("unexpected token contents: %q", data)
	}
}

// TestWriteSessionToken_DefaultPath uses ~/.platformctl/session.token.
func TestWriteSessionToken_DefaultPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	got, err := writeSessionToken("", "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(tmp, ".platformctl", "session.token")
	if got != want {
		t.Errorf("expected default path %q, got %q", want, got)
	}
	if _, statErr := os.Stat(got); statErr != nil {
		t.Errorf("file not written: %v", statErr)
	}
}
