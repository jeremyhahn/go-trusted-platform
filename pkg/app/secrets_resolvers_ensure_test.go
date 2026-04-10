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
	"log/slog"
	"testing"
	"time"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// fakeSecretsService records calls to EnsureSecret / GetSecret and
// returns canned responses, so the LocalSecretsResolver test can
// assert on the exact arguments the resolver passes down.
type fakeSecretsService struct {
	baasservice.SecretsService
	ensureCalls   []*baasservice.EnsureSecretRequest
	ensureResp    *baasservice.EnsureSecretResponse
	ensureErr     error
	getCalls      []*baasservice.GetSecretRequest
	getResp       *baasservice.GetSecretResponse
	getErr        error
}

func (f *fakeSecretsService) EnsureSecret(ctx context.Context, req *baasservice.EnsureSecretRequest) (*baasservice.EnsureSecretResponse, error) {
	f.ensureCalls = append(f.ensureCalls, req)
	if f.ensureErr != nil {
		return nil, f.ensureErr
	}
	return f.ensureResp, nil
}

func (f *fakeSecretsService) GetSecret(ctx context.Context, req *baasservice.GetSecretRequest) (*baasservice.GetSecretResponse, error) {
	f.getCalls = append(f.getCalls, req)
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getResp, nil
}

func newResolverWithFake(fake *fakeSecretsService) *LocalSecretsResolver {
	return NewLocalSecretsResolver(fake, slog.New(slog.DiscardHandler))
}

// TestLocalSecretsResolver_EnsureMode_GenerateThenRead verifies that
// a kms:// URI with ?ensure=true&len=&enc= reaches the SecretsService
// EnsureSecret method with the exact path and spec, and returns the
// response bytes. This is the contract that config templates depend
// on — a regression here breaks every persistent-autogen secret on
// every node at the next reboot.
func TestLocalSecretsResolver_EnsureMode_GenerateThenRead(t *testing.T) {
	fake := &fakeSecretsService{
		ensureResp: &baasservice.EnsureSecretResponse{
			SecretID:  "tenants/default/nodes/lab-node-2/secrets/platform/so-pin",
			Data:      []byte("45494337"),
			Generated: true,
			Version:   1,
			Timestamp: time.Now(),
		},
	}
	r := newResolverWithFake(fake)

	uri := "kms://tenants/default/nodes/lab-node-2/secrets/platform/so-pin?ensure=true&len=8&enc=numeric"
	got, err := r.Resolve(context.Background(), uri)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "45494337" {
		t.Fatalf("unexpected bytes: %q", got)
	}

	if len(fake.ensureCalls) != 1 {
		t.Fatalf("EnsureSecret call count: want 1, got %d", len(fake.ensureCalls))
	}
	call := fake.ensureCalls[0]
	if call.SecretID != "tenants/default/nodes/lab-node-2/secrets/platform/so-pin" {
		t.Errorf("path: want unchanged, got %q", call.SecretID)
	}
	if call.Length != 8 {
		t.Errorf("length: want 8, got %d", call.Length)
	}
	if call.Encoding != "numeric" {
		t.Errorf("encoding: want numeric, got %q", call.Encoding)
	}
	if len(fake.getCalls) != 0 {
		t.Fatalf("ensure mode should NOT call GetSecret, but saw %d calls", len(fake.getCalls))
	}
}

// TestLocalSecretsResolver_EnsureMode_AllEncodings verifies each
// supported encoding in the query string round-trips correctly.
func TestLocalSecretsResolver_EnsureMode_AllEncodings(t *testing.T) {
	cases := []struct {
		name string
		enc  string
	}{
		{"base64", "base64"},
		{"hex", "hex"},
		{"numeric", "numeric"},
		{"raw", "raw"},
		{"uppercase base64 normalized", "BASE64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSecretsService{
				ensureResp: &baasservice.EnsureSecretResponse{
					Data:      []byte("OK"),
					Generated: true,
				},
			}
			r := newResolverWithFake(fake)
			uri := "kms://p/" + tc.name + "?ensure=true&len=16&enc=" + tc.enc
			if _, err := r.Resolve(context.Background(), uri); err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(fake.ensureCalls) != 1 {
				t.Fatalf("call count: want 1, got %d", len(fake.ensureCalls))
			}
			wantEnc := tc.enc
			// resolver lowercases the value before accepting it
			switch tc.enc {
			case "BASE64":
				wantEnc = "base64"
			}
			if fake.ensureCalls[0].Encoding != wantEnc {
				t.Errorf("encoding: want %q, got %q", wantEnc, fake.ensureCalls[0].Encoding)
			}
		})
	}
}

// TestLocalSecretsResolver_StrictReadMode_UnchangedBehaviour checks
// that the legacy kms://path form (no query string) continues to
// behave as a strict read: it MUST call GetSecret, not EnsureSecret.
// A regression here would cause operator-managed secrets to be
// auto-generated with random bytes.
func TestLocalSecretsResolver_StrictReadMode_UnchangedBehaviour(t *testing.T) {
	fake := &fakeSecretsService{
		getResp: &baasservice.GetSecretResponse{
			SecretID: "operator/managed/secret",
			Data:     []byte("pre-stored-value"),
		},
	}
	r := newResolverWithFake(fake)

	got, err := r.Resolve(context.Background(), "kms://operator/managed/secret")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != "pre-stored-value" {
		t.Errorf("unexpected bytes: %q", got)
	}
	if len(fake.getCalls) != 1 {
		t.Errorf("GetSecret call count: want 1, got %d", len(fake.getCalls))
	}
	if len(fake.ensureCalls) != 0 {
		t.Errorf("strict-read mode should NOT call EnsureSecret, but saw %d calls", len(fake.ensureCalls))
	}
}

// TestLocalSecretsResolver_InvalidQueryParams verifies that a
// malformed or unknown query key is a hard error — silent fall-through
// to strict-read mode would be a security footgun (a typo in
// ?ensure= could turn "generate this secret" into "read a secret
// that doesn't exist", crashing the caller).
func TestLocalSecretsResolver_InvalidQueryParams(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"unknown key", "kms://p/x?ensuer=true&len=8&enc=numeric"},
		{"ensure=garbage", "kms://p/x?ensure=yessir&len=8&enc=numeric"},
		{"ensure=true no len", "kms://p/x?ensure=true&enc=base64"},
		{"ensure=true no enc", "kms://p/x?ensure=true&len=32"},
		{"ensure=true len=0", "kms://p/x?ensure=true&len=0&enc=base64"},
		{"ensure=true bad enc", "kms://p/x?ensure=true&len=32&enc=binary"},
		{"empty path", "kms://?ensure=true&len=32&enc=base64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSecretsService{}
			r := newResolverWithFake(fake)
			if _, err := r.Resolve(context.Background(), tc.uri); err == nil {
				t.Fatalf("expected error for %q, got nil", tc.uri)
			}
			if len(fake.ensureCalls) != 0 || len(fake.getCalls) != 0 {
				t.Errorf("should not have hit backend on bad input: ensure=%d get=%d",
					len(fake.ensureCalls), len(fake.getCalls))
			}
		})
	}
}

// TestLocalSecretsResolver_EnsureBackendError propagates backend
// errors up verbatim instead of swallowing them.
func TestLocalSecretsResolver_EnsureBackendError(t *testing.T) {
	fake := &fakeSecretsService{
		ensureErr: errors.New("backend exploded"),
	}
	r := newResolverWithFake(fake)
	_, err := r.Resolve(context.Background(),
		"kms://p/x?ensure=true&len=32&enc=base64")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
