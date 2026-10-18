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

//go:build integration

// Package ceremony provides multi-protocol integration tests for the
// platformd ceremony service. The suite drives platformctl and the SDK
// clients across all six protocols (CLI, REST, gRPC, QUIC, MCP, Unix) through
// one shared ceremony lifecycle. platformd always wires the SDK ceremony
// backend, so a "not configured" answer is a failure, not an outcome.
//
// Run via:
//
//	make integration-test-ceremony
package ceremony

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestCeremonyMultiProtocol runs the same scenario against every transport.
func TestCeremonyMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []CeremonyCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "ceremony", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
		adapter := adapter
		t.Cleanup(func() {
			if err := adapter.Teardown(); err != nil {
				t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
			}
		})
	}

	runCeremonyScenario(t, ctx, adapters)
}

// runCeremonyScenario initializes the ceremony once, then checks that every
// transport observes the shared lifecycle state.
func runCeremonyScenario(t *testing.T, ctx context.Context, adapters []CeremonyCommands) {
	t.Helper()
	if len(adapters) == 0 {
		t.Fatal("no ceremony adapters configured")
	}

	initAdapter := ceremonyInitAdapter(adapters)
	fixture := ceremonyLifecycleFixture(t)

	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	initResp, err := initAdapter.Init(callCtx, fixture.Init)
	cancel()
	if err != nil {
		t.Fatalf("%s Init failed: %v", initAdapter.Name(), err)
	}
	assertInitResponse(t, initResp)

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name()+"/Status", func(t *testing.T) {
			callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			status, err := adapter.Status(callCtx)
			if err != nil {
				t.Fatalf("Status failed: %v", err)
			}
			assertStatusResponse(t, status, initResp)
		})
	}

	t.Run(initAdapter.Name()+"/SignCSR", func(t *testing.T) {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		resp, err := initAdapter.SignCSR(callCtx, &ceremonysdk.SignCSRRequest{
			Username: fixture.Officer,
			SOPIN:    fixture.Init.SOPIN,
			Role:     ceremonysdk.RoleAdmin,
			CSRPEM:   fixture.CSRPEM,
		})
		if err != nil {
			t.Fatalf("SignCSR failed: %v", err)
		}
		if resp == nil || resp.Certificate == "" {
			t.Fatalf("SignCSR response = %+v, want certificate PEM", resp)
		}
	})
}

type ceremonyFixture struct {
	Init    *ceremonysdk.InitRequest
	Officer string
	CSRPEM  string
}

func ceremonyLifecycleFixture(t *testing.T) ceremonyFixture {
	t.Helper()
	return ceremonyFixture{
		Init: &ceremonysdk.InitRequest{
			SOPIN:     "so-pin-000000",
			UserPIN:   "user-pin-111111",
			Threshold: "1-of-1",
			Hostname:  "ceremony-mp-test",
			SANs:      []string{"ceremony-mp-test.local"},
		},
		Officer: "alice",
		CSRPEM:  newCSRFixture(t, "alice"),
	}
}

func newCSRFixture(t *testing.T, commonName string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CSR key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func ceremonyInitAdapter(adapters []CeremonyCommands) CeremonyCommands {
	for _, adapter := range adapters {
		if adapter.Name() == "REST" {
			return adapter
		}
	}
	return adapters[0]
}

func assertInitResponse(t *testing.T, resp *ceremonysdk.InitResponse) {
	t.Helper()
	if resp == nil {
		t.Fatal("Init response is nil")
	}
	if resp.State == "" || resp.State == ceremonysdk.StateUnknown {
		t.Fatalf("Init state = %q, want a real ceremony state", resp.State)
	}
	if resp.CeremonyID == "" {
		t.Fatal("Init ceremony_id is empty")
	}
}

func assertStatusResponse(t *testing.T, resp *ceremonysdk.StatusResponse, init *ceremonysdk.InitResponse) {
	t.Helper()
	if resp == nil {
		t.Fatal("Status response is nil")
	}
	if resp.State == "" || resp.State == ceremonysdk.StateUnknown {
		t.Fatalf("Status state = %q, want a real ceremony state", resp.State)
	}
	if init.CeremonyID != "" && resp.CeremonyID != "" && resp.CeremonyID != init.CeremonyID {
		t.Fatalf("Status ceremony_id = %q, want %q", resp.CeremonyID, init.CeremonyID)
	}
}
