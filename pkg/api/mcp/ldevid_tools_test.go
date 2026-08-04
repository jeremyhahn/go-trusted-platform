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

package mcp

import (
	"context"
	"errors"
	"testing"
)

// ldevidMockProvider embeds the base mock ServiceProvider and adds the LDevID
// capability so the idevid_create_ldevid tool can be exercised.
type ldevidMockProvider struct {
	*mockServiceProvider
	createFunc func(ctx context.Context, req *CreateLDevIDMCPRequest) (interface{}, error)
}

func (m *ldevidMockProvider) CreateLDevID(ctx context.Context, req *CreateLDevIDMCPRequest) (interface{}, error) {
	return m.createFunc(ctx, req)
}

func TestLDevIDToolRegistered(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())
	registry.registerLDevIDTools()

	found := false
	for _, tool := range registry.ListTools() {
		if tool.Name == "idevid_create_ldevid" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("idevid_create_ldevid tool was not registered")
	}
}

func TestExecuteLDevIDCreate(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("success maps args to request and returns result", func(t *testing.T) {
		var captured *CreateLDevIDMCPRequest
		provider := &ldevidMockProvider{
			mockServiceProvider: newMockServiceProvider(),
			createFunc: func(_ context.Context, req *CreateLDevIDMCPRequest) (interface{}, error) {
				captured = req
				return map[string]interface{}{"csr_pem": "CSR", "certificate_pem": "CERT"}, nil
			},
		}
		registry := NewToolRegistry(provider, log)

		result, err := registry.executeLDevIDCreate(ctx, map[string]interface{}{
			"algorithm":     "ECDSA-P384",
			"handle":        float64(0x81010102),
			"profile":       "tls-client",
			"validity_days": float64(90),
			"overwrite":     true,
			"template": map[string]interface{}{
				"common_name": "ldevid.example",
				"dns_names":   []interface{}{"a.example", "b.example"},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if captured == nil {
			t.Fatal("service was not invoked")
		}
		if captured.Algorithm != "ECDSA-P384" || captured.Handle != 0x81010102 ||
			captured.Profile != "tls-client" || captured.ValidityDays != 90 || !captured.Overwrite {
			t.Fatalf("scalar args not mapped: %+v", captured)
		}
		if captured.Template == nil || captured.Template.CommonName != "ldevid.example" ||
			len(captured.Template.DNSNames) != 2 {
			t.Fatalf("template args not mapped: %+v", captured.Template)
		}
	})

	t.Run("service error is propagated", func(t *testing.T) {
		sentinel := errors.New("boom")
		provider := &ldevidMockProvider{
			mockServiceProvider: newMockServiceProvider(),
			createFunc: func(_ context.Context, _ *CreateLDevIDMCPRequest) (interface{}, error) {
				return nil, sentinel
			},
		}
		registry := NewToolRegistry(provider, log)

		_, err := registry.executeLDevIDCreate(ctx, map[string]interface{}{})
		if !errors.Is(err, sentinel) {
			t.Fatalf("expected sentinel error, got %v", err)
		}
	})

	t.Run("provider without LDevID capability returns not supported", func(t *testing.T) {
		registry := NewToolRegistry(newMockServiceProvider(), log)

		_, err := registry.executeLDevIDCreate(ctx, map[string]interface{}{})
		if !errors.Is(err, ErrLDevIDNotSupported) {
			t.Fatalf("expected ErrLDevIDNotSupported, got %v", err)
		}
	})
}
