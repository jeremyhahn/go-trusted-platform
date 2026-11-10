//go:build !gcpcompute

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

package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// TestStubNew_FailsClosedWithTypedError verifies the stub New, compiled
// without the gcpcompute tag, never returns an orchestrator and always
// returns the typed not-compiled error for ProviderGCP, whatever it is given.
func TestStubNew_FailsClosedWithTypedError(t *testing.T) {
	tests := []struct {
		name string
		cfg  *compute.OrchestratorConfig
		deps *compute.Deps
	}{
		{name: "nil config and deps", cfg: nil, deps: nil},
		{name: "populated config and deps", cfg: &compute.OrchestratorConfig{}, deps: &compute.Deps{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch, err := New(context.Background(), tt.cfg, tt.deps)
			if orch != nil {
				t.Fatalf("New returned orchestrator %v, want nil", orch)
			}
			if !errors.Is(err, ErrProviderNotCompiled) {
				t.Fatalf("New error = %v, want ErrProviderNotCompiled", err)
			}
			var notCompiled *compute.ErrComputeProviderNotCompiled
			if !errors.As(err, &notCompiled) {
				t.Fatalf("New error %T is not *compute.ErrComputeProviderNotCompiled", err)
			}
			if notCompiled.Provider != compute.ProviderGCP {
				t.Fatalf("Provider = %q, want %q", notCompiled.Provider, compute.ProviderGCP)
			}
			if !strings.Contains(err.Error(), "gcpcompute") {
				t.Fatalf("error %q does not name the gcpcompute build tag", err.Error())
			}
		})
	}
}

// TestStubNew_DoesNotRegisterProvider verifies importing the stub package
// leaves ProviderGCP unregistered, so the resolver fails closed.
func TestStubNew_DoesNotRegisterProvider(t *testing.T) {
	if compute.IsProviderCompiled(compute.ProviderGCP) {
		t.Fatal("ProviderGCP is registered in a build without the gcpcompute tag")
	}
}
