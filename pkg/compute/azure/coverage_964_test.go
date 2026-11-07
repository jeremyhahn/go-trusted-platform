//go:build !azurecompute

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

package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// TestStubNew_FailsClosedWithTypedError covers the negated-tag stub: without
// the azurecompute tag, New must never hand back an orchestrator, whatever it
// is given, and must return the typed not-compiled error for ProviderAzure.
func TestStubNew_FailsClosedWithTypedError(t *testing.T) {
	tests := []struct {
		name string
		cfg  *compute.OrchestratorConfig
		deps *compute.Deps
	}{
		{name: "nil config and deps"},
		{
			name: "azure provider config",
			cfg: &compute.OrchestratorConfig{
				Provider: compute.ProviderAzure,
				Azure:    &compute.AzureProviderConfig{},
			},
			deps: &compute.Deps{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch, err := New(context.Background(), tt.cfg, tt.deps)
			if orch != nil {
				t.Fatalf("New returned an orchestrator %T; want nil", orch)
			}
			if !errors.Is(err, ErrProviderNotCompiled) {
				t.Fatalf("New error = %v; want ErrProviderNotCompiled", err)
			}
			var notCompiled *compute.ErrComputeProviderNotCompiled
			if !errors.As(err, &notCompiled) {
				t.Fatalf("New error %T is not *compute.ErrComputeProviderNotCompiled", err)
			}
			if notCompiled.Provider != compute.ProviderAzure {
				t.Fatalf("Provider = %q; want %q", notCompiled.Provider, compute.ProviderAzure)
			}
		})
	}
}

// TestStubNew_MatchesResolverError pins the stub's documented contract: a
// caller sees the same typed error whether it calls New directly or selects
// the Azure provider through compute.NewOrchestratorForConfig.
func TestStubNew_MatchesResolverError(t *testing.T) {
	cfg := &compute.OrchestratorConfig{Provider: compute.ProviderAzure}

	_, resolverErr := compute.NewOrchestratorForConfig(context.Background(), cfg, &compute.Deps{})
	var fromResolver *compute.ErrComputeProviderNotCompiled
	if !errors.As(resolverErr, &fromResolver) {
		t.Fatalf("resolver error = %v; want *compute.ErrComputeProviderNotCompiled", resolverErr)
	}

	_, stubErr := New(context.Background(), cfg, &compute.Deps{})
	var fromStub *compute.ErrComputeProviderNotCompiled
	if !errors.As(stubErr, &fromStub) {
		t.Fatalf("stub error = %v; want *compute.ErrComputeProviderNotCompiled", stubErr)
	}

	if fromStub.Provider != fromResolver.Provider {
		t.Fatalf("stub Provider %q != resolver Provider %q", fromStub.Provider, fromResolver.Provider)
	}
	if stubErr.Error() != resolverErr.Error() {
		t.Fatalf("stub error %q != resolver error %q", stubErr.Error(), resolverErr.Error())
	}
}
