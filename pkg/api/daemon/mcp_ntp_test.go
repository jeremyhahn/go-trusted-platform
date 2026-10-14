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

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ntpMCPProvider is the common surface both MCP service providers expose for
// time synchronization, so one table drives both implementations.
type ntpMCPProvider interface {
	NTPStatus(ctx context.Context) (interface{}, error)
	NTPSources(ctx context.Context) (interface{}, error)
	NTPStep(ctx context.Context) (interface{}, error)
}

// ntpProviders builds the MCP provider over the backend.
func ntpProviders(backend NTPBackend) map[string]ntpMCPProvider {
	server := NewNTPGRPCService(nil, backend)

	mcpProvider := &MCPServiceProvider{}
	mcpProvider.SetNTPService(server)

	return map[string]ntpMCPProvider{
		"MCPServiceProvider": mcpProvider,
	}
}

func TestMCPProvidersReturnTheProtoResponseShapes(t *testing.T) {
	backend := &fakeNTPBackend{
		status:     syncedNTPStatus(),
		sources:    ntpTestSources(),
		stepStatus: syncedNTPStatus(),
	}

	for name, provider := range ntpProviders(backend) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			statusResult, err := provider.NTPStatus(ctx)
			if err != nil {
				t.Fatalf("NTPStatus() error = %v", err)
			}
			statusResp, ok := statusResult.(*platformv1.GetNTPStatusResponse)
			if !ok {
				t.Fatalf("NTPStatus() = %T, want *platformv1.GetNTPStatusResponse", statusResult)
			}
			if !statusResp.GetStatus().GetSynced() {
				t.Fatalf("status = %+v, want synced", statusResp.GetStatus())
			}

			sourcesResult, err := provider.NTPSources(ctx)
			if err != nil {
				t.Fatalf("NTPSources() error = %v", err)
			}
			sourcesResp, ok := sourcesResult.(*platformv1.ListNTPSourcesResponse)
			if !ok {
				t.Fatalf("NTPSources() = %T, want *platformv1.ListNTPSourcesResponse", sourcesResult)
			}
			if len(sourcesResp.GetSources()) != 2 {
				t.Fatalf("len(sources) = %d, want 2", len(sourcesResp.GetSources()))
			}

			stepResult, err := provider.NTPStep(ctx)
			if err != nil {
				t.Fatalf("NTPStep() error = %v", err)
			}
			if _, ok := stepResult.(*platformv1.StepNTPClockResponse); !ok {
				t.Fatalf("NTPStep() = %T, want *platformv1.StepNTPClockResponse", stepResult)
			}
		})
	}
}

func TestMCPProvidersReportUnavailableWithoutABackend(t *testing.T) {
	providers := map[string]ntpMCPProvider{
		"MCPServiceProvider": &MCPServiceProvider{},
	}

	for name, provider := range providers {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var unavailable ErrServiceNotAvailable

			if _, err := provider.NTPStatus(ctx); !errors.As(err, &unavailable) {
				t.Fatalf("NTPStatus() error = %v, want ErrServiceNotAvailable", err)
			}
			if unavailable.Service != "ntp" {
				t.Fatalf("Service = %q, want ntp", unavailable.Service)
			}
			if _, err := provider.NTPSources(ctx); !errors.As(err, &unavailable) {
				t.Fatalf("NTPSources() error = %v, want ErrServiceNotAvailable", err)
			}
			if _, err := provider.NTPStep(ctx); !errors.As(err, &unavailable) {
				t.Fatalf("NTPStep() error = %v, want ErrServiceNotAvailable", err)
			}
		})
	}
}

func TestMCPProvidersPropagateBackendFailures(t *testing.T) {
	backend := &fakeNTPBackend{
		statusErr:  ntp.ErrControlUnavailable{Command: "tracking"},
		sourcesErr: ntp.ErrControlUnavailable{Command: "sources"},
		stepErr:    ntp.ErrNoReachableSource{Total: 1},
	}

	for name, provider := range ntpProviders(backend) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if _, err := provider.NTPStatus(ctx); err == nil {
				t.Fatal("NTPStatus() = nil error, want the control failure")
			}
			if _, err := provider.NTPSources(ctx); err == nil {
				t.Fatal("NTPSources() = nil error, want the control failure")
			}
			if _, err := provider.NTPStep(ctx); err == nil {
				t.Fatal("NTPStep() = nil error, want the conflict")
			}
		})
	}
}
