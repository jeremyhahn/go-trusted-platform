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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// provisionParityCase drives one provisioning call through both the gRPC
// ConfigDeliveryService and the MCP bridge over the same backing service.
type provisionParityCase struct {
	name     string
	want     codes.Code
	setup    func(t *testing.T, backing *configdelivery.Service) string
	grpcCall func(svc *ConfigDeliveryGRPCService, arg string) error
	mcpCall  func(p *MCPServiceProvider, arg string) error
}

// TestProvisionMCPErrorClassMatchesGRPC asserts the MCP provisioning bridge
// answers every failure with the gRPC code ConfigDeliveryService uses, so
// both transports report one error class.
func TestProvisionMCPErrorClassMatchesGRPC(t *testing.T) {
	ctx := context.Background()
	noSetup := func(*testing.T, *configdelivery.Service) string { return "missing" }
	fulfilled := func(t *testing.T, backing *configdelivery.Service) string {
		session := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:ff")
		if err := backing.FulfillSession(ctx, session.ID, 42); err != nil {
			t.Fatalf("unexpected error fulfilling session: %v", err)
		}
		return session.ID
	}

	cases := []provisionParityCase{
		{
			name:  "poll unknown session",
			want:  codes.NotFound,
			setup: noSetup,
			grpcCall: func(svc *ConfigDeliveryGRPCService, id string) error {
				_, err := svc.PollSession(ctx, &platformv1.PollSessionRequest{SessionId: id})
				return err
			},
			mcpCall: func(p *MCPServiceProvider, id string) error {
				_, err := p.ProvisionPollSession(ctx, id)
				return err
			},
		},
		{
			name:  "get unknown session",
			want:  codes.NotFound,
			setup: noSetup,
			grpcCall: func(svc *ConfigDeliveryGRPCService, id string) error {
				_, err := svc.GetSession(ctx, &platformv1.GetSessionRequest{SessionId: id})
				return err
			},
			mcpCall: func(p *MCPServiceProvider, id string) error {
				_, err := p.ProvisionGetSession(ctx, id)
				return err
			},
		},
		{
			name:  "fulfill unknown session",
			want:  codes.NotFound,
			setup: noSetup,
			grpcCall: func(svc *ConfigDeliveryGRPCService, id string) error {
				_, err := svc.FulfillSession(ctx, &platformv1.FulfillSessionRequest{SessionId: id, ProfileId: 42})
				return err
			},
			mcpCall: func(p *MCPServiceProvider, id string) error {
				_, err := p.ProvisionFulfillSession(ctx, id, 42)
				return err
			},
		},
		{
			name:  "fulfill already fulfilled session",
			want:  codes.InvalidArgument,
			setup: fulfilled,
			grpcCall: func(svc *ConfigDeliveryGRPCService, id string) error {
				_, err := svc.FulfillSession(ctx, &platformv1.FulfillSessionRequest{SessionId: id, ProfileId: 43})
				return err
			},
			mcpCall: func(p *MCPServiceProvider, id string) error {
				_, err := p.ProvisionFulfillSession(ctx, id, 43)
				return err
			},
		},
		{
			name:  "fetch config with an empty request",
			want:  codes.InvalidArgument,
			setup: noSetup,
			grpcCall: func(svc *ConfigDeliveryGRPCService, _ string) error {
				_, err := svc.FetchConfig(ctx, &platformv1.FetchConfigRequest{})
				return err
			},
			mcpCall: func(p *MCPServiceProvider, _ string) error {
				_, err := p.ProvisionFetchConfig(ctx, &mcp.ProvisionFetchConfigRequest{})
				return err
			},
		},
		{
			name:  "fetch config with a never-issued nonce",
			want:  codes.InvalidArgument,
			setup: noSetup,
			grpcCall: func(svc *ConfigDeliveryGRPCService, _ string) error {
				_, err := svc.FetchConfig(ctx, &platformv1.FetchConfigRequest{
					EkSerial: "ek-123", EabKeyId: "key-1", EabHmac: cdValidEABHMAC(), Nonce: "never-issued",
				})
				return err
			},
			mcpCall: func(p *MCPServiceProvider, _ string) error {
				_, err := p.ProvisionFetchConfig(ctx, &mcp.ProvisionFetchConfigRequest{
					EKSerial: "ek-123", EABKeyID: "key-1", EABHMAC: cdValidEABHMAC(), Nonce: "never-issued",
				})
				return err
			},
		},
		{
			name:  "sign digest with no signer wired",
			want:  codes.Unavailable,
			setup: cdIssueNonce,
			grpcCall: func(svc *ConfigDeliveryGRPCService, nonce string) error {
				_, err := svc.SignDigest(ctx, &platformv1.SignDigestRequest{
					EkSerial: "ek-123", EabKeyId: "key-1", EabHmac: cdValidEABHMAC(), Nonce: nonce, Digest: []byte("digest"),
				})
				return err
			},
			mcpCall: func(p *MCPServiceProvider, nonce string) error {
				_, err := p.ProvisionSignDigest(ctx, &mcp.ProvisionSignDigestRequest{
					EKSerial: "ek-123", EABKeyID: "key-1", EABHMAC: cdValidEABHMAC(), Nonce: nonce, Digest: []byte("digest"),
				})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
			grpcErr := tc.grpcCall(newCDGRPCService(t, backing), tc.setup(t, backing))

			backing = newCDTestService(t, &cdMockProfileResolver{}, nil)
			mcpErr := tc.mcpCall(newProvisionMCPProvider(backing), tc.setup(t, backing))

			if got := status.Code(grpcErr); got != tc.want {
				t.Fatalf("gRPC code = %v, want %v (err: %v)", got, tc.want, grpcErr)
			}
			if got := status.Code(mcpErr); got != tc.want {
				t.Fatalf("MCP code = %v, want the gRPC code %v (err: %v)", got, tc.want, mcpErr)
			}
		})
	}
}

// TestProvisionMCPUnwiredServiceMatchesGRPC asserts both transports answer
// Unavailable when no config delivery service is wired.
func TestProvisionMCPUnwiredServiceMatchesGRPC(t *testing.T) {
	ctx := context.Background()

	_, grpcErr := newCDGRPCService(t, nil).GetSession(ctx, &platformv1.GetSessionRequest{SessionId: "x"})
	_, mcpErr := newProvisionMCPProvider(nil).ProvisionGetSession(ctx, "x")

	if got := status.Code(grpcErr); got != codes.Unavailable {
		t.Fatalf("gRPC code = %v, want Unavailable", got)
	}
	if got := status.Code(mcpErr); got != codes.Unavailable {
		t.Fatalf("MCP code = %v, want Unavailable (err: %v)", got, mcpErr)
	}
}

// TestProvisionMCPClassifiedErrorKeepsTypedCause asserts the classified MCP
// error still exposes the typed configdelivery error through errors.As.
func TestProvisionMCPClassifiedErrorKeepsTypedCause(t *testing.T) {
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)

	_, err := newProvisionMCPProvider(backing).ProvisionPollSession(context.Background(), "missing")

	var notFound configdelivery.ErrSessionNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("errors.As(ErrSessionNotFound) = false for %T: %v", err, err)
	}
	var classified ErrConfigDeliveryClassified
	if !errors.As(err, &classified) || classified.Code != codes.NotFound {
		t.Fatalf("error %v is not classified NotFound", err)
	}
}

// TestProvisionMCPSuccessMatchesGRPC asserts both transports return the same
// session state for the same fulfilment.
func TestProvisionMCPSuccessMatchesGRPC(t *testing.T) {
	ctx := context.Background()
	backing := newCDTestService(t, &cdMockProfileResolver{}, nil)
	grpcSvc := newCDGRPCService(t, backing)
	provider := newProvisionMCPProvider(backing)

	viaGRPC := backing.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")
	viaMCP := backing.CreateSession("ek-2", "aa:bb:cc:dd:ee:02")
	if _, err := grpcSvc.FulfillSession(ctx, &platformv1.FulfillSessionRequest{SessionId: viaGRPC.ID, ProfileId: 42}); err != nil {
		t.Fatalf("gRPC FulfillSession: %v", err)
	}
	if _, err := provider.ProvisionFulfillSession(ctx, viaMCP.ID, 42); err != nil {
		t.Fatalf("MCP ProvisionFulfillSession: %v", err)
	}

	grpcList, err := grpcSvc.ListSessions(ctx, &platformv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("gRPC ListSessions: %v", err)
	}
	mcpList, err := provider.ProvisionListSessions(ctx)
	if err != nil {
		t.Fatalf("MCP ProvisionListSessions: %v", err)
	}
	listMap, ok := mcpList.(map[string]interface{})
	if !ok {
		t.Fatalf("MCP list type = %T, want map", mcpList)
	}
	mcpSessions, ok := listMap["sessions"].([]*configdelivery.Session)
	if !ok {
		t.Fatalf("MCP sessions type = %T, want []*configdelivery.Session", mcpList)
	}
	if len(mcpSessions) != len(grpcList.GetSessions()) {
		t.Fatalf("MCP lists %d sessions, gRPC lists %d", len(mcpSessions), len(grpcList.GetSessions()))
	}
	grpcByID := make(map[string]*platformv1.ProvisioningSession, len(grpcList.GetSessions()))
	for _, pb := range grpcList.GetSessions() {
		grpcByID[pb.GetId()] = pb
	}
	for _, session := range mcpSessions {
		if !session.Fulfilled || session.ProfileID != 42 {
			t.Fatalf("session %s: fulfilled=%v profile=%d, want fulfilled profile 42", session.ID, session.Fulfilled, session.ProfileID)
		}
		if !proto.Equal(grpcSvc.sessionToPb(session), grpcByID[session.ID]) {
			t.Fatalf("session %s differs between MCP and gRPC", session.ID)
		}
	}
}
