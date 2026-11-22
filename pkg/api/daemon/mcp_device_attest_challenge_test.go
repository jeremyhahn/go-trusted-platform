// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// stubAttestChallengeIssuer records the request it is asked for and answers
// with a canned response or error.
type stubAttestChallengeIssuer struct {
	got  *platformv1.IssueAttestationChallengeRequest
	resp *platformv1.IssueAttestationChallengeResponse
	err  error
}

func (s *stubAttestChallengeIssuer) IssueAttestationChallenge(_ context.Context, req *platformv1.IssueAttestationChallengeRequest) (*platformv1.IssueAttestationChallengeResponse, error) {
	s.got = req
	return s.resp, s.err
}

func TestMCPServiceProvider_DeviceAttestChallenge(t *testing.T) {
	t.Run("returns the pb response with the device id passed through", func(t *testing.T) {
		stub := &stubAttestChallengeIssuer{resp: &platformv1.IssueAttestationChallengeResponse{
			ChallengeId: "c-1",
			Nonce:       []byte("nonce"),
		}}
		p := NewMCPServiceProvider(&MCPServiceProviderConfig{
			DeviceService:         newMockDeviceService(),
			AttestChallengeIssuer: stub,
			Logger:                slog.Default(),
		})

		out, err := p.DeviceAttestChallenge(context.Background(), "42")
		require.NoError(t, err)
		resp, ok := out.(*platformv1.IssueAttestationChallengeResponse)
		require.True(t, ok, "the MCP result is the pb response so it marshals with proto field names")
		assert.Equal(t, "c-1", resp.GetChallengeId())
		require.NotNil(t, stub.got)
		assert.Equal(t, "42", stub.got.GetDeviceId())
	})

	t.Run("an issuer error is returned as it is", func(t *testing.T) {
		want := status.Error(codes.NotFound, "no such device")
		stub := &stubAttestChallengeIssuer{err: want}
		p := NewMCPServiceProvider(&MCPServiceProviderConfig{
			DeviceService:         newMockDeviceService(),
			AttestChallengeIssuer: stub,
			Logger:                slog.Default(),
		})

		_, err := p.DeviceAttestChallenge(context.Background(), "42")
		assert.True(t, errors.Is(err, want), "got %v", err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("no issuer configured answers codes.Unavailable", func(t *testing.T) {
		p := NewMCPServiceProvider(&MCPServiceProviderConfig{
			DeviceService: newMockDeviceService(),
			Logger:        slog.Default(),
		})

		_, err := p.DeviceAttestChallenge(context.Background(), "42")
		assert.Equal(t, codes.Unavailable, status.Code(err))
	})

	t.Run("a challenge from the device service verifies through AttestDevice", func(t *testing.T) {
		f := newQuoteFixture(t)
		clock := f.now
		svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())
		ctx := tokenCallerContext("tenant-a")
		p := NewMCPServiceProvider(&MCPServiceProviderConfig{
			DeviceService:         newMockDeviceService(),
			AttestChallengeIssuer: svc,
			Logger:                slog.Default(),
		})

		out, err := p.DeviceAttestChallenge(ctx, itoa(f.device.ID))
		require.NoError(t, err)
		ch, ok := out.(*platformv1.IssueAttestationChallengeResponse)
		require.True(t, ok)
		require.NotEmpty(t, ch.GetChallengeId())

		resp, err := svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
			DeviceId:    itoa(f.device.ID),
			Evidence:    f.evidence(t, ch.GetNonce(), goldenPCRs()),
			ChallengeId: ch.GetChallengeId(),
		})
		require.NoError(t, err)
		assert.True(t, resp.GetVerified())
		assert.True(t, resp.GetNonceValid())
	})
}

func TestMCPServiceProvider_DeviceAttest_ChecksTheChallenge(t *testing.T) {
	setup := func(t *testing.T) (*quoteFixture, *time.Time, *DeviceGRPCService, *MCPServiceProvider) {
		t.Helper()
		f := newQuoteFixture(t)
		clock := f.now
		svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())
		p := NewMCPServiceProvider(&MCPServiceProviderConfig{
			DeviceService:         f.devices,
			DeviceProfileService:  f.profiles,
			VerdictSink:           f.sink,
			AttestChallengeIssuer: svc,
			Logger:                slog.Default(),
		})
		return f, &clock, svc, p
	}

	t.Run("a live challenge is consumed and the quote reaches the verifier", func(t *testing.T) {
		f, _, svc, p := setup(t)
		ctx := tokenCallerContext("tenant-a")
		ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))
		evidence := f.evidence(t, ch.GetNonce(), goldenPCRs())

		out, err := p.DeviceAttest(ctx, itoa(f.device.ID), evidence, ch.GetChallengeId())
		require.NoError(t, err)
		_, ok := out.(*DeviceAttestationResult)
		require.True(t, ok, "the verifier ran and returned its result, got %T", out)

		_, err = p.DeviceAttest(ctx, itoa(f.device.ID), evidence, ch.GetChallengeId())
		requireChallengeCode(t, err, codes.FailedPrecondition)
	})

	t.Run("a missing challenge is refused when the service requires one", func(t *testing.T) {
		f, _, _, p := setup(t)
		ctx := tokenCallerContext("tenant-a")
		_, err := p.DeviceAttest(ctx, itoa(f.device.ID), f.evidence(t, []byte("nonce-mcp"), goldenPCRs()), "")
		requireChallengeCode(t, err, codes.InvalidArgument)
	})

	t.Run("an unknown challenge", func(t *testing.T) {
		f, _, _, p := setup(t)
		ctx := tokenCallerContext("tenant-a")
		_, err := p.DeviceAttest(ctx, itoa(f.device.ID), f.evidence(t, []byte("nonce-mcp"), goldenPCRs()), "deadbeef")
		requireChallengeCode(t, err, codes.FailedPrecondition)
	})

	t.Run("an expired challenge", func(t *testing.T) {
		f, clock, svc, p := setup(t)
		ctx := tokenCallerContext("tenant-a")
		ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))
		*clock = f.now.Add(5*time.Minute + time.Second)
		_, err := p.DeviceAttest(ctx, itoa(f.device.ID), f.evidence(t, ch.GetNonce(), goldenPCRs()), ch.GetChallengeId())
		requireChallengeCode(t, err, codes.FailedPrecondition)
	})

	t.Run("a nonce that does not match", func(t *testing.T) {
		f, _, svc, p := setup(t)
		ctx := tokenCallerContext("tenant-a")
		ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))
		_, err := p.DeviceAttest(ctx, itoa(f.device.ID), f.evidence(t, []byte("a-replayed-older-nonce"), goldenPCRs()), ch.GetChallengeId())
		requireChallengeCode(t, err, codes.FailedPrecondition)

		_, err = p.DeviceAttest(ctx, itoa(f.device.ID), f.evidence(t, ch.GetNonce(), goldenPCRs()), ch.GetChallengeId())
		requireChallengeCode(t, err, codes.FailedPrecondition)
	})

	t.Run("another tenant's challenge", func(t *testing.T) {
		f, _, svc, p := setup(t)
		ch := issueChallenge(t, tokenCallerContext("tenant-a"), svc, itoa(f.device.ID))
		_, err := p.DeviceAttest(tokenCallerContext("tenant-b"), itoa(f.device.ID), f.evidence(t, ch.GetNonce(), goldenPCRs()), ch.GetChallengeId())
		requireChallengeCode(t, err, codes.PermissionDenied)
	})

	t.Run("a challenge_id with no challenge service is Unavailable", func(t *testing.T) {
		f := newQuoteFixture(t)
		ctx := tokenCallerContext("tenant-a")
		evidence := f.evidence(t, []byte("nonce-mcp"), goldenPCRs())
		for name, issuer := range map[string]AttestChallengeIssuer{
			"no issuer":                   nil,
			"an issuer that cannot check": &stubAttestChallengeIssuer{},
		} {
			p := NewMCPServiceProvider(&MCPServiceProviderConfig{
				DeviceService:         f.devices,
				DeviceProfileService:  f.profiles,
				VerdictSink:           f.sink,
				AttestChallengeIssuer: issuer,
				Logger:                slog.Default(),
			})
			_, err := p.DeviceAttest(ctx, itoa(f.device.ID), evidence, "c-1")
			assert.Equal(t, codes.Unavailable, status.Code(err), "%s: %v", name, err)
		}
	})
}
