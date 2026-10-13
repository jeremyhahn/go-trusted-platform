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
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict/feed"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// verdictStreamScope is the scope a token caller following device verdicts
// must hold. The gRPC method catalog requires the same scope.
const verdictStreamScope = "attestation:read"

// ErrVerdictStreamUnavailable is returned when the daemon has no verdict
// feed to serve: the attestation service cannot hand out its verdicts.
type ErrVerdictStreamUnavailable struct{}

func (ErrVerdictStreamUnavailable) Error() string {
	return "attestation: the device verdict stream is not available"
}

// ErrVerdictStreamForbidden is returned when the caller may not follow
// device verdicts.
type ErrVerdictStreamForbidden struct {
	Reason string
}

func (e ErrVerdictStreamForbidden) Error() string {
	return "attestation: device verdict stream denied: " + e.Reason
}

// verdictAudienceFor decides which verdicts the gRPC caller of ctx may
// follow.
//
//   - A platform-token caller is judged by verdictAudienceOfToken.
//   - A bearer token the daemon could only check for validity carries no
//     scopes, so it is refused.
//   - An mTLS identity sees its certificate's tenant, or every tenant when
//     the certificate names none or the system tenant: it is infrastructure,
//     such as an overlay gateway.
//   - A caller with no credential in the context was admitted by the
//     transport itself, as the Unix socket admits local peers by their
//     credentials, and sees every tenant.
func verdictAudienceFor(ctx context.Context) (feed.Audience, error) {
	if authCtx, ok := grpccreds.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		return verdictAudienceOfToken(authCtx)
	}
	if _, ok := grpccreds.TokenFromContext(ctx); ok {
		return feed.Audience{}, ErrVerdictStreamForbidden{Reason: "the token carries no scopes"}
	}
	if identity := IdentityFromContext(ctx); identity != nil && identity.TenantID != "" {
		return feed.Tenant(identity.TenantID), nil
	}
	return feed.EveryTenant(), nil
}

// verdictAudienceOfToken decides which verdicts a platform-token caller may
// follow: it needs attestation:read and sees its token's tenant only, or
// every tenant when that is the system tenant. A missing token, or one
// naming no tenant, is refused. QUIC and MCP have no peer identity to fall
// back on, so they judge every caller here.
func verdictAudienceOfToken(authCtx *platformtoken.AuthorizedContext) (feed.Audience, error) {
	if authCtx == nil {
		return feed.Audience{}, ErrVerdictStreamForbidden{Reason: "a platform token is required"}
	}
	if !authCtx.HasScope(verdictStreamScope) {
		return feed.Audience{}, ErrVerdictStreamForbidden{Reason: verdictStreamScope + " is required"}
	}
	if authCtx.TenantID == "" {
		return feed.Audience{}, ErrVerdictStreamForbidden{Reason: "the token names no tenant"}
	}
	return feed.Tenant(authCtx.TenantID), nil
}

// verdictStatus renders a verdict feed or audience error as the gRPC status
// every transport maps onto its own codes.
func verdictStatus(err error) error {
	var (
		forbidden ErrVerdictStreamForbidden
		closed    feed.ErrClosed
		missed    feed.ErrMissedVerdicts
		invalid   feed.ErrInvalidCursor
	)
	switch {
	case errors.As(err, &forbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.As(err, &closed):
		return status.Error(codes.Unavailable, err.Error())
	case errors.As(err, &missed):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.As(err, &invalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// SetVerdictFeed installs the feed StreamDeviceVerdicts and
// PollDeviceVerdicts serve from. Until it is set both answer
// FailedPrecondition.
func (s *AttestationServiceServer) SetVerdictFeed(f *feed.Feed) {
	if s == nil {
		return
	}
	s.verdicts.Store(f)
}

// verdictFeed returns the installed feed, or a FailedPrecondition status.
func (s *AttestationServiceServer) verdictFeed() (*feed.Feed, error) {
	if s == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrVerdictStreamUnavailable{}.Error())
	}
	f := s.verdicts.Load()
	if f == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrVerdictStreamUnavailable{}.Error())
	}
	return f, nil
}

// StreamDeviceVerdicts streams every device verdict recorded from now on that
// the caller may see, until the caller goes away or the daemon shuts down. A
// caller that falls more than the feed's capacity behind is cut off with
// ResourceExhausted rather than silently missing verdicts.
func (s *AttestationServiceServer) StreamDeviceVerdicts(
	_ *platformv1.StreamDeviceVerdictsRequest,
	stream grpc.ServerStreamingServer[platformv1.DeviceVerdictEvent],
) error {
	f, err := s.verdictFeed()
	if err != nil {
		return err
	}
	ctx := stream.Context()
	audience, err := verdictAudienceFor(ctx)
	if err != nil {
		return verdictStatus(err)
	}
	cursor, err := f.Follow()
	if err != nil {
		return verdictStatus(err)
	}
	for {
		page, err := f.Poll(ctx, audience, cursor, feed.MaxWait)
		if err != nil {
			return verdictStatus(err)
		}
		for _, recorded := range page.Verdicts {
			if err := stream.Send(deviceVerdictEvent(recorded)); err != nil {
				return err
			}
		}
		cursor = page.Next
	}
}

// PollDeviceVerdicts answers one long-poll of the device verdicts for the
// gRPC caller of ctx.
func (s *AttestationServiceServer) PollDeviceVerdicts(
	ctx context.Context,
	req *platformv1.PollDeviceVerdictsRequest,
) (*platformv1.PollDeviceVerdictsResponse, error) {
	audience, err := verdictAudienceFor(ctx)
	if err != nil {
		return nil, verdictStatus(err)
	}
	return s.PollDeviceVerdictsFor(ctx, audience, req)
}

// PollDeviceVerdictsFor answers one long-poll for audience. The REST, QUIC
// and MCP transports decide the audience from their own credentials and
// share everything else with gRPC through it.
func (s *AttestationServiceServer) PollDeviceVerdictsFor(
	ctx context.Context,
	audience feed.Audience,
	req *platformv1.PollDeviceVerdictsRequest,
) (*platformv1.PollDeviceVerdictsResponse, error) {
	f, err := s.verdictFeed()
	if err != nil {
		return nil, err
	}
	cursor, err := feed.ParseCursor(req.GetCursor())
	if err != nil {
		return nil, verdictStatus(err)
	}
	wait := feed.ClampWait(time.Duration(req.GetWaitMs()) * time.Millisecond)
	page, err := f.Poll(ctx, audience, cursor, wait)
	if err != nil {
		return nil, verdictStatus(err)
	}
	resp := &platformv1.PollDeviceVerdictsResponse{
		Cursor:   page.Next.String(),
		Verdicts: make([]*platformv1.DeviceVerdictEvent, 0, len(page.Verdicts)),
	}
	for _, recorded := range page.Verdicts {
		resp.Verdicts = append(resp.Verdicts, deviceVerdictEvent(recorded))
	}
	return resp, nil
}

// deviceVerdictEvent renders a recorded device verdict for the wire.
func deviceVerdictEvent(recorded verdict.RecordedDeviceVerdict) *platformv1.DeviceVerdictEvent {
	v := recorded.Verdict
	return &platformv1.DeviceVerdictEvent{
		EventId:       recorded.EventID,
		RecordedAt:    timestamppb.New(recorded.RecordedAt),
		DeviceId:      v.DeviceID,
		TenantId:      v.TenantID,
		HostId:        v.HostID,
		Serial:        v.Serial,
		Passed:        v.Passed,
		Cryptographic: v.Cryptographic,
		Reason:        v.Reason,
	}
}

// streamDeviceVerdicts feeds the attestation service's recorded verdicts to
// server's StreamDeviceVerdicts and PollDeviceVerdicts, and returns the feed
// the daemon closes on shutdown. It returns nil, leaving both RPCs
// unavailable, when the service cannot hand out its verdicts.
func streamDeviceVerdicts(server *AttestationServiceServer, attestation AttestationService, opts ...feed.Option) *feed.Feed {
	registry, ok := attestation.(verdict.ObserverRegistry)
	if !ok || server == nil {
		return nil
	}
	f := feed.New(opts...)
	registry.RegisterDeviceVerdictObserver(f)
	server.SetVerdictFeed(f)
	return f
}
