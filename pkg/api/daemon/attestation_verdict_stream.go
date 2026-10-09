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
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	// verdictStreamScope is the scope a token caller of StreamDeviceVerdicts
	// must hold. The gRPC method catalog requires the same scope.
	verdictStreamScope = "attestation:read"

	// platformTenantID is the system tenant firstboot creates and the platform
	// operates as (pkg/app systemTenantID). A principal of this tenant sees the
	// verdicts of every device.
	platformTenantID = "system"

	// verdictSubscriberBuffer is how many verdicts a subscriber may fall
	// behind before the hub ends its stream.
	verdictSubscriberBuffer = 64
)

// The verdict stream's errors are shared with the REST transport, which cannot
// import this package, so they live in pkg/attestation/verdict.
type (
	// ErrVerdictStreamUnavailable is returned when the daemon has no verdict
	// stream to serve.
	ErrVerdictStreamUnavailable = verdict.ErrStreamUnavailable
	// ErrVerdictStreamClosed is returned when the daemon is shutting down.
	ErrVerdictStreamClosed = verdict.ErrStreamClosed
	// ErrVerdictSubscriberBehind ends the stream of a subscriber that fell more
	// than verdictSubscriberBuffer verdicts behind.
	ErrVerdictSubscriberBehind = verdict.ErrSubscriberBehind
	// ErrVerdictStreamForbidden is returned when the caller may not follow
	// device verdicts.
	ErrVerdictStreamForbidden = verdict.ErrStreamForbidden
)

// deviceVerdictHub fans every recorded device verdict out to the open
// StreamDeviceVerdicts streams. It is a verdict.Observer, so the attestation
// service calls it synchronously; it never blocks there.
type deviceVerdictHub struct {
	mu     sync.Mutex
	subs   map[chan verdict.RecordedDeviceVerdict]struct{}
	closed bool
	done   chan struct{}

	// onSubscribe, when set, runs after each subscription is registered.
	// Tests use it to publish only once a stream can receive.
	onSubscribe func()
}

func newDeviceVerdictHub() *deviceVerdictHub {
	return &deviceVerdictHub{
		subs: make(map[chan verdict.RecordedDeviceVerdict]struct{}),
		done: make(chan struct{}),
	}
}

// OnDeviceVerdict implements verdict.Observer. A subscriber whose buffer is
// full is cut off: its channel is closed so its stream ends and it follows
// again, rather than silently missing a failed verdict.
func (h *deviceVerdictHub) OnDeviceVerdict(_ context.Context, recorded verdict.RecordedDeviceVerdict) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.subs {
		select {
		case sub <- recorded:
		default:
			delete(h.subs, sub)
			close(sub)
		}
	}
}

// subscribe registers a new subscriber, or fails once the hub is closed.
func (h *deviceVerdictHub) subscribe() (chan verdict.RecordedDeviceVerdict, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, ErrVerdictStreamClosed{}
	}
	sub := make(chan verdict.RecordedDeviceVerdict, verdictSubscriberBuffer)
	h.subs[sub] = struct{}{}
	h.mu.Unlock()
	if h.onSubscribe != nil {
		h.onSubscribe()
	}
	return sub, nil
}

// unsubscribe removes a subscriber the hub has not already cut off.
func (h *deviceVerdictHub) unsubscribe(sub chan verdict.RecordedDeviceVerdict) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, sub)
}

// Close ends every open stream and refuses new ones. The daemon closes the
// hub before it stops its gRPC servers, whose graceful stop waits for open
// streams to end.
func (h *deviceVerdictHub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	close(h.done)
}

// verdictAudience is the set of tenants whose device verdicts a caller may
// see.
type verdictAudience struct {
	tenantID    string
	everyTenant bool
}

// admits reports whether a verdict on a device of tenantID may reach the
// caller. A device with no tenant is the platform's own and reaches only
// callers that see every tenant.
func (a verdictAudience) admits(tenantID string) bool {
	return a.everyTenant || (tenantID != "" && tenantID == a.tenantID)
}

// resolveVerdictAudience is the one place that decides which verdicts a
// principal may follow, whatever transport it came in on.
//
//   - A principal naming a tenant sees that tenant only, or every tenant when
//     it is the system tenant: the platform's own infrastructure, such as an
//     overlay gateway.
//   - A certificate that names no tenant is refused.
//   - A principal with no credential sees every tenant only when the Unix
//     socket admitted it by its kernel-verified peer credentials. Any other
//     caller without a credential, such as one on TCP, is refused.
func resolveVerdictAudience(principal verdict.StreamPrincipal) (verdictAudience, error) {
	if principal.TenantID != "" {
		return audienceOfTenant(principal.TenantID), nil
	}
	if principal.HasCertificate {
		return verdictAudience{}, ErrVerdictStreamForbidden{Reason: "the certificate names no tenant"}
	}
	if principal.UnixPeer {
		return verdictAudience{everyTenant: true}, nil
	}
	return verdictAudience{}, ErrVerdictStreamForbidden{Reason: "the caller presented no credential"}
}

// verdictPrincipalFor reads the caller of a gRPC (or Unix socket) context.
//
//   - A platform-token caller needs attestation:read and is the tenant of its
//     token. A token naming no tenant is refused.
//   - A bearer token the daemon could only check for validity carries no
//     scopes, so it is refused.
//   - An mTLS identity is its certificate's tenant.
func verdictPrincipalFor(ctx context.Context) (verdict.StreamPrincipal, error) {
	if authCtx, ok := grpccreds.AuthorizedContextFromContext(ctx); ok && authCtx != nil {
		if !authCtx.HasScope(verdictStreamScope) {
			return verdict.StreamPrincipal{}, ErrVerdictStreamForbidden{Reason: verdictStreamScope + " is required"}
		}
		if authCtx.TenantID == "" {
			return verdict.StreamPrincipal{}, ErrVerdictStreamForbidden{Reason: "the token names no tenant"}
		}
		return verdict.StreamPrincipal{TenantID: authCtx.TenantID}, nil
	}
	if _, ok := grpccreds.TokenFromContext(ctx); ok {
		return verdict.StreamPrincipal{}, ErrVerdictStreamForbidden{Reason: "the token carries no scopes"}
	}
	if identity := IdentityFromContext(ctx); identity != nil {
		return verdict.StreamPrincipal{TenantID: identity.TenantID, HasCertificate: true}, nil
	}
	_, unixPeer := peercred.UnixCredentialsFromContext(ctx)
	return verdict.StreamPrincipal{UnixPeer: unixPeer}, nil
}

// verdictAudienceFor decides which verdicts the caller of ctx may follow.
func verdictAudienceFor(ctx context.Context) (verdictAudience, error) {
	principal, err := verdictPrincipalFor(ctx)
	if err != nil {
		return verdictAudience{}, err
	}
	return resolveVerdictAudience(principal)
}

func audienceOfTenant(tenantID string) verdictAudience {
	if tenantID == platformTenantID {
		return verdictAudience{everyTenant: true}
	}
	return verdictAudience{tenantID: tenantID}
}

// OpenStream admits principal to the stream and registers its subscription.
// It is the transport-neutral entry: gRPC, the Unix socket and REST all follow
// verdicts through it.
func (h *deviceVerdictHub) OpenStream(principal verdict.StreamPrincipal) (verdict.StreamSubscription, error) {
	audience, err := resolveVerdictAudience(principal)
	if err != nil {
		return nil, err
	}
	sub, err := h.subscribe()
	if err != nil {
		return nil, err
	}
	return &verdictSubscription{hub: h, sub: sub, audience: audience}, nil
}

// verdictSubscription is one admitted follower of a deviceVerdictHub.
type verdictSubscription struct {
	hub      *deviceVerdictHub
	sub      chan verdict.RecordedDeviceVerdict
	audience verdictAudience
}

// Serve implements verdict.StreamSubscription.
func (s *verdictSubscription) Serve(
	ctx context.Context,
	send func(verdict.RecordedDeviceVerdict) error,
	heartbeat verdict.StreamHeartbeat,
) error {
	var beat <-chan time.Time
	if heartbeat.Every > 0 && heartbeat.Beat != nil {
		ticker := time.NewTicker(heartbeat.Every)
		defer ticker.Stop()
		beat = ticker.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.hub.done:
			return ErrVerdictStreamClosed{}
		case <-beat:
			if err := heartbeat.Beat(); err != nil {
				return err
			}
		case recorded, ok := <-s.sub:
			if !ok {
				return ErrVerdictSubscriberBehind{}
			}
			if !s.audience.admits(recorded.Verdict.TenantID) {
				continue
			}
			if err := send(recorded); err != nil {
				return err
			}
		}
	}
}

// Close implements verdict.StreamSubscription.
func (s *verdictSubscription) Close() {
	s.hub.unsubscribe(s.sub)
}

// OpenVerdictStream implements verdict.StreamOpener. Until a hub is set it
// answers ErrVerdictStreamUnavailable.
func (s *AttestationServiceServer) OpenVerdictStream(principal verdict.StreamPrincipal) (verdict.StreamSubscription, error) {
	if s == nil {
		return nil, ErrVerdictStreamUnavailable{}
	}
	hub := s.verdicts.Load()
	if hub == nil {
		return nil, ErrVerdictStreamUnavailable{}
	}
	return hub.OpenStream(principal)
}

// SetVerdictHub installs the hub StreamDeviceVerdicts serves from. Until it
// is set the RPC answers FailedPrecondition.
func (s *AttestationServiceServer) SetVerdictHub(hub *deviceVerdictHub) {
	if s == nil {
		return
	}
	s.verdicts.Store(hub)
}

// StreamDeviceVerdicts streams every device verdict recorded from now on that
// the caller may see, until the caller goes away or the daemon shuts down.
func (s *AttestationServiceServer) StreamDeviceVerdicts(
	_ *platformv1.StreamDeviceVerdictsRequest,
	stream grpc.ServerStreamingServer[platformv1.DeviceVerdictEvent],
) error {
	if s == nil || s.verdicts.Load() == nil {
		return verdictStreamStatus(ErrVerdictStreamUnavailable{})
	}
	ctx := stream.Context()
	principal, err := verdictPrincipalFor(ctx)
	if err != nil {
		return verdictStreamStatus(err)
	}
	subscription, err := s.OpenVerdictStream(principal)
	if err != nil {
		return verdictStreamStatus(err)
	}
	defer subscription.Close()

	err = subscription.Serve(ctx, func(recorded verdict.RecordedDeviceVerdict) error {
		return stream.Send(deviceVerdictEvent(recorded))
	}, verdict.StreamHeartbeat{})
	return verdictStreamStatus(err)
}

// verdictStreamStatus maps a stream error to its gRPC status. An error it does
// not know, such as a failed send, passes through.
func verdictStreamStatus(err error) error {
	var (
		unavailable ErrVerdictStreamUnavailable
		forbidden   ErrVerdictStreamForbidden
		closed      ErrVerdictStreamClosed
		behind      ErrVerdictSubscriberBehind
	)
	switch {
	case err == nil:
		return nil
	case errors.As(err, &unavailable):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &forbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.As(err, &closed):
		return status.Error(codes.Unavailable, err.Error())
	case errors.As(err, &behind):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	}
	return err
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

// streamDeviceVerdicts serves the attestation service's recorded verdicts on
// server's StreamDeviceVerdicts, and returns the hub the daemon closes on
// shutdown. It returns nil, leaving the RPC unavailable, when the service
// cannot hand out its verdicts.
func streamDeviceVerdicts(server *AttestationServiceServer, attestation AttestationService) *deviceVerdictHub {
	registry, ok := attestation.(verdict.ObserverRegistry)
	if !ok || server == nil {
		return nil
	}
	hub := newDeviceVerdictHub()
	registry.RegisterDeviceVerdictObserver(hub)
	server.SetVerdictHub(hub)
	return hub
}
