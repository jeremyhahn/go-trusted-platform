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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict/feed"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkattestation "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
)

// verdictRegistryService is an attestation service that hands its recorded
// verdicts to the registered verdict observers.
type verdictRegistryService struct {
	AttestationService
	observers []verdict.Observer
}

func (s *verdictRegistryService) RegisterDeviceVerdictObserver(obs verdict.Observer) {
	s.observers = append(s.observers, obs)
}

func (s *verdictRegistryService) record(v verdict.DeviceVerdict, eventID string) {
	recorded := verdict.RecordedDeviceVerdict{
		Verdict:    v,
		EventID:    eventID,
		RecordedAt: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
	}
	for _, obs := range s.observers {
		obs.OnDeviceVerdict(context.Background(), recorded)
	}
}

// tokenContexts is a platform-token validator keyed by bearer token: each
// token stands for one AuthorizedContext, and a required scope is enforced
// as the real validator does.
type tokenContexts map[string]*platformtoken.AuthorizedContext

func (v tokenContexts) ValidateToken(_ context.Context, token string) (bool, error) {
	_, ok := v[token]
	return ok, nil
}

func (v tokenContexts) AuthorizeToken(_ context.Context, token, requiredPerm, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	authCtx, ok := v[token]
	if !ok {
		return nil, &platformtoken.InvalidTokenError{Detail: "unknown test token"}
	}
	if requiredPerm != "" {
		if err := authCtx.RequireScope(requiredPerm); err != nil {
			return nil, err
		}
	}
	return authCtx, nil
}

// verdictFeedServer returns an attestation server wired to a fresh feed, the
// attestation service whose verdicts it serves, and a signal fired each time
// a follower takes the head of the feed.
func verdictFeedServer(t *testing.T, opts ...feed.Option) (*AttestationServiceServer, *verdictRegistryService, *feed.Feed, *signal) {
	t.Helper()
	attestation := &verdictRegistryService{}
	server := NewAttestationServiceServer(attestation, discardLogger().Slog())
	followed := newSignal()
	f := streamDeviceVerdicts(server, attestation, append(opts, feed.WithOnFollow(followed.fire))...)
	if f == nil {
		t.Fatal("an attestation service that hands out its verdicts must get a feed")
	}
	t.Cleanup(f.Close)
	return server, attestation, f, followed
}

// verdictStreamServer serves an attestation server wired to a fresh feed
// over listener with opts.
func verdictStreamServer(t *testing.T, listener net.Listener, opts ...grpc.ServerOption) (*verdictRegistryService, *feed.Feed, *signal) {
	t.Helper()
	server, attestation, f, followed := verdictFeedServer(t)
	grpcServer := grpc.NewServer(opts...)
	platformv1.RegisterAttestationServiceServer(grpcServer, server)
	served := make(chan error, 1)
	go func() { served <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		f.Close()
		grpcServer.GracefulStop()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return attestation, f, followed
}

func dialVerdicts(t *testing.T, target string, creds grpc.DialOption) *sdkattestation.Client {
	t.Helper()
	conn, err := grpc.NewClient(target, creds)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return sdkattestation.NewClientFromGRPC(platformv1.NewAttestationServiceClient(conn))
}

func withBearer(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

// TestStreamDeviceVerdictsOverUnixSocket follows verdicts the way gatewayd
// does by default: over platformd's Unix socket, admitted by the peer's
// credentials, seeing every tenant's devices.
func TestStreamDeviceVerdictsOverUnixSocket(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "d.sock"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	attestation, _, followed := verdictStreamServer(t, listener, grpc.Creds(local.NewCredentials()))
	client := dialVerdicts(t, "unix://"+listener.Addr().String(), grpc.WithTransportCredentials(local.NewCredentials()))

	ctx, cancel := context.WithTimeout(context.Background(), streamDeadline)
	defer cancel()
	stream, err := client.StreamDeviceVerdicts(ctx)
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts: %v", err)
	}
	followed.await(t, 1, "verdict streams following")

	failed := verdict.DeviceVerdict{DeviceID: 42, TenantID: "tenant-a", HostID: "node-42", Serial: "SN42", Cryptographic: true, Reason: "signature invalid"}
	passed := verdict.DeviceVerdict{DeviceID: 43, HostID: "node-43", Passed: true}
	attestation.record(failed, "ev-42")
	attestation.record(passed, "ev-43")

	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if first.GetEventId() != "ev-42" || first.GetDeviceId() != 42 || first.GetTenantId() != "tenant-a" ||
		first.GetHostId() != "node-42" || first.GetSerial() != "SN42" || first.GetPassed() ||
		!first.GetCryptographic() || first.GetReason() != "signature invalid" ||
		!first.GetRecordedAt().AsTime().Equal(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("the failed verdict must cross the wire intact: %+v", first)
	}
	second, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if second.GetDeviceId() != 43 || !second.GetPassed() {
		t.Fatalf("a platform-owned device's passing verdict must reach the gateway: %+v", second)
	}
}

// TestStreamDeviceVerdictsOverTCPEnforcesScopeAndTenant follows verdicts with
// platform tokens through the gRPC OIDC interceptor: a tenant sees only its
// own devices, the system tenant sees all, and a token without
// attestation:read is refused.
func TestStreamDeviceVerdictsOverTCPEnforcesScopeAndTenant(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	validator := tokenContexts{
		"tenant-a":  {Subject: "a", TenantID: "tenant-a", Scopes: []string{"attestation:read"}},
		"operator":  {Subject: "op", TenantID: feed.PlatformTenantID, Scopes: []string{"attestation:*"}},
		"no-scope":  {Subject: "n", TenantID: "tenant-a", Scopes: []string{"device:read"}},
		"no-tenant": {Subject: "x", Scopes: []string{"attestation:read"}},
	}
	// Bearer tokens cross the network only inside verified TLS: the
	// self-signed test certificate is its own trust root.
	cert := sharedTestTLSCertificate()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	attestation, _, followed := verdictStreamServer(t, listener,
		grpc.Creds(credentials.NewServerTLSFromCert(&cert)),
		grpc.StreamInterceptor(grpccreds.OIDCStreamInterceptor(grpccreds.WithTokenValidator(validator))))
	client := dialVerdicts(t, listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13})))

	ctx, cancel := context.WithTimeout(context.Background(), streamDeadline)
	defer cancel()

	for token, want := range map[string]codes.Code{"no-scope": codes.PermissionDenied, "no-tenant": codes.PermissionDenied} {
		stream, err := client.StreamDeviceVerdicts(withBearer(ctx, token))
		if err == nil {
			_, err = stream.Recv()
		}
		if status.Code(errors.Unwrap(err)) != want && status.Code(err) != want {
			t.Fatalf("token %q: got %v, want %s", token, err, want)
		}
	}

	tenantStream, err := client.StreamDeviceVerdicts(withBearer(ctx, "tenant-a"))
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts(tenant-a): %v", err)
	}
	operatorStream, err := client.StreamDeviceVerdicts(withBearer(ctx, "operator"))
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts(operator): %v", err)
	}
	followed.await(t, 2, "verdict streams following")

	attestation.record(verdict.DeviceVerdict{DeviceID: 1, TenantID: "tenant-b", Reason: "pcr mismatch"}, "ev-b")
	attestation.record(verdict.DeviceVerdict{DeviceID: 2, Reason: "pcr mismatch"}, "ev-platform")
	attestation.record(verdict.DeviceVerdict{DeviceID: 3, TenantID: "tenant-a", Reason: "pcr mismatch"}, "ev-a")

	got, err := tenantStream.Recv()
	if err != nil {
		t.Fatalf("Recv(tenant-a): %v", err)
	}
	if got.GetEventId() != "ev-a" {
		t.Fatalf("tenant-a must see only its own device's verdict first, got %q", got.GetEventId())
	}
	for _, want := range []string{"ev-b", "ev-platform", "ev-a"} {
		got, err := operatorStream.Recv()
		if err != nil {
			t.Fatalf("Recv(operator): %v", err)
		}
		if got.GetEventId() != want {
			t.Fatalf("the system tenant sees every verdict in order: got %q, want %q", got.GetEventId(), want)
		}
	}
}

func TestVerdictAudienceFor(t *testing.T) {
	tokenCtx := func(authCtx *platformtoken.AuthorizedContext) context.Context {
		return grpccreds.ContextWithToken(grpccreds.ContextWithAuthorizedContext(context.Background(), authCtx), "tok")
	}
	mtlsCtx := func(tenantID string) context.Context {
		return context.WithValue(context.Background(), ContextKeyIdentity, &auth.Identity{ID: "gw", TenantID: tenantID})
	}
	tests := []struct {
		name      string
		ctx       context.Context
		forbidden bool
		sees      []string
		blind     []string
	}{
		{name: "tenant token", ctx: tokenCtx(&platformtoken.AuthorizedContext{TenantID: "t1", Scopes: []string{"attestation:read"}}),
			sees: []string{"t1"}, blind: []string{"t2", ""}},
		{name: "system token", ctx: tokenCtx(&platformtoken.AuthorizedContext{TenantID: feed.PlatformTenantID, Scopes: []string{"*:*"}}),
			sees: []string{"t1", "t2", ""}},
		{name: "token without the scope", ctx: tokenCtx(&platformtoken.AuthorizedContext{TenantID: "t1", Scopes: []string{"attestation:write"}}), forbidden: true},
		{name: "token without a tenant", ctx: tokenCtx(&platformtoken.AuthorizedContext{Scopes: []string{"attestation:read"}}), forbidden: true},
		{name: "unscoped bearer token", ctx: grpccreds.ContextWithToken(context.Background(), "tok"), forbidden: true},
		{name: "tenant certificate", ctx: mtlsCtx("t2"), sees: []string{"t2"}, blind: []string{"t1", ""}},
		{name: "infrastructure certificate", ctx: mtlsCtx(""), sees: []string{"t1", ""}},
		{name: "local peer", ctx: context.Background(), sees: []string{"t1", "t2", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audience, err := verdictAudienceFor(tt.ctx)
			if tt.forbidden {
				var forbidden ErrVerdictStreamForbidden
				if !errors.As(err, &forbidden) {
					t.Fatalf("err = %v, want ErrVerdictStreamForbidden", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("verdictAudienceFor: %v", err)
			}
			for _, tenant := range tt.sees {
				if !audience.Admits(tenant) {
					t.Errorf("must see tenant %q", tenant)
				}
			}
			for _, tenant := range tt.blind {
				if audience.Admits(tenant) {
					t.Errorf("must not see tenant %q", tenant)
				}
			}
		})
	}
}

// TestVerdictAudienceOfTokenRefusesAMissingToken guards QUIC and MCP, which
// have no peer identity to fall back on: no token is no audience.
func TestVerdictAudienceOfTokenRefusesAMissingToken(t *testing.T) {
	var forbidden ErrVerdictStreamForbidden
	if _, err := verdictAudienceOfToken(nil); !errors.As(err, &forbidden) {
		t.Fatalf("err = %v, want ErrVerdictStreamForbidden", err)
	}
	if status.Code(verdictStatus(ErrVerdictStreamForbidden{Reason: "x"})) != codes.PermissionDenied {
		t.Fatal("a refused audience must be PermissionDenied on the wire")
	}
}

func TestStreamDeviceVerdictsWithoutAFeed(t *testing.T) {
	// An attestation service that cannot hand out its verdicts gets no feed,
	// and both RPCs say so rather than serving nothing forever.
	server := NewAttestationServiceServer(&recordingHostQuoteService{}, discardLogger().Slog())
	if f := streamDeviceVerdicts(server, &recordingHostQuoteService{}); f != nil {
		t.Fatal("no feed for a service that cannot hand out its verdicts")
	}
	if f := streamDeviceVerdicts(nil, &verdictRegistryService{}); f != nil {
		t.Fatal("no feed without a server to serve it")
	}
	err := server.StreamDeviceVerdicts(&platformv1.StreamDeviceVerdictsRequest{}, nil)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want FailedPrecondition", err)
	}
	if _, err := server.PollDeviceVerdicts(context.Background(), &platformv1.PollDeviceVerdictsRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("PollDeviceVerdicts = %v, want FailedPrecondition", err)
	}
	var nilServer *AttestationServiceServer
	if status.Code(nilServer.StreamDeviceVerdicts(nil, nil)) != codes.FailedPrecondition {
		t.Fatal("a nil server must answer FailedPrecondition")
	}
}

// TestDeviceVerdictFeedShutdownEndsOpenStreams closes the feed under an open
// stream: the stream must end, so the daemon's graceful gRPC stop does not
// wait on it, and no stream may open afterwards.
func TestDeviceVerdictFeedShutdownEndsOpenStreams(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "d.sock"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	_, f, followed := verdictStreamServer(t, listener, grpc.Creds(local.NewCredentials()))
	client := dialVerdicts(t, "unix://"+listener.Addr().String(), grpc.WithTransportCredentials(local.NewCredentials()))

	ctx, cancel := context.WithTimeout(context.Background(), streamDeadline)
	defer cancel()
	stream, err := client.StreamDeviceVerdicts(ctx)
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts: %v", err)
	}
	followed.await(t, 1, "verdict streams following")

	f.Close()
	if _, err := stream.Recv(); status.Code(err) != codes.Unavailable {
		t.Fatalf("Recv after shutdown = %v, want Unavailable", err)
	}
	late, err := client.StreamDeviceVerdicts(ctx)
	if err == nil {
		_, err = late.Recv()
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("a stream opened after shutdown = %v, want Unavailable", err)
	}
}

// TestPollDeviceVerdictsFollowsFromACursor long-polls the way the REST, QUIC
// and MCP transports do: the first poll takes the head, each later poll
// returns what was recorded since, filtered to the caller's tenant.
func TestPollDeviceVerdictsFollowsFromACursor(t *testing.T) {
	server, attestation, _, _ := verdictFeedServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), streamDeadline)
	defer cancel()

	head, err := server.PollDeviceVerdictsFor(ctx, feed.Tenant("tenant-a"), &platformv1.PollDeviceVerdictsRequest{})
	if err != nil {
		t.Fatalf("PollDeviceVerdictsFor(head): %v", err)
	}
	if head.GetCursor() == "" || len(head.GetVerdicts()) != 0 {
		t.Fatalf("the first poll returns only a cursor: %+v", head)
	}

	attestation.record(verdict.DeviceVerdict{DeviceID: 1, TenantID: "tenant-b", Reason: "pcr mismatch"}, "ev-b")
	attestation.record(verdict.DeviceVerdict{DeviceID: 2, TenantID: "tenant-a", Reason: "pcr mismatch"}, "ev-a")

	page, err := server.PollDeviceVerdictsFor(ctx, feed.Tenant("tenant-a"),
		&platformv1.PollDeviceVerdictsRequest{Cursor: head.GetCursor(), WaitMs: 1000})
	if err != nil {
		t.Fatalf("PollDeviceVerdictsFor: %v", err)
	}
	if len(page.GetVerdicts()) != 1 || page.GetVerdicts()[0].GetEventId() != "ev-a" || page.GetVerdicts()[0].GetDeviceId() != 2 {
		t.Fatalf("tenant-a must see only its own device's verdict: %+v", page.GetVerdicts())
	}
	if page.GetCursor() == head.GetCursor() {
		t.Fatal("the cursor must advance past the verdicts read")
	}

	// A local gRPC peer sees every tenant.
	every, err := server.PollDeviceVerdicts(ctx, &platformv1.PollDeviceVerdictsRequest{Cursor: head.GetCursor()})
	if err != nil {
		t.Fatalf("PollDeviceVerdicts: %v", err)
	}
	if len(every.GetVerdicts()) != 2 {
		t.Fatalf("a local peer sees every tenant's verdicts: %+v", every.GetVerdicts())
	}
}

func TestPollDeviceVerdictsRefusesBadCursors(t *testing.T) {
	server, attestation, _, _ := verdictFeedServer(t, feed.WithCapacity(2))
	ctx := context.Background()

	head, err := server.PollDeviceVerdicts(ctx, &platformv1.PollDeviceVerdictsRequest{})
	if err != nil {
		t.Fatalf("PollDeviceVerdicts(head): %v", err)
	}
	for i, id := range []string{"ev-1", "ev-2", "ev-3"} {
		attestation.record(verdict.DeviceVerdict{DeviceID: uint64(i + 1), TenantID: "t1"}, id)
	}

	tests := []struct {
		name   string
		cursor string
		want   codes.Code
	}{
		{name: "missed verdicts", cursor: head.GetCursor(), want: codes.ResourceExhausted},
		{name: "malformed", cursor: "garbage", want: codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := server.PollDeviceVerdicts(ctx, &platformv1.PollDeviceVerdictsRequest{Cursor: tt.cursor})
			if status.Code(err) != tt.want {
				t.Fatalf("err = %v, want %s", err, tt.want)
			}
		})
	}
}

func TestPollDeviceVerdictsRefusesAForbiddenCaller(t *testing.T) {
	server, _, _, _ := verdictFeedServer(t)
	ctx := grpccreds.ContextWithToken(context.Background(), "tok")
	if _, err := server.PollDeviceVerdicts(ctx, &platformv1.PollDeviceVerdictsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied for an unscoped bearer token", err)
	}
}
