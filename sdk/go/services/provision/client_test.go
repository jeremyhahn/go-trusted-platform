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

package provision

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

// fakeConfigDeliveryClient implements platformv1.ConfigDeliveryServiceClient
// with programmable responses so the wrapper's argument mapping and typed
// error wrapping can be asserted without a daemon.
type fakeConfigDeliveryClient struct {
	err error

	lastFetchConfig *platformv1.FetchConfigRequest
	lastSignDigest  *platformv1.SignDigestRequest
	lastPoll        *platformv1.PollSessionRequest
	lastFulfill     *platformv1.FulfillSessionRequest
	lastGetSession  *platformv1.GetSessionRequest

	nonce    string
	fetch    *platformv1.FetchConfigResponse
	sign     *platformv1.SignDigestResponse
	poll     *platformv1.PollSessionResponse
	fulfill  *platformv1.FulfillSessionResponse
	sessions []*platformv1.ProvisioningSession
	session  *platformv1.ProvisioningSession
}

func (f *fakeConfigDeliveryClient) GetNonce(ctx context.Context, in *platformv1.GetNonceRequest, opts ...grpc.CallOption) (*platformv1.GetNonceResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetNonceResponse{Nonce: f.nonce}, nil
}

func (f *fakeConfigDeliveryClient) FetchConfig(ctx context.Context, in *platformv1.FetchConfigRequest, opts ...grpc.CallOption) (*platformv1.FetchConfigResponse, error) {
	f.lastFetchConfig = in
	if f.err != nil {
		return nil, f.err
	}
	return f.fetch, nil
}

func (f *fakeConfigDeliveryClient) SignDigest(ctx context.Context, in *platformv1.SignDigestRequest, opts ...grpc.CallOption) (*platformv1.SignDigestResponse, error) {
	f.lastSignDigest = in
	if f.err != nil {
		return nil, f.err
	}
	return f.sign, nil
}

func (f *fakeConfigDeliveryClient) PollSession(ctx context.Context, in *platformv1.PollSessionRequest, opts ...grpc.CallOption) (*platformv1.PollSessionResponse, error) {
	f.lastPoll = in
	if f.err != nil {
		return nil, f.err
	}
	return f.poll, nil
}

func (f *fakeConfigDeliveryClient) FulfillSession(ctx context.Context, in *platformv1.FulfillSessionRequest, opts ...grpc.CallOption) (*platformv1.FulfillSessionResponse, error) {
	f.lastFulfill = in
	if f.err != nil {
		return nil, f.err
	}
	return f.fulfill, nil
}

func (f *fakeConfigDeliveryClient) ListSessions(ctx context.Context, in *platformv1.ListSessionsRequest, opts ...grpc.CallOption) (*platformv1.ListSessionsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ListSessionsResponse{Sessions: f.sessions}, nil
}

func (f *fakeConfigDeliveryClient) GetSession(ctx context.Context, in *platformv1.GetSessionRequest, opts ...grpc.CallOption) (*platformv1.GetSessionResponse, error) {
	f.lastGetSession = in
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetSessionResponse{Session: f.session}, nil
}

var errBackend = errors.New("backend down")

func TestNewClient_NilConnection(t *testing.T) {
	if _, err := NewClient(nil); !errors.Is(err, common.ErrNilConnection) {
		t.Errorf("NewClient(nil) error = %v, want %v", err, common.ErrNilConnection)
	}
}

func TestNewClientFromGRPC(t *testing.T) {
	fake := &fakeConfigDeliveryClient{}
	client := NewClientFromGRPC(fake)
	if client == nil || client.grpc != platformv1.ConfigDeliveryServiceClient(fake) {
		t.Fatal("NewClientFromGRPC must wrap the supplied gRPC client")
	}
}

func TestGetNonce_Success(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{nonce: "n-1"})
	nonce, err := client.GetNonce(context.Background())
	if err != nil {
		t.Fatalf("GetNonce() unexpected error: %v", err)
	}
	if nonce != "n-1" {
		t.Errorf("nonce = %q, want n-1", nonce)
	}
}

func TestGetNonce_Error(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{err: errBackend})
	_, err := client.GetNonce(context.Background())
	var typed *ErrGetNonceFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrGetNonceFailed, got %T: %v", err, err)
	}
	if !errors.Is(err, errBackend) {
		t.Error("error must unwrap to the backend cause")
	}
}

func TestFetchConfig_Success(t *testing.T) {
	fake := &fakeConfigDeliveryClient{
		fetch: &platformv1.FetchConfigResponse{
			Result: &platformv1.FetchConfigResponse_Delivered{
				Delivered: &platformv1.DeliveredConfig{Status: "ok"},
			},
		},
	}
	client := NewClientFromGRPC(fake)

	req := &platformv1.FetchConfigRequest{EabKeyId: "kid", EabHmac: "mac", Nonce: "n"}
	resp, err := client.FetchConfig(context.Background(), req)
	if err != nil {
		t.Fatalf("FetchConfig() unexpected error: %v", err)
	}
	if resp.GetDelivered().GetStatus() != "ok" {
		t.Errorf("status = %q", resp.GetDelivered().GetStatus())
	}
	if fake.lastFetchConfig.GetEabKeyId() != "kid" {
		t.Errorf("request not passed through: %+v", fake.lastFetchConfig)
	}
}

func TestFetchConfig_NilRequest(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{})
	_, err := client.FetchConfig(context.Background(), nil)
	var typed *ErrNilRequest
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrNilRequest, got %T: %v", err, err)
	}
}

func TestFetchConfig_Error(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{err: errBackend})
	_, err := client.FetchConfig(context.Background(), &platformv1.FetchConfigRequest{})
	var typed *ErrFetchConfigFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrFetchConfigFailed, got %T: %v", err, err)
	}
}

func TestSignDigest_Success(t *testing.T) {
	fake := &fakeConfigDeliveryClient{
		sign: &platformv1.SignDigestResponse{Signature: []byte{1, 2}, CertPem: []byte("PEM")},
	}
	client := NewClientFromGRPC(fake)

	resp, err := client.SignDigest(context.Background(), &platformv1.SignDigestRequest{Digest: []byte{9}})
	if err != nil {
		t.Fatalf("SignDigest() unexpected error: %v", err)
	}
	if string(resp.GetCertPem()) != "PEM" {
		t.Errorf("cert_pem = %s", resp.GetCertPem())
	}
	if string(fake.lastSignDigest.GetDigest()) != string([]byte{9}) {
		t.Error("digest not passed through")
	}
}

func TestSignDigest_NilRequestAndError(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{err: errBackend})
	if _, err := client.SignDigest(context.Background(), nil); err == nil {
		t.Fatal("expected nil-request error")
	}
	_, err := client.SignDigest(context.Background(), &platformv1.SignDigestRequest{})
	var typed *ErrSignDigestFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrSignDigestFailed, got %T: %v", err, err)
	}
}

func TestPollSession_Success(t *testing.T) {
	fake := &fakeConfigDeliveryClient{
		poll: &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_PendingStatus{PendingStatus: "pending"},
		},
	}
	client := NewClientFromGRPC(fake)

	resp, err := client.PollSession(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("PollSession() unexpected error: %v", err)
	}
	if resp.GetPendingStatus() != "pending" {
		t.Errorf("pending_status = %q", resp.GetPendingStatus())
	}
	if fake.lastPoll.GetSessionId() != "sess-1" {
		t.Errorf("session_id = %q", fake.lastPoll.GetSessionId())
	}
}

func TestPollSession_Validation(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{})
	_, err := client.PollSession(context.Background(), "")
	var typed *ErrSessionIDRequired
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrSessionIDRequired, got %T: %v", err, err)
	}
}

func TestPollSession_Error(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{err: errBackend})
	_, err := client.PollSession(context.Background(), "sess-1")
	var typed *ErrPollSessionFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrPollSessionFailed, got %T: %v", err, err)
	}
	if typed.SessionID != "sess-1" {
		t.Errorf("SessionID = %q", typed.SessionID)
	}
}

func TestFulfillSession_Success(t *testing.T) {
	fake := &fakeConfigDeliveryClient{
		fulfill: &platformv1.FulfillSessionResponse{Status: "fulfilled"},
	}
	client := NewClientFromGRPC(fake)

	resp, err := client.FulfillSession(context.Background(), "sess-1", 18446744073709551615)
	if err != nil {
		t.Fatalf("FulfillSession() unexpected error: %v", err)
	}
	if resp.GetStatus() != "fulfilled" {
		t.Errorf("status = %q", resp.GetStatus())
	}
	if fake.lastFulfill.GetProfileId() != 18446744073709551615 {
		t.Errorf("profile_id = %d, want max uint64", fake.lastFulfill.GetProfileId())
	}
}

func TestFulfillSession_Validation(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{})

	if _, err := client.FulfillSession(context.Background(), "", 1); err == nil {
		t.Fatal("expected session-ID validation error")
	}
	_, err := client.FulfillSession(context.Background(), "sess-1", 0)
	var typed *ErrProfileIDRequired
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrProfileIDRequired, got %T: %v", err, err)
	}
}

func TestFulfillSession_Error(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{err: errBackend})
	_, err := client.FulfillSession(context.Background(), "sess-1", 42)
	var typed *ErrFulfillSessionFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrFulfillSessionFailed, got %T: %v", err, err)
	}
}

func TestListSessions_Success(t *testing.T) {
	fake := &fakeConfigDeliveryClient{
		sessions: []*platformv1.ProvisioningSession{{Id: "a"}, {Id: "b"}},
	}
	client := NewClientFromGRPC(fake)

	sessions, err := client.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions() unexpected error: %v", err)
	}
	if len(sessions) != 2 || sessions[0].GetId() != "a" {
		t.Errorf("sessions = %+v", sessions)
	}
}

func TestListSessions_Error(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{err: errBackend})
	_, err := client.ListSessions(context.Background())
	var typed *ErrListSessionsFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrListSessionsFailed, got %T: %v", err, err)
	}
}

func TestGetSession_Success(t *testing.T) {
	fake := &fakeConfigDeliveryClient{
		session: &platformv1.ProvisioningSession{Id: "sess-1", Fulfilled: true},
	}
	client := NewClientFromGRPC(fake)

	session, err := client.GetSession(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("GetSession() unexpected error: %v", err)
	}
	if session.GetId() != "sess-1" || !session.GetFulfilled() {
		t.Errorf("session = %+v", session)
	}
	if fake.lastGetSession.GetSessionId() != "sess-1" {
		t.Errorf("session_id = %q", fake.lastGetSession.GetSessionId())
	}
}

func TestGetSession_ValidationAndError(t *testing.T) {
	client := NewClientFromGRPC(&fakeConfigDeliveryClient{})
	if _, err := client.GetSession(context.Background(), ""); err == nil {
		t.Fatal("expected session-ID validation error")
	}

	client = NewClientFromGRPC(&fakeConfigDeliveryClient{err: errBackend})
	_, err := client.GetSession(context.Background(), "sess-1")
	var typed *ErrGetSessionFailed
	if !errors.As(err, &typed) {
		t.Fatalf("expected *ErrGetSessionFailed, got %T: %v", err, err)
	}
}
