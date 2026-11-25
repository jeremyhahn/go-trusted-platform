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

package device

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type fakeChallengeClient struct {
	platformv1.DeviceServiceClient

	challengeReq  *platformv1.IssueAttestationChallengeRequest
	challengeResp *platformv1.IssueAttestationChallengeResponse
	attestReq     *platformv1.AttestDeviceRequest
	attestResp    *platformv1.AttestDeviceResponse
	err           error
}

func (f *fakeChallengeClient) IssueAttestationChallenge(_ context.Context, in *platformv1.IssueAttestationChallengeRequest, _ ...grpc.CallOption) (*platformv1.IssueAttestationChallengeResponse, error) {
	f.challengeReq = in
	return f.challengeResp, f.err
}

func (f *fakeChallengeClient) AttestDevice(_ context.Context, in *platformv1.AttestDeviceRequest, _ ...grpc.CallOption) (*platformv1.AttestDeviceResponse, error) {
	f.attestReq = in
	return f.attestResp, f.err
}

func TestClient_IssueAttestationChallenge(t *testing.T) {
	expires := timestamppb.New(time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC))
	fake := &fakeChallengeClient{challengeResp: &platformv1.IssueAttestationChallengeResponse{
		ChallengeId: "c1",
		Nonce:       []byte{1, 2, 3},
		ExpiresAt:   expires,
	}}

	resp, err := NewClientFromGRPC(fake).IssueAttestationChallenge(context.Background(), 42)
	if err != nil {
		t.Fatalf("IssueAttestationChallenge: %v", err)
	}
	if fake.challengeReq.GetDeviceId() != "42" {
		t.Errorf("device_id = %q, want 42", fake.challengeReq.GetDeviceId())
	}
	if resp.GetChallengeId() != "c1" {
		t.Errorf("challenge_id = %q, want c1", resp.GetChallengeId())
	}
	if !bytes.Equal(resp.GetNonce(), []byte{1, 2, 3}) {
		t.Errorf("nonce = %v, want [1 2 3]", resp.GetNonce())
	}
	if !resp.GetExpiresAt().AsTime().Equal(expires.AsTime()) {
		t.Errorf("expires_at = %v, want %v", resp.GetExpiresAt().AsTime(), expires.AsTime())
	}
}

func TestClient_AttestDeviceWithChallenge(t *testing.T) {
	fake := &fakeChallengeClient{attestResp: &platformv1.AttestDeviceResponse{DeviceId: 42, Verified: true}}
	evidence := []byte{1, 2, 3}

	resp, err := NewClientFromGRPC(fake).AttestDeviceWithChallenge(context.Background(), 42, "c1", evidence)
	if err != nil {
		t.Fatalf("AttestDeviceWithChallenge: %v", err)
	}
	if fake.attestReq.GetDeviceId() != "42" || fake.attestReq.GetChallengeId() != "c1" ||
		!bytes.Equal(fake.attestReq.GetEvidence(), evidence) {
		t.Errorf("request = %+v, want device 42, challenge c1 and the evidence", fake.attestReq)
	}
	if !resp.GetVerified() {
		t.Error("the verified result was not reported")
	}
}

func TestClient_AttestDevice_SendsNoChallenge(t *testing.T) {
	fake := &fakeChallengeClient{attestResp: &platformv1.AttestDeviceResponse{DeviceId: 42}}

	if _, err := NewClientFromGRPC(fake).AttestDevice(context.Background(), 42, []byte{1}); err != nil {
		t.Fatalf("AttestDevice: %v", err)
	}
	if fake.attestReq.GetChallengeId() != "" {
		t.Errorf("challenge_id = %q, want empty", fake.attestReq.GetChallengeId())
	}
}

func TestClient_ChallengeErrors(t *testing.T) {
	cause := errors.New("store unavailable")
	client := NewClientFromGRPC(&fakeChallengeClient{err: cause})

	_, err := client.IssueAttestationChallenge(context.Background(), 7)
	var issue *ErrIssueAttestationChallengeFailed
	if !errors.As(err, &issue) || issue.ID != 7 || !errors.Is(err, cause) {
		t.Fatalf("IssueAttestationChallenge err = %v, want ErrIssueAttestationChallengeFailed for 7 wrapping the cause", err)
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("message %q does not name the device", err.Error())
	}

	_, err = client.AttestDeviceWithChallenge(context.Background(), 7, "c1", nil)
	var attest *ErrAttestDeviceFailed
	if !errors.As(err, &attest) || attest.ID != 7 || !errors.Is(err, cause) {
		t.Fatalf("AttestDeviceWithChallenge err = %v, want ErrAttestDeviceFailed for 7 wrapping the cause", err)
	}
}
