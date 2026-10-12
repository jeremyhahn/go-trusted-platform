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
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// fakeBinding is the channel binding fakeBootClient hands to the call's
// binding option, standing in for the exporter of a live connection.
var fakeBinding = []byte("connection-binding")

// fakeBootClient stubs the two boot RPCs the way a transport adapter runs
// them: it calls the call's channel-binding option with the connection's
// binding before "sending" the request. The embedded interface panics on
// any other method.
type fakeBootClient struct {
	platformv1.DeviceServiceClient

	certReq  *platformv1.BootCertificateRequest
	certResp *platformv1.BootCertificateResponse
	delReq   *platformv1.BootDeliveryRequest
	delResp  *platformv1.BootDeliveryResponse
	err      error
}

func (f *fakeBootClient) bind(ctx context.Context, opts []grpc.CallOption) error {
	bind, ok := transport.ChannelBindingFrom(opts)
	if !ok {
		return errors.New("boot call sent without a channel-binding option")
	}
	return bind(ctx, fakeBinding)
}

func (f *fakeBootClient) BootCertificate(ctx context.Context, in *platformv1.BootCertificateRequest, opts ...grpc.CallOption) (*platformv1.BootCertificateResponse, error) {
	if err := f.bind(ctx, opts); err != nil {
		return nil, err
	}
	f.certReq = in
	return f.certResp, f.err
}

func (f *fakeBootClient) BootDelivery(ctx context.Context, in *platformv1.BootDeliveryRequest, opts ...grpc.CallOption) (*platformv1.BootDeliveryResponse, error) {
	if err := f.bind(ctx, opts); err != nil {
		return nil, err
	}
	f.delReq = in
	return f.delResp, f.err
}

// proofOver returns a BootProofFunc that answers "proof(<binding>)", so a
// test can see which binding the proof was computed over.
func proofOver(t *testing.T) BootProofFunc {
	t.Helper()
	return func(_ context.Context, binding []byte) ([]byte, error) {
		return []byte("proof(" + string(binding) + ")"), nil
	}
}

func TestClient_BootCertificate(t *testing.T) {
	fake := &fakeBootClient{certResp: &platformv1.BootCertificateResponse{Identity: "node-1", IdevidChain: "chain"}}

	resp, err := NewClientFromGRPC(fake).BootCertificate(context.Background(), "node-1", proofOver(t))
	if err != nil {
		t.Fatalf("BootCertificate: %v", err)
	}
	if resp.GetIdevidChain() != "chain" {
		t.Errorf("chain = %q, want chain", resp.GetIdevidChain())
	}
	if fake.certReq.GetIdentity() != "node-1" {
		t.Errorf("identity = %q, want node-1", fake.certReq.GetIdentity())
	}
	if got := string(fake.certReq.GetSignature()); got != "proof(connection-binding)" {
		t.Errorf("signature = %q, want the proof over the connection's binding", got)
	}
}

func TestClient_BootCertificate_Error(t *testing.T) {
	cause := errors.New("refused")
	signErr := errors.New("signer unavailable")
	failingSign := func(context.Context, []byte) ([]byte, error) { return nil, signErr }

	tests := []struct {
		name   string
		client *fakeBootClient
		sign   BootProofFunc
		want   func(error) bool
	}{
		{
			name:   "server refusal",
			client: &fakeBootClient{err: cause},
			sign:   proofOver(t),
			want:   func(err error) bool { return errors.Is(err, cause) },
		},
		{
			name:   "signer failure",
			client: &fakeBootClient{},
			sign:   failingSign,
			want:   func(err error) bool { return errors.Is(err, signErr) },
		},
		{
			name:   "no signer",
			client: &fakeBootClient{},
			sign:   nil,
			want: func(err error) bool {
				var missing *ErrBootProofMissing
				return errors.As(err, &missing)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClientFromGRPC(tt.client).BootCertificate(context.Background(), "node-1", tt.sign)

			var typed *ErrBootCertificateFailed
			if !errors.As(err, &typed) || typed.Identity != "node-1" {
				t.Fatalf("want *ErrBootCertificateFailed for node-1, got %v", err)
			}
			if !tt.want(err) {
				t.Errorf("the cause must stay reachable through Unwrap, got %v", err)
			}
			if tt.client.certReq != nil && tt.client.err == nil {
				t.Error("a request was sent without a proof")
			}
		})
	}
}

func TestClient_BootDelivery(t *testing.T) {
	fake := &fakeBootClient{delResp: &platformv1.BootDeliveryResponse{Serial: "SN-1"}}

	resp, err := NewClientFromGRPC(fake).BootDelivery(context.Background(), proofOver(t))
	if err != nil {
		t.Fatalf("BootDelivery: %v", err)
	}
	if resp.GetSerial() != "SN-1" {
		t.Errorf("serial = %q, want SN-1", resp.GetSerial())
	}
	if got := string(fake.delReq.GetEvidence()); got != "proof(connection-binding)" {
		t.Errorf("evidence = %q, want the quote over the connection's binding", got)
	}
}

func TestClient_BootDelivery_Error(t *testing.T) {
	cause := errors.New("refused")
	quoteErr := errors.New("tpm unavailable")
	failingQuote := func(context.Context, []byte) ([]byte, error) { return nil, quoteErr }

	tests := []struct {
		name   string
		client *fakeBootClient
		quote  BootProofFunc
		want   func(error) bool
	}{
		{
			name:   "server refusal",
			client: &fakeBootClient{err: cause},
			quote:  proofOver(t),
			want:   func(err error) bool { return errors.Is(err, cause) },
		},
		{
			name:   "quote failure",
			client: &fakeBootClient{},
			quote:  failingQuote,
			want:   func(err error) bool { return errors.Is(err, quoteErr) },
		},
		{
			name:   "no quote callback",
			client: &fakeBootClient{},
			quote:  nil,
			want: func(err error) bool {
				var missing *ErrBootProofMissing
				return errors.As(err, &missing)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClientFromGRPC(tt.client).BootDelivery(context.Background(), tt.quote)

			var typed *ErrBootDeliveryFailed
			if !errors.As(err, &typed) || !tt.want(err) {
				t.Fatalf("want *ErrBootDeliveryFailed wrapping the cause, got %v", err)
			}
			if tt.client.delReq != nil && tt.client.err == nil {
				t.Error("a request was sent without evidence")
			}
		})
	}
}
