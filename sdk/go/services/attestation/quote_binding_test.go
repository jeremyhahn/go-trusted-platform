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

package attestation

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/quotebind"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/quotebind/quotebindtest"
)

var (
	callerBinding = bytes.Repeat([]byte{0xa1}, 32)
	relayBinding  = bytes.Repeat([]byte{0xb2}, 32)
)

// quotingNode answers the two quote rpcs the way a node does: it quotes
// SHA-256(nonce || the binding of the connection the request arrived on).
// The caller's connection exports callerBinding; nodeBinding is what the
// node's connection exported — callerBinding when the call is direct, the
// relay's own binding when it is not. echo is the channel_binding the
// response carries, which a relay may rewrite.
type quotingNode struct {
	platformv1.AttestationServiceClient

	nodeBinding []byte
	echo        []byte
	err         error
}

func direct() *quotingNode {
	return &quotingNode{nodeBinding: callerBinding, echo: callerBinding}
}

func relayed() *quotingNode {
	return &quotingNode{nodeBinding: relayBinding, echo: relayBinding}
}

func (n *quotingNode) quote(ctx context.Context, nonce []byte, opts []grpc.CallOption) ([]byte, error) {
	if err := quotebindtest.Bind(ctx, opts, callerBinding); err != nil {
		return nil, err
	}
	if n.err != nil {
		return nil, n.err
	}
	return quotebindtest.Quote(nonce, n.nodeBinding), nil
}

func (n *quotingNode) GetAttestationQuote(ctx context.Context, in *platformv1.GetAttestationQuoteRequest, opts ...grpc.CallOption) (*platformv1.GetAttestationQuoteResponse, error) {
	data, err := n.quote(ctx, in.GetNonce(), opts)
	if err != nil {
		return nil, err
	}
	return &platformv1.GetAttestationQuoteResponse{
		Quote:          &platformv1.AttestationQuote{QuoteData: data},
		ChannelBinding: n.echo,
	}, nil
}

func (n *quotingNode) CollectHostAttestation(ctx context.Context, in *platformv1.CollectHostAttestationRequest, opts ...grpc.CallOption) (*platformv1.CollectHostAttestationResponse, error) {
	data, err := n.quote(ctx, in.GetNonce(), opts)
	if err != nil {
		return nil, err
	}
	return &platformv1.CollectHostAttestationResponse{
		Attestation: &platformv1.HostAttestation{QuoteData: data},
	}, nil
}

func TestGetAttestationQuote_AcceptsTheQuoteBoundToItsConnection(t *testing.T) {
	resp, err := NewClientFromGRPC(direct()).GetAttestationQuote(context.Background(), nil, []byte("nonce"))
	if err != nil {
		t.Fatalf("GetAttestationQuote: %v", err)
	}
	if !bytes.Equal(resp.GetChannelBinding(), callerBinding) {
		t.Errorf("channel_binding = %x, want the caller's connection binding", resp.GetChannelBinding())
	}
}

// TestGetAttestationQuote_RefusesARelayedQuote is the oracle #482 closes: a
// relay asks the node for a quote of the caller's nonce over its own
// connection and hands it back. The quote is genuine; it is not bound to the
// caller's connection, so the client refuses it — with the relay's echo and
// with an echo rewritten to the caller's binding.
func TestGetAttestationQuote_RefusesARelayedQuote(t *testing.T) {
	rewritten := relayed()
	rewritten.echo = callerBinding
	nodes := map[string]*quotingNode{"relay's echo": relayed(), "rewritten echo": rewritten}

	for name, node := range nodes {
		t.Run(name, func(t *testing.T) {
			_, err := NewClientFromGRPC(node).GetAttestationQuote(context.Background(), nil, []byte("nonce"))
			requireQuoteRefused(t, err)
		})
	}
}

func TestGetAttestationQuote_TransportRefusalIsTyped(t *testing.T) {
	node := direct()
	node.err = status.Error(codes.FailedPrecondition, "channel binding required")

	_, err := NewClientFromGRPC(node).GetAttestationQuote(context.Background(), nil, []byte("nonce"))
	var failed *ErrGetQuoteFailed
	if !errors.As(err, &failed) || status.Code(failed.Cause) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want ErrGetQuoteFailed carrying FailedPrecondition", err)
	}
}

func TestCollectHostAttestation_AcceptsTheQuoteBoundToItsConnection(t *testing.T) {
	host, err := NewClientFromGRPC(direct()).CollectHostAttestation(context.Background(), nil, []byte("nonce"))
	if err != nil {
		t.Fatalf("CollectHostAttestation: %v", err)
	}
	if len(host.GetQuoteData()) == 0 {
		t.Error("host attestation carries no quote")
	}
}

func TestCollectHostAttestation_RefusesARelayedQuote(t *testing.T) {
	_, err := NewClientFromGRPC(relayed()).CollectHostAttestation(context.Background(), nil, []byte("nonce"))
	var failed *ErrCollectHostAttestationFailed
	if !errors.As(err, &failed) {
		t.Fatalf("err = %v, want ErrCollectHostAttestationFailed", err)
	}
	var notBound *quotebind.ErrQuoteNotBound
	if !errors.As(err, &notBound) {
		t.Fatalf("err = %v, want it to wrap quotebind.ErrQuoteNotBound", err)
	}
}

func TestCollectHostAttestation_TransportRefusalIsTyped(t *testing.T) {
	node := direct()
	node.err = status.Error(codes.FailedPrecondition, "channel binding required")

	_, err := NewClientFromGRPC(node).CollectHostAttestation(context.Background(), nil, []byte("nonce"))
	var failed *ErrCollectHostAttestationFailed
	if !errors.As(err, &failed) || status.Code(failed.Cause) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want ErrCollectHostAttestationFailed carrying FailedPrecondition", err)
	}
}

func requireQuoteRefused(t *testing.T, err error) {
	t.Helper()
	var failed *ErrGetQuoteFailed
	if !errors.As(err, &failed) {
		t.Fatalf("err = %v, want ErrGetQuoteFailed", err)
	}
	var notBound *quotebind.ErrQuoteNotBound
	if !errors.As(err, &notBound) {
		t.Fatalf("err = %v, want it to wrap quotebind.ErrQuoteNotBound", err)
	}
}
