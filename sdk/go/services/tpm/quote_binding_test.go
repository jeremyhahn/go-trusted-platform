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

package tpm

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

// quotingTPM answers Quote the way a node does: it quotes
// SHA-256(nonce || nodeBinding), the binding of the connection the request
// arrived on, and echoes echo. The caller's own connection exports
// callerBinding; the embedded interface panics on any other rpc.
type quotingTPM struct {
	platformv1.TPMServiceClient

	nodeBinding []byte
	echo        []byte
	err         error
}

func (q *quotingTPM) Quote(ctx context.Context, in *platformv1.QuoteRequest, opts ...grpc.CallOption) (*platformv1.QuoteResponse, error) {
	if err := quotebindtest.Bind(ctx, opts, callerBinding); err != nil {
		return nil, err
	}
	if q.err != nil {
		return nil, q.err
	}
	return &platformv1.QuoteResponse{
		Quote:          quotebindtest.Quote(in.GetNonce(), q.nodeBinding),
		ChannelBinding: q.echo,
	}, nil
}

func quote(node *quotingTPM) (*platformv1.QuoteResponse, error) {
	return NewClientFromGRPC(node).Quote(context.Background(), 0x81010002, "", []uint32{0},
		platformv1.PCRBank_PCR_BANK_SHA256, []byte("nonce"))
}

func TestQuote_AcceptsTheQuoteBoundToItsConnection(t *testing.T) {
	resp, err := quote(&quotingTPM{nodeBinding: callerBinding, echo: callerBinding})
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if !bytes.Equal(resp.GetChannelBinding(), callerBinding) {
		t.Errorf("channel_binding = %x, want the caller's connection binding", resp.GetChannelBinding())
	}
}

// TestQuote_RefusesARelayedQuote: a relay obtains the node's quote of the
// caller's nonce over its own connection. Whether it forwards the node's echo
// or rewrites it to the caller's binding, the quote is refused.
func TestQuote_RefusesARelayedQuote(t *testing.T) {
	nodes := map[string]*quotingTPM{
		"relay's echo":   {nodeBinding: relayBinding, echo: relayBinding},
		"rewritten echo": {nodeBinding: relayBinding, echo: callerBinding},
	}
	for name, node := range nodes {
		t.Run(name, func(t *testing.T) {
			_, err := quote(node)
			var failed *ErrQuoteFailed
			if !errors.As(err, &failed) {
				t.Fatalf("err = %v, want ErrQuoteFailed", err)
			}
			var notBound *quotebind.ErrQuoteNotBound
			if !errors.As(err, &notBound) {
				t.Fatalf("err = %v, want it to wrap quotebind.ErrQuoteNotBound", err)
			}
		})
	}
}

func TestQuote_TransportRefusalIsTyped(t *testing.T) {
	_, err := quote(&quotingTPM{err: status.Error(codes.FailedPrecondition, "channel binding required")})
	var failed *ErrQuoteFailed
	if !errors.As(err, &failed) || status.Code(failed.Cause) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want ErrQuoteFailed carrying FailedPrecondition", err)
	}
}
